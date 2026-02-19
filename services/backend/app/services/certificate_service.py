"""
Certificate service for certificate issuance and management
"""

import uuid
from typing import Optional, List, Tuple
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, and_
from datetime import datetime, timedelta
import structlog

from app.models.database import Certificate, CertificateAuthority, Organization, CertificateLifecycleEvent
from app.models.schemas import CertificateRequest, CSRSigningRequest, CertificateRevocationRequest
from app.services.crypto_service import get_crypto_service
from app.services.kms_service import get_kms_service, KMSException
from app.services.audit_service import create_audit_event
from app.core.config import settings

logger = structlog.get_logger()


async def issue_certificate(
    db: AsyncSession,
    ca_id: uuid.UUID,
    cert_request: CertificateRequest,
    organization_id: uuid.UUID,
    requester: str
) -> Certificate:
    """
    Issue a new certificate
    
    Args:
        db: Database session
        ca_id: Certificate Authority ID
        cert_request: Certificate request details
        organization_id: Organization ID
        requester: User requesting the certificate
        
    Returns:
        Issued Certificate instance
    """
    crypto_service = get_crypto_service()
    
    # Get the CA
    result = await db.execute(
        select(CertificateAuthority).where(
            and_(
                CertificateAuthority.id == ca_id,
                CertificateAuthority.organization_id == organization_id,
                CertificateAuthority.status == "active"
            )
        )
    )
    ca = result.scalar_one_or_none()
    if not ca:
        raise ValueError("Certificate Authority not found or inactive")
    
    # Load CA private key from KMS or generate for development
    ca_private_key = await _load_ca_private_key(ca)
    
    # Parse CA certificate
    if not ca.certificate_pem:
        raise ValueError("CA certificate not found")
    
    from cryptography import x509
    ca_certificate = x509.load_pem_x509_certificate(ca.certificate_pem.encode('utf-8'))
    
    # Generate the certificate and private key
    certificate, private_key = crypto_service.generate_end_entity_certificate(
        cert_request, ca, ca_private_key, ca_certificate
    )
    
    # Convert to PEM
    certificate_pem = crypto_service.certificate_to_pem(certificate)
    
    # Create certificate database record
    cert_record = Certificate(
        ca_id=ca_id,
        organization_id=organization_id,
        serial_number=f"{certificate.serial_number:x}",
        fingerprint_sha256=crypto_service.get_certificate_fingerprint(certificate),
        common_name=cert_request.common_name,
        subject_dn=str(certificate.subject),
        subject_alternative_names=_extract_sans_from_certificate(certificate),
        certificate_pem=certificate_pem,
        not_before=certificate.not_valid_before,
        not_after=certificate.not_valid_after,
        certificate_type=cert_request.certificate_type.value,
        key_type=cert_request.key_type.value,
        key_usage=cert_request.key_usage,
        extended_key_usage=cert_request.extended_key_usage,
        provisioner_id=cert_request.provisioner_id,
        template_id=cert_request.template_id,
        requester=requester,
        request_source="api",
        status="active",
        metadata=cert_request.metadata or {}
    )
    
    db.add(cert_record)
    await db.flush()  # Get the certificate ID
    
    # Create lifecycle event
    lifecycle_event = CertificateLifecycleEvent(
        certificate_id=cert_record.id,
        event_type="issued",
        event_data={
            "ca_id": str(ca_id),
            "ca_name": ca.name,
            "certificate_type": cert_request.certificate_type.value,
            "key_type": cert_request.key_type.value,
            "validity_days": cert_request.validity_days,
            "requester": requester
        }
    )
    db.add(lifecycle_event)
    
    # Note: End-entity private keys are generated for the client
    # In production, these should be:
    # 1. Generated client-side (CSR workflow), OR
    # 2. Securely transmitted to client, OR  
    # 3. Stored in client's secure storage (KMS, HSM, etc.)
    # For this API, we generate and return the private key to the client
    logger.info(
        "Certificate issued successfully",
        certificate_id=str(cert_record.id),
        ca_id=str(ca_id),
        common_name=cert_request.common_name,
        serial_number=cert_record.serial_number,
        requester=requester,
        expires_at=cert_record.not_after.isoformat()
    )
    
    return cert_record


async def sign_certificate_request(
    db: AsyncSession,
    ca_id: uuid.UUID,
    csr_request: CSRSigningRequest,
    organization_id: uuid.UUID,
    requester: str
) -> Certificate:
    """
    Sign a Certificate Signing Request
    
    Args:
        db: Database session
        ca_id: Certificate Authority ID
        csr_request: CSR signing request
        organization_id: Organization ID
        requester: User requesting the signing
        
    Returns:
        Signed Certificate instance
    """
    crypto_service = get_crypto_service()
    
    # Get the CA
    result = await db.execute(
        select(CertificateAuthority).where(
            and_(
                CertificateAuthority.id == ca_id,
                CertificateAuthority.organization_id == organization_id,
                CertificateAuthority.status == "active"
            )
        )
    )
    ca = result.scalar_one_or_none()
    if not ca:
        raise ValueError("Certificate Authority not found or inactive")
    
    # Load CA private key from KMS or generate for development
    ca_private_key = await _load_ca_private_key(ca)
    
    # Parse CA certificate
    from cryptography import x509
    ca_certificate = x509.load_pem_x509_certificate(ca.certificate_pem.encode('utf-8'))
    
    # Parse and validate CSR
    try:
        csr = x509.load_pem_x509_csr(csr_request.csr_pem.encode('utf-8'))
        common_name = _extract_common_name_from_name(csr.subject)
    except Exception as e:
        raise ValueError(f"Invalid CSR: {e}")
    
    # Sign the CSR
    certificate = crypto_service.sign_certificate_signing_request(
        csr_request, ca, ca_private_key, ca_certificate
    )
    
    # Convert to PEM
    certificate_pem = crypto_service.certificate_to_pem(certificate)
    
    # Create certificate database record
    cert_record = Certificate(
        ca_id=ca_id,
        organization_id=organization_id,
        serial_number=f"{certificate.serial_number:x}",
        fingerprint_sha256=crypto_service.get_certificate_fingerprint(certificate),
        common_name=common_name or "Unknown",
        subject_dn=str(certificate.subject),
        subject_alternative_names=_extract_sans_from_certificate(certificate),
        certificate_pem=certificate_pem,
        not_before=certificate.not_valid_before,
        not_after=certificate.not_valid_after,
        certificate_type=csr_request.certificate_type.value,
        requester=requester,
        request_source="csr",
        status="active",
        metadata=csr_request.metadata or {}
    )
    
    db.add(cert_record)
    await db.flush()
    
    # Create lifecycle event
    lifecycle_event = CertificateLifecycleEvent(
        certificate_id=cert_record.id,
        event_type="issued",
        event_data={
            "ca_id": str(ca_id),
            "ca_name": ca.name,
            "certificate_type": csr_request.certificate_type.value,
            "validity_days": csr_request.validity_days,
            "requester": requester,
            "signed_from_csr": True
        }
    )
    db.add(lifecycle_event)
    
    logger.info(
        "CSR signed successfully",
        certificate_id=str(cert_record.id),
        ca_id=str(ca_id),
        common_name=common_name,
        serial_number=cert_record.serial_number,
        requester=requester
    )
    
    return cert_record


async def revoke_certificate(
    db: AsyncSession,
    certificate_id: uuid.UUID,
    revocation_request: CertificateRevocationRequest,
    organization_id: uuid.UUID,
    revoked_by: str
) -> Certificate:
    """
    Revoke a certificate
    
    Args:
        db: Database session
        certificate_id: Certificate ID to revoke
        revocation_request: Revocation details
        organization_id: Organization ID
        revoked_by: User revoking the certificate
        
    Returns:
        Revoked Certificate instance
    """
    # Get the certificate
    result = await db.execute(
        select(Certificate).where(
            and_(
                Certificate.id == certificate_id,
                Certificate.organization_id == organization_id,
                Certificate.status == "active"
            )
        )
    )
    cert = result.scalar_one_or_none()
    if not cert:
        raise ValueError("Certificate not found or already revoked")
    
    # Update certificate status
    await db.execute(
        update(Certificate)
        .where(Certificate.id == certificate_id)
        .values(
            status="revoked",
            revoked_at=datetime.utcnow(),
            revocation_reason=revocation_request.reason,
            revoked_by=revoked_by,
            updated_at=datetime.utcnow()
        )
    )
    
    # Refresh the certificate object
    await db.refresh(cert)
    
    # Create lifecycle event
    lifecycle_event = CertificateLifecycleEvent(
        certificate_id=certificate_id,
        event_type="revoked",
        event_data={
            "revocation_reason": revocation_request.reason,
            "revoked_by": revoked_by,
            "revoked_at": datetime.utcnow().isoformat()
        }
    )
    db.add(lifecycle_event)
    
    # Update CRL and notify OCSP responder
    try:
        await _update_crl_after_revocation(db, certificate.ca_id, certificate.id, revocation_reason)
        await _notify_ocsp_responder(certificate)
        
        logger.info(
            "CRL and OCSP updated after certificate revocation",
            certificate_id=str(certificate.id),
            ca_id=str(certificate.ca_id)
        )
        
    except Exception as e:
        logger.error(
            "Failed to update CRL/OCSP after revocation",
            certificate_id=str(certificate.id),
            ca_id=str(certificate.ca_id),
            error=str(e)
        )
        # Don't fail the revocation if CRL/OCSP update fails
    
    logger.warning(
        "Certificate revoked",
        certificate_id=str(certificate_id),
        serial_number=cert.serial_number,
        common_name=cert.common_name,
        reason=revocation_request.reason,
        revoked_by=revoked_by
    )
    
    return cert


async def renew_certificate(
    db: AsyncSession,
    certificate_id: uuid.UUID,
    organization_id: uuid.UUID,
    requester: str,
    validity_days: Optional[int] = None
) -> Certificate:
    """
    Renew a certificate
    
    Args:
        db: Database session
        certificate_id: Certificate ID to renew
        organization_id: Organization ID
        requester: User requesting renewal
        validity_days: New validity period (optional)
        
    Returns:
        New Certificate instance
    """
    # Get the original certificate
    result = await db.execute(
        select(Certificate).where(
            and_(
                Certificate.id == certificate_id,
                Certificate.organization_id == organization_id
            )
        )
    )
    old_cert = result.scalar_one_or_none()
    if not old_cert:
        raise ValueError("Certificate not found")
    
    # Create renewal request based on original certificate
    from app.models.schemas import CertificateRequest, CertificateType, KeyType, SubjectAlternativeNames
    
    # Parse SANs from the old certificate
    sans = None
    if old_cert.subject_alternative_names:
        sans_data = old_cert.subject_alternative_names
        sans = SubjectAlternativeNames(
            dns=sans_data.get("dns", []),
            ip=sans_data.get("ip", []),
            email=sans_data.get("email", []),
            uri=sans_data.get("uri", [])
        )
    
    renewal_request = CertificateRequest(
        common_name=old_cert.common_name,
        subject_alternative_names=sans,
        certificate_type=CertificateType(old_cert.certificate_type),
        key_type=KeyType(old_cert.key_type) if old_cert.key_type else KeyType.ECDSA_P256,
        validity_days=validity_days or settings.DEFAULT_CERT_VALIDITY_DAYS,
        key_usage=old_cert.key_usage or ["digitalSignature", "keyEncipherment"],
        extended_key_usage=old_cert.extended_key_usage or ["serverAuth"],
        template_id=old_cert.template_id,
        metadata=old_cert.metadata
    )
    
    # Issue new certificate
    new_cert = await issue_certificate(
        db, old_cert.ca_id, renewal_request, organization_id, requester
    )
    
    # Create lifecycle event for renewal
    lifecycle_event = CertificateLifecycleEvent(
        certificate_id=new_cert.id,
        event_type="renewed",
        event_data={
            "previous_certificate_id": str(certificate_id),
            "renewed_by": requester,
            "previous_serial": old_cert.serial_number,
            "new_serial": new_cert.serial_number
        }
    )
    db.add(lifecycle_event)
    
    logger.info(
        "Certificate renewed",
        old_certificate_id=str(certificate_id),
        new_certificate_id=str(new_cert.id),
        common_name=new_cert.common_name,
        requester=requester
    )
    
    return new_cert


async def get_expiring_certificates(
    db: AsyncSession,
    organization_id: uuid.UUID,
    days_ahead: int = 30
) -> List[Certificate]:
    """
    Get certificates expiring within the specified number of days
    
    Args:
        db: Database session
        organization_id: Organization ID
        days_ahead: Number of days to look ahead
        
    Returns:
        List of expiring certificates
    """
    expiry_threshold = datetime.utcnow() + timedelta(days=days_ahead)
    
    result = await db.execute(
        select(Certificate).where(
            and_(
                Certificate.organization_id == organization_id,
                Certificate.status == "active",
                Certificate.not_after <= expiry_threshold
            )
        ).order_by(Certificate.not_after)
    )
    
    return result.scalars().all()


def _extract_sans_from_certificate(certificate) -> Optional[dict]:
    """
    Extract Subject Alternative Names from a certificate
    
    Args:
        certificate: X.509 certificate
        
    Returns:
        Dictionary of SANs or None
    """
    try:
        from cryptography import x509
        
        # Get SAN extension
        san_ext = certificate.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        sans = san_ext.value
        
        result = {
            "dns": [],
            "ip": [],
            "email": [],
            "uri": []
        }
        
        for name in sans:
            if isinstance(name, x509.DNSName):
                result["dns"].append(name.value)
            elif isinstance(name, x509.IPAddress):
                result["ip"].append(str(name.value))
            elif isinstance(name, x509.RFC822Name):
                result["email"].append(name.value)
            elif isinstance(name, x509.UniformResourceIdentifier):
                result["uri"].append(name.value)
        
        return result if any(result.values()) else None
        
    except x509.ExtensionNotFound:
        return None
    except Exception:
        return None


def _extract_common_name_from_name(name) -> Optional[str]:
    """
    Extract common name from X.509 Name object
    
    Args:
        name: X.509 Name object
        
    Returns:
        Common name or None
    """
    try:
        from cryptography.x509.oid import NameOID
        
        cn_attributes = name.get_attributes_for_oid(NameOID.COMMON_NAME)
        if cn_attributes:
            return cn_attributes[0].value
        return None
        
    except Exception:
        return None


async def _load_ca_private_key(ca: CertificateAuthority):
    """
    Load CA private key from KMS or generate for development
    
    Args:
        ca: Certificate Authority database object
        
    Returns:
        Private key instance
        
    Raises:
        KMSException: If KMS key access fails
    """
    if ca.key_storage == "kms" and ca.kms_key_id:
        try:
            kms_service = get_kms_service()
            
            logger.info(
                "Loading CA private key from KMS",
                ca_id=str(ca.id),
                kms_key_id=ca.kms_key_id,
                key_type=ca.key_type
            )
            
            # Load private key from KMS
            private_key = await kms_service.get_private_key(ca.kms_key_id, ca.key_type)
            
            logger.info(
                "CA private key loaded successfully from KMS",
                ca_id=str(ca.id),
                kms_key_id=ca.kms_key_id
            )
            
            return private_key
            
        except KMSException as e:
            logger.error(
                "Failed to load CA private key from KMS",
                ca_id=str(ca.id),
                kms_key_id=ca.kms_key_id,
                error=str(e)
            )
            raise
        except Exception as e:
            logger.error(
                "Unexpected error loading CA private key from KMS",
                ca_id=str(ca.id),
                kms_key_id=ca.kms_key_id,
                error=str(e)
            )
            raise KMSException(f"Failed to load CA private key: {e}")
    
    else:
        # For development or file-based storage, generate temporary key
        logger.warning(
            "Generating temporary CA private key (development mode)",
            ca_id=str(ca.id),
            key_storage=ca.key_storage,
            key_type=ca.key_type
        )
        
        crypto_service = get_crypto_service()
        return crypto_service.generate_private_key(ca.key_type)


async def _update_crl_after_revocation(
    db: AsyncSession, 
    ca_id: uuid.UUID, 
    certificate_id: uuid.UUID, 
    revocation_reason: str
):
    """
    Update Certificate Revocation List after certificate revocation
    
    Args:
        db: Database session
        ca_id: CA ID
        certificate_id: Revoked certificate ID
        revocation_reason: Revocation reason
    """
    try:
        # Get CA information
        ca_result = await db.execute(
            select(CertificateAuthority).where(CertificateAuthority.id == ca_id)
        )
        ca = ca_result.scalar_one_or_none()
        
        if not ca:
            logger.error("CA not found for CRL update", ca_id=str(ca_id))
            return
        
        # TODO: Implement actual CRL generation and distribution
        # This would involve:
        # 1. Generating new CRL with revoked certificate
        # 2. Signing CRL with CA private key
        # 3. Publishing CRL to distribution points
        # 4. Notifying dependent systems
        
        logger.info(
            "CRL update scheduled for CA",
            ca_id=str(ca_id),
            certificate_id=str(certificate_id),
            revocation_reason=revocation_reason
        )
        
    except Exception as e:
        logger.error(
            "Failed to update CRL",
            ca_id=str(ca_id),
            certificate_id=str(certificate_id),
            error=str(e)
        )
        raise


async def _notify_ocsp_responder(certificate: Certificate):
    """
    Notify OCSP responder about certificate revocation
    
    Args:
        certificate: Revoked certificate object
    """
    try:
        # TODO: Implement OCSP responder notification
        # This would involve:
        # 1. Connecting to OCSP responder service
        # 2. Updating certificate status
        # 3. Clearing any cached responses
        
        logger.info(
            "OCSP responder notification scheduled",
            certificate_id=str(certificate.id),
            serial_number=certificate.serial_number,
            ca_id=str(certificate.ca_id)
        )
        
    except Exception as e:
        logger.error(
            "Failed to notify OCSP responder",
            certificate_id=str(certificate.id),
            error=str(e)
        )
        raise