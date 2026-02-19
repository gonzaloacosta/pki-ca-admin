"""
Certificate Authority service for CA creation, management, and operations
"""

from typing import Optional, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
from datetime import datetime, timedelta
import uuid
import structlog

from app.models.database import CertificateAuthority, Organization
from app.models.schemas import CACreate, CAUpdate, CASubject
from app.services.stepca_service import StepCAService, StepCAInstance, StepCAException
from app.core.config import settings

logger = structlog.get_logger()

async def create_certificate_authority(
    db: AsyncSession,
    organization_id: uuid.UUID,
    ca_data: CACreate,
    created_by: str
) -> CertificateAuthority:
    """
    Create a new Certificate Authority
    
    This function creates the database record for the CA. The actual
    cryptographic operations (key generation, certificate creation) 
    would be handled by step-ca integration or KMS services.
    
    Args:
        db: Database session
        organization_id: Organization UUID
        ca_data: CA creation data
        created_by: User ID creating the CA
        
    Returns:
        Created CertificateAuthority instance
    """
    
    # Build subject DN from subject data
    subject_dn = _build_subject_dn(ca_data.subject)
    
    # Calculate validity period
    not_before = datetime.utcnow()
    not_after = not_before + timedelta(days=ca_data.validity_years * 365)
    
    # Create CA database record
    ca = CertificateAuthority(
        organization_id=organization_id,
        name=ca_data.name,
        description=ca_data.description,
        type=ca_data.type.value,
        parent_ca_id=ca_data.parent_ca_id,
        subject_dn=subject_dn,
        key_type=ca_data.key_type.value,
        key_storage=ca_data.key_storage.value,
        not_before=not_before,
        not_after=not_after,
        auto_renewal=ca_data.auto_renewal,
        renewal_threshold_days=ca_data.renewal_threshold_days,
        status="pending",  # Will be updated to "active" after crypto operations
        metadata=ca_data.metadata or {},
        created_by=created_by
    )
    
    # Set CA policy constraints
    if ca_data.policy:
        ca.max_path_length = ca_data.policy.max_path_length
        ca.allowed_key_types = [kt.value for kt in ca_data.policy.allowed_key_types]
        ca.max_validity_days = ca_data.policy.max_validity_days
        ca.crl_distribution_points = ca_data.policy.crl_distribution_points
        ca.ocsp_responder_url = ca_data.policy.ocsp_responder_url
    else:
        # Set default policy
        ca.max_validity_days = settings.DEFAULT_CERT_VALIDITY_DAYS
        ca.allowed_key_types = [settings.DEFAULT_CA_KEY_TYPE]
    
    # For KMS storage, set region
    if ca_data.key_storage == "kms":
        ca.kms_region = settings.AWS_REGION
        if ca_data.kms_key_arn:
            ca.kms_key_id = ca_data.kms_key_arn
    
    db.add(ca)
    await db.flush()  # Get the CA ID
    
    # Generate real CA certificate and key
    await _generate_ca_crypto_operations(ca)
    
    logger.info(
        "Certificate Authority created in database",
        ca_id=str(ca.id),
        ca_name=ca.name,
        ca_type=ca.type,
        key_type=ca.key_type,
        key_storage=ca.key_storage,
        organization_id=str(organization_id)
    )
    
    return ca

async def update_certificate_authority(
    db: AsyncSession,
    ca: CertificateAuthority,
    ca_update: CAUpdate
) -> CertificateAuthority:
    """
    Update Certificate Authority configuration
    
    Args:
        db: Database session
        ca: Existing CA to update
        ca_update: Update data
        
    Returns:
        Updated CertificateAuthority instance
    """
    
    # Update fields that are provided
    update_data = {}
    
    if ca_update.name is not None:
        update_data["name"] = ca_update.name
        
    if ca_update.description is not None:
        update_data["description"] = ca_update.description
        
    if ca_update.auto_renewal is not None:
        update_data["auto_renewal"] = ca_update.auto_renewal
        
    if ca_update.renewal_threshold_days is not None:
        update_data["renewal_threshold_days"] = ca_update.renewal_threshold_days
        
    if ca_update.policy is not None:
        if ca_update.policy.max_path_length is not None:
            update_data["max_path_length"] = ca_update.policy.max_path_length
        if ca_update.policy.allowed_key_types:
            update_data["allowed_key_types"] = [kt.value for kt in ca_update.policy.allowed_key_types]
        if ca_update.policy.max_validity_days is not None:
            update_data["max_validity_days"] = ca_update.policy.max_validity_days
        if ca_update.policy.crl_distribution_points is not None:
            update_data["crl_distribution_points"] = ca_update.policy.crl_distribution_points
        if ca_update.policy.ocsp_responder_url is not None:
            update_data["ocsp_responder_url"] = ca_update.policy.ocsp_responder_url
    
    if ca_update.metadata is not None:
        update_data["metadata"] = ca_update.metadata
    
    # Update the record
    if update_data:
        update_data["updated_at"] = datetime.utcnow()
        
        await db.execute(
            update(CertificateAuthority)
            .where(CertificateAuthority.id == ca.id)
            .values(**update_data)
        )
        
        # Refresh the instance
        await db.refresh(ca)
    
    logger.info(
        "Certificate Authority updated",
        ca_id=str(ca.id),
        ca_name=ca.name,
        updated_fields=list(update_data.keys())
    )
    
    return ca

async def revoke_certificate_authority(
    db: AsyncSession,
    ca: CertificateAuthority,
    reason: str,
    revoked_by: str
) -> CertificateAuthority:
    """
    Revoke a Certificate Authority
    
    Args:
        db: Database session
        ca: CA to revoke
        reason: Revocation reason
        revoked_by: User ID revoking the CA
        
    Returns:
        Updated CertificateAuthority instance
    """
    
    # Update CA status
    ca.status = "revoked"
    ca.updated_at = datetime.utcnow()
    
    # Add revocation metadata
    if not ca.metadata:
        ca.metadata = {}
    ca.metadata.update({
        "revoked_at": datetime.utcnow().isoformat(),
        "revoked_by": revoked_by,
        "revocation_reason": reason
    })
    
    # TODO: Integrate with step-ca to revoke the CA certificate
    # This would involve:
    # 1. Revoking the CA certificate
    # 2. Updating CRL
    # 3. Stopping step-ca instance
    # 4. Notifying dependent systems
    
    logger.warning(
        "Certificate Authority revoked",
        ca_id=str(ca.id),
        ca_name=ca.name,
        reason=reason,
        revoked_by=revoked_by
    )
    
    return ca

async def rotate_ca_key(
    db: AsyncSession,
    ca: CertificateAuthority,
    initiated_by: str,
    reason: str = "scheduled_rotation"
) -> str:
    """
    Rotate Certificate Authority key
    
    Args:
        db: Database session
        ca: CA to rotate key for
        initiated_by: User ID initiating rotation
        reason: Rotation reason
        
    Returns:
        New KMS key ID
    """
    
    old_key_id = ca.kms_key_id
    
    # TODO: Implement key rotation with KMS/HSM
    # This would involve:
    # 1. Creating new KMS key
    # 2. Generating new CA certificate with new key
    # 3. Cross-signing with old key if needed
    # 4. Updating step-ca configuration
    # 5. Publishing new certificate
    
    # Simulate new key creation
    new_key_id = f"arn:aws:kms:{settings.AWS_REGION}:123456789012:key/{uuid.uuid4()}"
    
    # Update CA with new key
    ca.kms_key_id = new_key_id
    ca.updated_at = datetime.utcnow()
    
    # Record key rotation
    from app.models.database import CAKeyRotation
    rotation = CAKeyRotation(
        ca_id=ca.id,
        old_key_id=old_key_id,
        new_key_id=new_key_id,
        rotation_reason=reason,
        initiated_by=initiated_by,
        completed_at=datetime.utcnow()
    )
    db.add(rotation)
    
    logger.warning(
        "Certificate Authority key rotated",
        ca_id=str(ca.id),
        ca_name=ca.name,
        old_key_id=old_key_id,
        new_key_id=new_key_id,
        reason=reason,
        initiated_by=initiated_by
    )
    
    return new_key_id

async def check_ca_renewal_needed(
    db: AsyncSession,
    ca: CertificateAuthority
) -> bool:
    """
    Check if CA certificate renewal is needed
    
    Args:
        db: Database session
        ca: CA to check
        
    Returns:
        True if renewal is needed
    """
    
    if not ca.auto_renewal or not ca.not_after:
        return False
    
    threshold_date = datetime.utcnow() + timedelta(days=ca.renewal_threshold_days)
    return ca.not_after <= threshold_date

def _build_subject_dn(subject: CASubject) -> str:
    """
    Build X.500 Distinguished Name string from subject components
    
    Args:
        subject: Subject components
        
    Returns:
        DN string
    """
    
    dn_parts = []
    
    if subject.common_name:
        dn_parts.append(f"CN={subject.common_name}")
    if subject.organizational_unit:
        dn_parts.append(f"OU={subject.organizational_unit}")
    if subject.organization:
        dn_parts.append(f"O={subject.organization}")
    if subject.locality:
        dn_parts.append(f"L={subject.locality}")
    if subject.state:
        dn_parts.append(f"ST={subject.state}")
    if subject.country:
        dn_parts.append(f"C={subject.country}")
    if subject.email:
        dn_parts.append(f"emailAddress={subject.email}")
    
    return ", ".join(dn_parts)

async def _generate_ca_crypto_operations(ca: CertificateAuthority):
    """
    Generate real cryptographic materials for CA creation
    
    This function:
    1. Generates private key
    2. Creates CA certificate
    3. Updates CA with certificate details
    
    NOTE: In production with KMS, the private key would be stored in KMS
    and only the key reference would be stored in the database.
    """
    from app.services.crypto_service import get_crypto_service
    
    crypto_service = get_crypto_service()
    
    try:
        # Generate private key
        private_key = crypto_service.generate_private_key(ca.key_type)
        
        # Generate CA certificate (self-signed for root, signed by parent for intermediate)
        certificate = crypto_service.generate_ca_certificate(ca, private_key)
        
        # Convert certificate to PEM
        ca.certificate_pem = crypto_service.certificate_to_pem(certificate)
        
        # Extract certificate details
        ca.serial_number = f"{certificate.serial_number:x}"
        ca.not_before = certificate.not_valid_before
        ca.not_after = certificate.not_valid_after
        
        # Create KMS key if using KMS storage
        if ca.key_storage == "kms" and not ca.kms_key_id:
            try:
                from app.services.kms_service import get_kms_service
                kms_service = get_kms_service()
                
                # Create KMS key for CA
                ca.kms_key_id = await kms_service.create_kms_key(
                    key_type=ca.key_type,
                    description=f"PKI CA Admin - {ca.name}",
                    tags={
                        "ca_id": str(ca.id),
                        "ca_name": ca.name,
                        "service": "pki-ca-admin"
                    }
                )
                
                logger.info(
                    "KMS key created for CA",
                    ca_id=str(ca.id),
                    kms_key_id=ca.kms_key_id
                )
                
            except Exception as e:
                logger.error(
                    "Failed to create KMS key for CA",
                    ca_id=str(ca.id),
                    error=str(e)
                )
                # For development, continue with file storage
                ca.key_storage = "file"
                logger.warning(
                    "Falling back to file storage for CA key",
                    ca_id=str(ca.id)
                )
        
        # Create and start step-ca instance
        try:
            stepca_service = StepCAService()
            stepca_instance = StepCAInstance(ca)
            
            logger.info(
                "Creating step-ca instance for CA",
                ca_id=str(ca.id),
                ca_name=ca.name
            )
            
            # Create step-ca configuration and instance
            await stepca_service.create_instance(stepca_instance, certificate, private_key)
            
            # Start the step-ca instance
            await stepca_service.start_instance(stepca_instance)
            
            # Mark CA as active only after step-ca is running
            ca.status = "active"
            
            logger.info(
                "step-ca instance created and started successfully",
                ca_id=str(ca.id),
                stepca_port=stepca_instance.port,
                stepca_address=stepca_instance.address
            )
            
        except StepCAException as e:
            ca.status = "failed"
            logger.error(
                "Failed to create step-ca instance",
                ca_id=str(ca.id),
                error=str(e)
            )
            raise
        
        logger.info(
            "CA cryptographic operations completed",
            ca_id=str(ca.id),
            serial_number=ca.serial_number,
            subject_dn=ca.subject_dn,
            key_type=ca.key_type,
            not_before=ca.not_before.isoformat() if ca.not_before else None,
            not_after=ca.not_after.isoformat() if ca.not_after else None
        )
        
    except Exception as e:
        ca.status = "failed"
        logger.error(
            "CA cryptographic operations failed",
            ca_id=str(ca.id),
            error=str(e),
            exc_info=True
        )
        raise