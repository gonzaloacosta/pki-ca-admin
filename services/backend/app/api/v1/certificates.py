"""
API endpoints for Certificate management.
"""

from typing import List, Optional
from datetime import datetime
import uuid
import hashlib

from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, or_
from sqlalchemy.orm import selectinload
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from app.core.database import get_db
from app.core.security import CurrentUser, require_admin, require_operator, require_viewer
from app.models import CaNode, Certificate, AuditEvent
from app.schemas.certificate import (
    CertificateIssueRequest,
    CertificateSignRequest,
    CertificateResponse,
    CertificateListResponse,
    CertificateRevokeRequest,
    CertificateSearchRequest,
    CertificateStatsResponse
)
from app.services.ca_engine import CaEngine, CaEngineError

router = APIRouter(prefix="/certificates", tags=["Certificates"])


@router.get("", response_model=CertificateListResponse)
async def list_certificates(
    db: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(require_viewer),
    ca_id: Optional[uuid.UUID] = Query(None, description="Filter by CA ID"),
    certificate_type: Optional[str] = Query(None, description="Filter by certificate type"),
    status: Optional[str] = Query(None, description="Filter by status"),
    common_name: Optional[str] = Query(None, description="Filter by common name"),
    page: int = Query(1, ge=1, description="Page number"),
    size: int = Query(20, ge=1, le=100, description="Page size")
):
    """
    List certificates with pagination and filtering.
    """
    try:
        # Build query
        query = select(Certificate).options(selectinload(Certificate.ca))
        
        # Apply filters
        if ca_id:
            query = query.where(Certificate.ca_id == ca_id)
        if certificate_type:
            query = query.where(Certificate.certificate_type == certificate_type)
        if status:
            query = query.where(Certificate.status == status)
        if common_name:
            query = query.where(Certificate.common_name.ilike(f"%{common_name}%"))
        
        # Count total records
        count_query = select(func.count()).select_from(Certificate)
        if ca_id:
            count_query = count_query.where(Certificate.ca_id == ca_id)
        if certificate_type:
            count_query = count_query.where(Certificate.certificate_type == certificate_type)
        if status:
            count_query = count_query.where(Certificate.status == status)
        if common_name:
            count_query = count_query.where(Certificate.common_name.ilike(f"%{common_name}%"))
        
        total_result = await db.execute(count_query)
        total = total_result.scalar()
        
        # Apply pagination
        offset = (page - 1) * size
        query = query.offset(offset).limit(size).order_by(Certificate.created_at.desc())
        
        result = await db.execute(query)
        certificates = result.scalars().all()
        
        # Convert to response models
        cert_responses = []
        for cert in certificates:
            cert_dict = {
                "id": cert.id,
                "ca_id": cert.ca_id,
                "common_name": cert.common_name,
                "certificate_type": cert.certificate_type,
                "serial_number": cert.serial_number,
                "fingerprint_sha256": cert.fingerprint_sha256,
                "subject_dn": cert.subject_dn,
                "subject_alternative_names": cert.subject_alternative_names,
                "certificate_pem": cert.certificate_pem,
                "not_before": cert.not_before,
                "not_after": cert.not_after,
                "key_type": cert.key_type,
                "key_usage": cert.key_usage,
                "extended_key_usage": cert.extended_key_usage,
                "provisioner_id": cert.provisioner_id,
                "template_id": cert.template_id,
                "requester": cert.requester,
                "request_source": cert.request_source,
                "status": cert.status,
                "revoked_at": cert.revoked_at,
                "revocation_reason": cert.revocation_reason,
                "revoked_by": cert.revoked_by,
                "certificate_transparency_scts": cert.certificate_transparency_scts,
                "metadata": cert.metadata_,
                "created_at": cert.created_at,
                "updated_at": cert.updated_at,
                "is_expired": cert.is_expired,
                "is_revoked": cert.is_revoked,
                "is_valid": cert.is_valid,
                "validity_period_days": cert.validity_period_days,
                "days_until_expiry": cert.days_until_expiry,
            }
            cert_responses.append(CertificateResponse(**cert_dict))
        
        pages = (total + size - 1) // size
        
        return CertificateListResponse(
            items=cert_responses,
            total=total,
            page=page,
            size=size,
            pages=pages
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list certificates: {str(e)}"
        )


@router.get("/stats", response_model=CertificateStatsResponse)
async def get_certificate_stats(
    db: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(require_viewer)
):
    """
    Get certificate statistics.
    """
    try:
        now = datetime.utcnow()
        
        # Basic counts
        total_certs_query = select(func.count()).select_from(Certificate)
        active_certs_query = select(func.count()).select_from(Certificate).where(Certificate.status == "active")
        expired_certs_query = select(func.count()).select_from(Certificate).where(Certificate.not_after < now)
        revoked_certs_query = select(func.count()).select_from(Certificate).where(Certificate.status == "revoked")
        
        total_certificates = (await db.execute(total_certs_query)).scalar()
        active_certificates = (await db.execute(active_certs_query)).scalar()
        expired_certificates = (await db.execute(expired_certs_query)).scalar()
        revoked_certificates = (await db.execute(revoked_certs_query)).scalar()
        
        # Expiring certificates
        from datetime import timedelta
        expires_30_query = select(func.count()).select_from(Certificate).where(
            and_(
                Certificate.not_after > now,
                Certificate.not_after <= now + timedelta(days=30)
            )
        )
        expires_90_query = select(func.count()).select_from(Certificate).where(
            and_(
                Certificate.not_after > now,
                Certificate.not_after <= now + timedelta(days=90)
            )
        )
        
        expiring_within_30_days = (await db.execute(expires_30_query)).scalar()
        expiring_within_90_days = (await db.execute(expires_90_query)).scalar()
        
        return CertificateStatsResponse(
            total_certificates=total_certificates,
            active_certificates=active_certificates,
            expired_certificates=expired_certificates,
            revoked_certificates=revoked_certificates,
            expiring_within_30_days=expiring_within_30_days,
            expiring_within_90_days=expiring_within_90_days,
            by_type={},  # TODO: Implement grouping
            by_ca={},    # TODO: Implement grouping
            by_month={}  # TODO: Implement grouping
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get certificate statistics: {str(e)}"
        )


@router.get("/{certificate_id}", response_model=CertificateResponse)
async def get_certificate(
    certificate_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(require_viewer)
):
    """
    Get a specific certificate by ID.
    """
    try:
        query = select(Certificate).options(selectinload(Certificate.ca)).where(Certificate.id == certificate_id)
        result = await db.execute(query)
        cert = result.scalar_one_or_none()
        
        if not cert:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Certificate not found: {certificate_id}"
            )
        
        cert_dict = {
            "id": cert.id,
            "ca_id": cert.ca_id,
            "common_name": cert.common_name,
            "certificate_type": cert.certificate_type,
            "serial_number": cert.serial_number,
            "fingerprint_sha256": cert.fingerprint_sha256,
            "subject_dn": cert.subject_dn,
            "subject_alternative_names": cert.subject_alternative_names,
            "certificate_pem": cert.certificate_pem,
            "not_before": cert.not_before,
            "not_after": cert.not_after,
            "key_type": cert.key_type,
            "key_usage": cert.key_usage,
            "extended_key_usage": cert.extended_key_usage,
            "provisioner_id": cert.provisioner_id,
            "template_id": cert.template_id,
            "requester": cert.requester,
            "request_source": cert.request_source,
            "status": cert.status,
            "revoked_at": cert.revoked_at,
            "revocation_reason": cert.revocation_reason,
            "revoked_by": cert.revoked_by,
            "certificate_transparency_scts": cert.certificate_transparency_scts,
            "metadata": cert.metadata_,
            "created_at": cert.created_at,
            "updated_at": cert.updated_at,
            "is_expired": cert.is_expired,
            "is_revoked": cert.is_revoked,
            "is_valid": cert.is_valid,
            "validity_period_days": cert.validity_period_days,
            "days_until_expiry": cert.days_until_expiry,
        }
        
        return CertificateResponse(**cert_dict)
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get certificate: {str(e)}"
        )


@router.post("/issue", response_model=CertificateResponse, status_code=status.HTTP_201_CREATED)
async def issue_certificate(
    ca_id: uuid.UUID,
    cert_request: CertificateIssueRequest,
    db: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(require_operator)
):
    """
    Issue a new certificate using a CA.
    """
    try:
        # Get the CA
        ca_query = select(CaNode).where(CaNode.id == ca_id)
        ca_result = await db.execute(ca_query)
        ca = ca_result.scalar_one_or_none()
        
        if not ca:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"CA not found: {ca_id}"
            )
        
        if ca.status != "active":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="CA is not active"
            )
        
        # Initialize CA engine
        ca_engine = CaEngine()
        
        # Generate key pair for the certificate
        key_id, private_key = await ca_engine.generate_key_pair(cert_request.key_type)
        
        # Build subject information
        from app.schemas.ca import SubjectInfo
        subject = SubjectInfo(
            common_name=cert_request.common_name,
            organization=cert_request.organization,
            organizational_unit=cert_request.organizational_unit,
            country=cert_request.country,
            state=cert_request.state,
            locality=cert_request.locality,
            email=cert_request.email
        )
        
        # Sign the certificate
        certificate_pem = await ca_engine.sign_certificate(
            ca_key_id=ca.kms_key_id,
            ca_certificate_pem=ca.certificate_pem,
            subject=subject,
            public_key=private_key.public_key(),
            validity_days=cert_request.validity_days,
            certificate_type=cert_request.certificate_type,
            subject_alternative_names=cert_request.subject_alternative_names,
            key_usage=cert_request.key_usage,
            extended_key_usage=cert_request.extended_key_usage,
            is_ca=False
        )
        
        # Parse certificate to extract details
        cert = x509.load_pem_x509_certificate(certificate_pem.encode())
        
        # Calculate fingerprint
        fingerprint = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
        
        # Create certificate record
        certificate = Certificate(
            ca_id=ca_id,
            serial_number=str(cert.serial_number),
            fingerprint_sha256=fingerprint,
            common_name=cert_request.common_name,
            subject_dn=cert.subject.rfc4514_string(),
            subject_alternative_names=cert_request.subject_alternative_names.dict() if cert_request.subject_alternative_names else None,
            certificate_pem=certificate_pem,
            not_before=cert.not_valid_before,
            not_after=cert.not_valid_after,
            certificate_type=cert_request.certificate_type,
            key_type=cert_request.key_type,
            key_usage=cert_request.key_usage,
            extended_key_usage=cert_request.extended_key_usage,
            requester=current_user.user_id,
            request_source="api",
            metadata_=cert_request.metadata,
            status="active"
        )
        
        db.add(certificate)
        await db.commit()
        await db.refresh(certificate)
        
        # Create audit event
        audit_event = AuditEvent.create_certificate_event(
            event_type="cert.issued",
            certificate_id=certificate.id,
            actor_id=current_user.user_id,
            event_data={
                "ca_id": str(ca_id),
                "ca_name": ca.name,
                "common_name": cert_request.common_name,
                "certificate_type": cert_request.certificate_type,
                "validity_days": cert_request.validity_days
            }
        )
        db.add(audit_event)
        await db.commit()
        
        # Return response
        cert_dict = {
            "id": certificate.id,
            "ca_id": certificate.ca_id,
            "common_name": certificate.common_name,
            "certificate_type": certificate.certificate_type,
            "serial_number": certificate.serial_number,
            "fingerprint_sha256": certificate.fingerprint_sha256,
            "subject_dn": certificate.subject_dn,
            "subject_alternative_names": certificate.subject_alternative_names,
            "certificate_pem": certificate.certificate_pem,
            "not_before": certificate.not_before,
            "not_after": certificate.not_after,
            "key_type": certificate.key_type,
            "key_usage": certificate.key_usage,
            "extended_key_usage": certificate.extended_key_usage,
            "provisioner_id": certificate.provisioner_id,
            "template_id": certificate.template_id,
            "requester": certificate.requester,
            "request_source": certificate.request_source,
            "status": certificate.status,
            "revoked_at": certificate.revoked_at,
            "revocation_reason": certificate.revocation_reason,
            "revoked_by": certificate.revoked_by,
            "certificate_transparency_scts": certificate.certificate_transparency_scts,
            "metadata": certificate.metadata_,
            "created_at": certificate.created_at,
            "updated_at": certificate.updated_at,
            "is_expired": certificate.is_expired,
            "is_revoked": certificate.is_revoked,
            "is_valid": certificate.is_valid,
            "validity_period_days": certificate.validity_period_days,
            "days_until_expiry": certificate.days_until_expiry,
        }
        
        return CertificateResponse(**cert_dict)
        
    except HTTPException:
        raise
    except CaEngineError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Certificate issuance failed: {str(e)}"
        )
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to issue certificate: {str(e)}"
        )


@router.post("/sign-csr", response_model=CertificateResponse, status_code=status.HTTP_201_CREATED)
async def sign_csr(
    ca_id: uuid.UUID,
    csr_request: CertificateSignRequest,
    db: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(require_operator)
):
    """
    Sign a Certificate Signing Request (CSR) with a CA.
    """
    try:
        # Get the CA
        ca_query = select(CaNode).where(CaNode.id == ca_id)
        ca_result = await db.execute(ca_query)
        ca = ca_result.scalar_one_or_none()
        
        if not ca:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"CA not found: {ca_id}"
            )
        
        if ca.status != "active":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="CA is not active"
            )
        
        # Initialize CA engine
        ca_engine = CaEngine()
        
        # Sign the CSR
        certificate_pem = await ca_engine.sign_csr(
            ca_key_id=ca.kms_key_id,
            ca_certificate_pem=ca.certificate_pem,
            csr_pem=csr_request.csr_pem,
            validity_days=csr_request.validity_days,
            certificate_type=csr_request.certificate_type,
            subject_alternative_names=csr_request.subject_alternative_names,
            key_usage=csr_request.key_usage,
            extended_key_usage=csr_request.extended_key_usage
        )
        
        # Parse certificate to extract details
        cert = x509.load_pem_x509_certificate(certificate_pem.encode())
        
        # Calculate fingerprint
        fingerprint = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
        
        # Extract common name from subject
        common_name = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        
        # Create certificate record
        certificate = Certificate(
            ca_id=ca_id,
            serial_number=str(cert.serial_number),
            fingerprint_sha256=fingerprint,
            common_name=common_name,
            subject_dn=cert.subject.rfc4514_string(),
            subject_alternative_names=csr_request.subject_alternative_names.dict() if csr_request.subject_alternative_names else None,
            certificate_pem=certificate_pem,
            not_before=cert.not_valid_before,
            not_after=cert.not_valid_after,
            certificate_type=csr_request.certificate_type,
            key_usage=csr_request.key_usage,
            extended_key_usage=csr_request.extended_key_usage,
            requester=current_user.user_id,
            request_source="csr",
            metadata_=csr_request.metadata,
            status="active"
        )
        
        db.add(certificate)
        await db.commit()
        await db.refresh(certificate)
        
        # Create audit event
        audit_event = AuditEvent.create_certificate_event(
            event_type="cert.signed_csr",
            certificate_id=certificate.id,
            actor_id=current_user.user_id,
            event_data={
                "ca_id": str(ca_id),
                "ca_name": ca.name,
                "common_name": common_name,
                "certificate_type": csr_request.certificate_type,
                "validity_days": csr_request.validity_days
            }
        )
        db.add(audit_event)
        await db.commit()
        
        # Return response
        cert_dict = {
            "id": certificate.id,
            "ca_id": certificate.ca_id,
            "common_name": certificate.common_name,
            "certificate_type": certificate.certificate_type,
            "serial_number": certificate.serial_number,
            "fingerprint_sha256": certificate.fingerprint_sha256,
            "subject_dn": certificate.subject_dn,
            "subject_alternative_names": certificate.subject_alternative_names,
            "certificate_pem": certificate.certificate_pem,
            "not_before": certificate.not_before,
            "not_after": certificate.not_after,
            "key_type": certificate.key_type,
            "key_usage": certificate.key_usage,
            "extended_key_usage": certificate.extended_key_usage,
            "provisioner_id": certificate.provisioner_id,
            "template_id": certificate.template_id,
            "requester": certificate.requester,
            "request_source": certificate.request_source,
            "status": certificate.status,
            "revoked_at": certificate.revoked_at,
            "revocation_reason": certificate.revocation_reason,
            "revoked_by": certificate.revoked_by,
            "certificate_transparency_scts": certificate.certificate_transparency_scts,
            "metadata": certificate.metadata_,
            "created_at": certificate.created_at,
            "updated_at": certificate.updated_at,
            "is_expired": certificate.is_expired,
            "is_revoked": certificate.is_revoked,
            "is_valid": certificate.is_valid,
            "validity_period_days": certificate.validity_period_days,
            "days_until_expiry": certificate.days_until_expiry,
        }
        
        return CertificateResponse(**cert_dict)
        
    except HTTPException:
        raise
    except CaEngineError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"CSR signing failed: {str(e)}"
        )
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to sign CSR: {str(e)}"
        )


@router.post("/{certificate_id}/revoke", status_code=status.HTTP_200_OK)
async def revoke_certificate(
    certificate_id: uuid.UUID,
    revoke_request: CertificateRevokeRequest,
    db: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(require_operator)
):
    """
    Revoke a certificate.
    """
    try:
        # Get the certificate
        query = select(Certificate).where(Certificate.id == certificate_id)
        result = await db.execute(query)
        cert = result.scalar_one_or_none()
        
        if not cert:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Certificate not found: {certificate_id}"
            )
        
        if cert.status == "revoked":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Certificate is already revoked"
            )
        
        # Revoke the certificate
        cert.status = "revoked"
        cert.revoked_at = revoke_request.revocation_date or datetime.utcnow()
        cert.revocation_reason = revoke_request.reason
        cert.revoked_by = current_user.user_id
        cert.updated_at = datetime.utcnow()
        
        await db.commit()
        
        # Create audit event
        audit_event = AuditEvent.create_certificate_event(
            event_type="cert.revoked",
            certificate_id=certificate_id,
            actor_id=current_user.user_id,
            event_data={
                "common_name": cert.common_name,
                "serial_number": cert.serial_number,
                "revocation_reason": revoke_request.reason
            }
        )
        db.add(audit_event)
        await db.commit()
        
        return {"message": "Certificate revoked successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to revoke certificate: {str(e)}"
        )