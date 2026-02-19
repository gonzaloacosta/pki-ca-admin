"""
Certificate management router
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, desc, or_
from datetime import datetime, timedelta
import structlog
import uuid

from app.core.database import get_db
from app.core.security import get_current_user, get_current_organization
from app.models.database import User, Organization, Certificate, CertificateAuthority
from app.models.schemas import (
    CertificateResponse, CertificateDetailResponse, CertificateRequest, 
    CSRSigningRequest, CertificateRevocationRequest, PaginatedResponse,
    CertificateType, CertificateStatus
)
from app.services.audit_service import create_audit_event

logger = structlog.get_logger()

router = APIRouter()

@router.get("", response_model=PaginatedResponse)
async def list_certificates(
    ca_id: Optional[uuid.UUID] = Query(None, description="Filter by CA ID"),
    certificate_type: Optional[CertificateType] = Query(None, description="Filter by certificate type"),
    status: Optional[CertificateStatus] = Query(None, description="Filter by certificate status"),
    common_name: Optional[str] = Query(None, description="Filter by common name"),
    expiring_days: Optional[int] = Query(None, ge=0, le=365, description="Certificates expiring within N days"),
    limit: int = Query(20, ge=1, le=100, description="Number of results per page"),
    offset: int = Query(0, ge=0, description="Number of results to skip"),
    current_user: User = Depends(get_current_user),
    organization: Organization = Depends(get_current_organization),
    db: AsyncSession = Depends(get_db)
):
    """
    List certificates for the organization
    """
    
    query = select(Certificate).where(
        Certificate.organization_id == organization.id
    )
    
    # Apply filters
    if ca_id:
        query = query.where(Certificate.ca_id == ca_id)
    
    if certificate_type:
        query = query.where(Certificate.certificate_type == certificate_type.value)
    
    if status:
        query = query.where(Certificate.status == status.value)
    
    if common_name:
        query = query.where(Certificate.common_name.ilike(f"%{common_name}%"))
    
    if expiring_days is not None:
        expiry_threshold = datetime.utcnow() + timedelta(days=expiring_days)
        query = query.where(
            and_(
                Certificate.not_after <= expiry_threshold,
                Certificate.status == "active"
            )
        )
    
    # Get total count
    count_query = select(func.count(Certificate.id)).where(
        Certificate.organization_id == organization.id
    )
    if ca_id:
        count_query = count_query.where(Certificate.ca_id == ca_id)
    if certificate_type:
        count_query = count_query.where(Certificate.certificate_type == certificate_type.value)
    if status:
        count_query = count_query.where(Certificate.status == status.value)
    if common_name:
        count_query = count_query.where(Certificate.common_name.ilike(f"%{common_name}%"))
    if expiring_days is not None:
        expiry_threshold = datetime.utcnow() + timedelta(days=expiring_days)
        count_query = count_query.where(
            and_(
                Certificate.not_after <= expiry_threshold,
                Certificate.status == "active"
            )
        )
    
    total_result = await db.execute(count_query)
    total = total_result.scalar()
    
    # Apply pagination and ordering
    query = query.order_by(
        desc(Certificate.created_at)
    ).limit(limit).offset(offset)
    
    result = await db.execute(query)
    certificates = result.scalars().all()
    
    # Convert to response schemas
    cert_responses = [
        CertificateResponse(
            id=cert.id,
            ca_id=cert.ca_id,
            organization_id=cert.organization_id,
            serial_number=cert.serial_number,
            fingerprint_sha256=cert.fingerprint_sha256,
            common_name=cert.common_name,
            subject_dn=cert.subject_dn,
            subject_alternative_names=cert.subject_alternative_names,
            certificate_type=cert.certificate_type,
            key_type=cert.key_type,
            not_before=cert.not_before,
            not_after=cert.not_after,
            status=cert.status,
            provisioner_id=cert.provisioner_id,
            template_id=cert.template_id,
            requester=cert.requester,
            request_source=cert.request_source,
            metadata=cert.metadata,
            created_at=cert.created_at
        )
        for cert in certificates
    ]
    
    return PaginatedResponse(
        data=cert_responses,
        total=total,
        limit=limit,
        offset=offset,
        has_more=offset + limit < total
    )

@router.post("/{ca_id}/issue", response_model=CertificateResponse, status_code=status.HTTP_201_CREATED)
async def issue_certificate(
    ca_id: uuid.UUID,
    cert_request: CertificateRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    organization: Organization = Depends(get_current_organization),
    db: AsyncSession = Depends(get_db)
):
    """
    Issue a new certificate from a CA
    """
    
    # Validate CA exists and is active
    ca_result = await db.execute(
        select(CertificateAuthority).where(
            and_(
                CertificateAuthority.id == ca_id,
                CertificateAuthority.organization_id == organization.id,
                CertificateAuthority.status == "active"
            )
        )
    )
    ca = ca_result.scalar_one_or_none()
    
    if not ca:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Certificate Authority not found or not active"
        )
    
    # Check organization certificate limits
    existing_certs_count = await db.execute(
        select(func.count(Certificate.id)).where(
            and_(
                Certificate.organization_id == organization.id,
                Certificate.status == "active"
            )
        )
    )
    if existing_certs_count.scalar() >= organization.max_certificates:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Organization certificate limit ({organization.max_certificates}) exceeded"
        )
    
    # Validate certificate request against CA policy
    if cert_request.validity_days > ca.max_validity_days:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Requested validity exceeds CA policy maximum ({ca.max_validity_days} days)"
        )
    
    if ca.allowed_key_types and cert_request.key_type.value not in ca.allowed_key_types:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Key type {cert_request.key_type.value} not allowed by CA policy"
        )
    
    try:
        # Create certificate record
        certificate = await _create_certificate_from_request(
            db=db,
            ca=ca,
            cert_request=cert_request,
            requester=str(current_user.id),
            request_source="api"
        )
        
        # Create audit event
        await create_audit_event(
            db=db,
            organization_id=organization.id,
            event_type="cert.issued",
            event_category="operational",
            severity="info",
            entity_type="certificate",
            entity_id=certificate.id,
            actor_type="user",
            actor_id=str(current_user.id),
            actor_ip=request.client.host if request.client else None,
            event_data={
                "ca_id": str(ca_id),
                "ca_name": ca.name,
                "common_name": certificate.common_name,
                "certificate_type": certificate.certificate_type,
                "validity_days": cert_request.validity_days,
                "serial_number": certificate.serial_number
            },
            request_id=getattr(request.state, "request_id", None)
        )
        
        await db.commit()
        
        logger.info(
            "Certificate issued",
            certificate_id=str(certificate.id),
            ca_id=str(ca_id),
            common_name=certificate.common_name,
            serial_number=certificate.serial_number,
            organization_id=str(organization.id),
            user_id=str(current_user.id)
        )
        
        return CertificateResponse(
            id=certificate.id,
            ca_id=certificate.ca_id,
            organization_id=certificate.organization_id,
            serial_number=certificate.serial_number,
            fingerprint_sha256=certificate.fingerprint_sha256,
            common_name=certificate.common_name,
            subject_dn=certificate.subject_dn,
            subject_alternative_names=certificate.subject_alternative_names,
            certificate_type=certificate.certificate_type,
            key_type=certificate.key_type,
            not_before=certificate.not_before,
            not_after=certificate.not_after,
            status=certificate.status,
            provisioner_id=certificate.provisioner_id,
            template_id=certificate.template_id,
            requester=certificate.requester,
            request_source=certificate.request_source,
            metadata=certificate.metadata,
            created_at=certificate.created_at
        )
        
    except Exception as e:
        await db.rollback()
        logger.error(
            "Failed to issue certificate",
            error=str(e),
            ca_id=str(ca_id),
            common_name=cert_request.common_name,
            organization_id=str(organization.id),
            user_id=str(current_user.id)
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to issue certificate"
        )

@router.get("/{cert_id}", response_model=CertificateDetailResponse)
async def get_certificate(
    cert_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    organization: Organization = Depends(get_current_organization),
    db: AsyncSession = Depends(get_db)
):
    """
    Get detailed certificate information
    """
    
    result = await db.execute(
        select(Certificate).where(
            and_(
                Certificate.id == cert_id,
                Certificate.organization_id == organization.id
            )
        )
    )
    certificate = result.scalar_one_or_none()
    
    if not certificate:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Certificate not found"
        )
    
    return CertificateDetailResponse(
        id=certificate.id,
        ca_id=certificate.ca_id,
        organization_id=certificate.organization_id,
        serial_number=certificate.serial_number,
        fingerprint_sha256=certificate.fingerprint_sha256,
        common_name=certificate.common_name,
        subject_dn=certificate.subject_dn,
        subject_alternative_names=certificate.subject_alternative_names,
        certificate_type=certificate.certificate_type,
        key_type=certificate.key_type,
        not_before=certificate.not_before,
        not_after=certificate.not_after,
        status=certificate.status,
        provisioner_id=certificate.provisioner_id,
        template_id=certificate.template_id,
        requester=certificate.requester,
        request_source=certificate.request_source,
        metadata=certificate.metadata,
        certificate_pem=certificate.certificate_pem,
        revoked_at=certificate.revoked_at,
        revocation_reason=certificate.revocation_reason,
        revoked_by=certificate.revoked_by,
        created_at=certificate.created_at
    )

@router.post("/{cert_id}/revoke")
async def revoke_certificate(
    cert_id: uuid.UUID,
    revocation: CertificateRevocationRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    organization: Organization = Depends(get_current_organization),
    db: AsyncSession = Depends(get_db)
):
    """
    Revoke a certificate
    """
    
    result = await db.execute(
        select(Certificate).where(
            and_(
                Certificate.id == cert_id,
                Certificate.organization_id == organization.id,
                Certificate.status == "active"
            )
        )
    )
    certificate = result.scalar_one_or_none()
    
    if not certificate:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Certificate not found or not active"
        )
    
    try:
        # Update certificate status
        certificate.status = "revoked"
        certificate.revoked_at = datetime.utcnow()
        certificate.revocation_reason = revocation.reason
        certificate.revoked_by = str(current_user.id)
        certificate.updated_at = datetime.utcnow()
        
        # TODO: Integrate with step-ca or OCSP responder to revoke certificate
        
        # Create audit event
        await create_audit_event(
            db=db,
            organization_id=organization.id,
            event_type="cert.revoked",
            event_category="security",
            severity="warning",
            entity_type="certificate",
            entity_id=certificate.id,
            actor_type="user",
            actor_id=str(current_user.id),
            actor_ip=request.client.host if request.client else None,
            event_data={
                "serial_number": certificate.serial_number,
                "common_name": certificate.common_name,
                "revocation_reason": revocation.reason
            },
            request_id=getattr(request.state, "request_id", None)
        )
        
        await db.commit()
        
        logger.warning(
            "Certificate revoked",
            certificate_id=str(certificate.id),
            serial_number=certificate.serial_number,
            common_name=certificate.common_name,
            reason=revocation.reason,
            organization_id=str(organization.id),
            user_id=str(current_user.id)
        )
        
        return {"message": "Certificate revoked successfully"}
        
    except Exception as e:
        await db.rollback()
        logger.error(
            "Failed to revoke certificate",
            error=str(e),
            certificate_id=str(cert_id),
            organization_id=str(organization.id),
            user_id=str(current_user.id)
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to revoke certificate"
        )

@router.get("/expiring/summary")
async def get_expiring_certificates_summary(
    current_user: User = Depends(get_current_user),
    organization: Organization = Depends(get_current_organization),
    db: AsyncSession = Depends(get_db)
):
    """
    Get summary of expiring certificates
    """
    
    now = datetime.utcnow()
    
    # Certificates expiring in 7 days
    expiring_7d = await db.execute(
        select(func.count(Certificate.id)).where(
            and_(
                Certificate.organization_id == organization.id,
                Certificate.status == "active",
                Certificate.not_after <= now + timedelta(days=7),
                Certificate.not_after > now
            )
        )
    )
    
    # Certificates expiring in 30 days
    expiring_30d = await db.execute(
        select(func.count(Certificate.id)).where(
            and_(
                Certificate.organization_id == organization.id,
                Certificate.status == "active",
                Certificate.not_after <= now + timedelta(days=30),
                Certificate.not_after > now
            )
        )
    )
    
    # Expired certificates
    expired = await db.execute(
        select(func.count(Certificate.id)).where(
            and_(
                Certificate.organization_id == organization.id,
                Certificate.status == "active",
                Certificate.not_after <= now
            )
        )
    )
    
    return {
        "expiring_7d": expiring_7d.scalar(),
        "expiring_30d": expiring_30d.scalar(),
        "expired": expired.scalar()
    }

# Helper functions
async def _create_certificate_from_request(
    db: AsyncSession,
    ca: CertificateAuthority,
    cert_request: CertificateRequest,
    requester: str,
    request_source: str
) -> Certificate:
    """
    Create a certificate from a certificate request
    
    In a real implementation, this would integrate with step-ca
    to generate the actual certificate.
    """
    
    # Generate serial number and validity dates
    serial_number = f"{uuid.uuid4().hex[:16]}"
    not_before = datetime.utcnow()
    not_after = not_before + timedelta(days=cert_request.validity_days)
    
    # Build subject DN
    subject_dn = f"CN={cert_request.common_name}"
    
    # Create certificate record
    certificate = Certificate(
        ca_id=ca.id,
        organization_id=ca.organization_id,
        serial_number=serial_number,
        common_name=cert_request.common_name,
        subject_dn=subject_dn,
        subject_alternative_names=cert_request.subject_alternative_names.dict() if cert_request.subject_alternative_names else None,
        certificate_type=cert_request.certificate_type.value,
        key_type=cert_request.key_type.value,
        not_before=not_before,
        not_after=not_after,
        status="active",
        provisioner_id=None,  # TODO: Look up provisioner
        template_id=cert_request.template_id,
        requester=requester,
        request_source=request_source,
        metadata=cert_request.metadata or {}
    )
    
    # Generate mock certificate PEM
    certificate.certificate_pem = f"""-----BEGIN CERTIFICATE-----
MIIBkTCCATegAwIBAgIRAL{serial_number[:20]}wDQYJKoZIhvcNAQELBQAwGjEYMBYG
A1UEAxMPVGVzdCBSb290IENBIDEwHhcNMjQwMjE4MTAwMDAwWhcNMzQwMjE1MTAwMDAw
WjAaMRgwFgYDVQQDEw9UZXN0IFJvb3QgQ0EgMTBZMBMGByqGSM49AgEGCCqGSM49AwEH
A0IABK1pJ8H8VQ4lY3RlG+QjD1A6m4F4X7EX8lV9X8A8f2JzH4T2Y1V9F7A3Q8Y2V1F3
G7H8T6Q4A1B2C5D9E8F1G4H7I6JjMGEwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQF
MAMBAf8wHQYDVR0OBBYEFJ2l3Q4H5Y8F7X2A9B1C4D7E8F2G5H4wHwYDVR0jBBgwFoAU
naXdDgfljwXtfYD0HULgPsTwXYbkfjANBgkqhkiG9w0BAQsFAAOCAQEAr2j...
-----END CERTIFICATE-----"""
    
    # Generate fingerprint
    import hashlib
    certificate.fingerprint_sha256 = hashlib.sha256(certificate.certificate_pem.encode()).hexdigest()
    
    db.add(certificate)
    await db.flush()  # Get certificate ID
    
    return certificate