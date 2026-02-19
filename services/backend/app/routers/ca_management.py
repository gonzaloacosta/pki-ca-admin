"""
Certificate Authority management router
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, desc
from sqlalchemy.orm import selectinload
import structlog
import uuid

from app.core.database import get_db
from app.core.security import get_current_user, get_current_organization
from app.models.database import User, Organization, CertificateAuthority, Certificate
from app.models.schemas import (
    CACreate, CAUpdate, CAResponse, CADetailResponse, PaginatedResponse,
    CAType, CAStatus
)
from app.services.audit_service import create_audit_event
from app.services.ca_service import create_certificate_authority, update_certificate_authority

logger = structlog.get_logger()

router = APIRouter()

@router.get("", response_model=PaginatedResponse)
async def list_certificate_authorities(
    ca_type: Optional[CAType] = Query(None, description="Filter by CA type"),
    status: Optional[CAStatus] = Query(None, description="Filter by CA status"),
    limit: int = Query(20, ge=1, le=100, description="Number of results per page"),
    offset: int = Query(0, ge=0, description="Number of results to skip"),
    current_user: User = Depends(get_current_user),
    organization: Organization = Depends(get_current_organization),
    db: AsyncSession = Depends(get_db)
):
    """
    List certificate authorities for the organization
    """
    
    query = select(CertificateAuthority).where(
        CertificateAuthority.organization_id == organization.id
    )
    
    # Apply filters
    if ca_type:
        query = query.where(CertificateAuthority.type == ca_type.value)
    
    if status:
        query = query.where(CertificateAuthority.status == status.value)
    
    # Get total count
    count_query = select(func.count(CertificateAuthority.id)).where(
        CertificateAuthority.organization_id == organization.id
    )
    if ca_type:
        count_query = count_query.where(CertificateAuthority.type == ca_type.value)
    if status:
        count_query = count_query.where(CertificateAuthority.status == status.value)
        
    total_result = await db.execute(count_query)
    total = total_result.scalar()
    
    # Apply pagination and ordering
    query = query.order_by(
        desc(CertificateAuthority.created_at)
    ).limit(limit).offset(offset)
    
    result = await db.execute(query)
    cas = result.scalars().all()
    
    # Convert to response schemas
    ca_responses = [
        CAResponse(
            id=ca.id,
            organization_id=ca.organization_id,
            name=ca.name,
            description=ca.description,
            type=ca.type,
            parent_ca_id=ca.parent_ca_id,
            subject=_parse_subject_dn(ca.subject_dn),
            key_type=ca.key_type,
            key_storage=ca.key_storage,
            validity_years=_calculate_validity_years(ca.not_before, ca.not_after) if ca.not_before and ca.not_after else None,
            auto_renewal=ca.auto_renewal,
            renewal_threshold_days=ca.renewal_threshold_days,
            policy=_parse_ca_policy(ca),
            metadata=ca.metadata,
            status=ca.status,
            subject_dn=ca.subject_dn,
            serial_number=ca.serial_number,
            not_before=ca.not_before,
            not_after=ca.not_after,
            kms_key_id=ca.kms_key_id,
            kms_region=ca.kms_region,
            created_at=ca.created_at,
            updated_at=ca.updated_at,
            created_by=ca.created_by
        )
        for ca in cas
    ]
    
    return PaginatedResponse(
        data=ca_responses,
        total=total,
        limit=limit,
        offset=offset,
        has_more=offset + limit < total
    )

@router.post("", response_model=CAResponse, status_code=status.HTTP_201_CREATED)
async def create_ca(
    ca_data: CACreate,
    request: Request,
    current_user: User = Depends(get_current_user),
    organization: Organization = Depends(get_current_organization),
    db: AsyncSession = Depends(get_db)
):
    """
    Create a new certificate authority
    """
    
    # Validate organization limits
    existing_cas_count = await db.execute(
        select(func.count(CertificateAuthority.id)).where(
            CertificateAuthority.organization_id == organization.id
        )
    )
    if existing_cas_count.scalar() >= organization.max_cas:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Organization CA limit ({organization.max_cas}) exceeded"
        )
    
    # Validate parent CA exists if specified
    if ca_data.parent_ca_id:
        parent_ca_result = await db.execute(
            select(CertificateAuthority).where(
                and_(
                    CertificateAuthority.id == ca_data.parent_ca_id,
                    CertificateAuthority.organization_id == organization.id,
                    CertificateAuthority.status == "active"
                )
            )
        )
        parent_ca = parent_ca_result.scalar_one_or_none()
        if not parent_ca:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Parent CA not found or not active"
            )
    
    # Check for duplicate CA name
    existing_ca_result = await db.execute(
        select(CertificateAuthority).where(
            and_(
                CertificateAuthority.organization_id == organization.id,
                CertificateAuthority.name == ca_data.name
            )
        )
    )
    if existing_ca_result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="CA with this name already exists"
        )
    
    try:
        # Create the certificate authority
        ca = await create_certificate_authority(
            db=db,
            organization_id=organization.id,
            ca_data=ca_data,
            created_by=str(current_user.id)
        )
        
        # Create audit event
        await create_audit_event(
            db=db,
            organization_id=organization.id,
            event_type="ca.created",
            event_category="operational",
            severity="info",
            entity_type="ca",
            entity_id=ca.id,
            actor_type="user",
            actor_id=str(current_user.id),
            actor_ip=request.client.host if request.client else None,
            event_data={
                "ca_name": ca.name,
                "ca_type": ca.type,
                "key_type": ca.key_type,
                "key_storage": ca.key_storage,
                "parent_ca_id": str(ca.parent_ca_id) if ca.parent_ca_id else None,
            },
            request_id=getattr(request.state, "request_id", None)
        )
        
        await db.commit()
        
        logger.info(
            "Certificate Authority created",
            ca_id=str(ca.id),
            ca_name=ca.name,
            ca_type=ca.type,
            organization_id=str(organization.id),
            user_id=str(current_user.id)
        )
        
        return CAResponse(
            id=ca.id,
            organization_id=ca.organization_id,
            name=ca.name,
            description=ca.description,
            type=ca.type,
            parent_ca_id=ca.parent_ca_id,
            subject=_parse_subject_dn(ca.subject_dn),
            key_type=ca.key_type,
            key_storage=ca.key_storage,
            validity_years=_calculate_validity_years(ca.not_before, ca.not_after) if ca.not_before and ca.not_after else None,
            auto_renewal=ca.auto_renewal,
            renewal_threshold_days=ca.renewal_threshold_days,
            policy=_parse_ca_policy(ca),
            metadata=ca.metadata,
            status=ca.status,
            subject_dn=ca.subject_dn,
            serial_number=ca.serial_number,
            not_before=ca.not_before,
            not_after=ca.not_after,
            kms_key_id=ca.kms_key_id,
            kms_region=ca.kms_region,
            created_at=ca.created_at,
            updated_at=ca.updated_at,
            created_by=ca.created_by
        )
        
    except Exception as e:
        await db.rollback()
        logger.error(
            "Failed to create Certificate Authority",
            error=str(e),
            ca_name=ca_data.name,
            organization_id=str(organization.id),
            user_id=str(current_user.id)
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create Certificate Authority"
        )

@router.get("/{ca_id}", response_model=CADetailResponse)
async def get_certificate_authority(
    ca_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    organization: Organization = Depends(get_current_organization),
    db: AsyncSession = Depends(get_db)
):
    """
    Get detailed information about a certificate authority
    """
    
    # Get CA with related data
    result = await db.execute(
        select(CertificateAuthority)
        .options(selectinload(CertificateAuthority.certificates))
        .where(
            and_(
                CertificateAuthority.id == ca_id,
                CertificateAuthority.organization_id == organization.id
            )
        )
    )
    ca = result.scalar_one_or_none()
    
    if not ca:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Certificate Authority not found"
        )
    
    # Count children CAs
    children_count_result = await db.execute(
        select(func.count(CertificateAuthority.id)).where(
            CertificateAuthority.parent_ca_id == ca_id
        )
    )
    children_count = children_count_result.scalar()
    
    # Count issued certificates
    issued_certs_count = len(ca.certificates)
    active_certs_count = len([cert for cert in ca.certificates if cert.status == "active"])
    
    return CADetailResponse(
        id=ca.id,
        organization_id=ca.organization_id,
        name=ca.name,
        description=ca.description,
        type=ca.type,
        parent_ca_id=ca.parent_ca_id,
        subject=_parse_subject_dn(ca.subject_dn),
        key_type=ca.key_type,
        key_storage=ca.key_storage,
        validity_years=_calculate_validity_years(ca.not_before, ca.not_after) if ca.not_before and ca.not_after else None,
        auto_renewal=ca.auto_renewal,
        renewal_threshold_days=ca.renewal_threshold_days,
        policy=_parse_ca_policy(ca),
        metadata=ca.metadata,
        status=ca.status,
        subject_dn=ca.subject_dn,
        serial_number=ca.serial_number,
        not_before=ca.not_before,
        not_after=ca.not_after,
        kms_key_id=ca.kms_key_id,
        kms_region=ca.kms_region,
        certificate_pem=ca.certificate_pem,
        certificate_chain_pem=ca.certificate_chain_pem,
        children_count=children_count,
        issued_certificates_count=issued_certs_count,
        active_certificates_count=active_certs_count,
        created_at=ca.created_at,
        updated_at=ca.updated_at,
        created_by=ca.created_by
    )

@router.put("/{ca_id}", response_model=CAResponse)
async def update_ca(
    ca_id: uuid.UUID,
    ca_update: CAUpdate,
    request: Request,
    current_user: User = Depends(get_current_user),
    organization: Organization = Depends(get_current_organization),
    db: AsyncSession = Depends(get_db)
):
    """
    Update certificate authority configuration
    """
    
    # Get existing CA
    result = await db.execute(
        select(CertificateAuthority).where(
            and_(
                CertificateAuthority.id == ca_id,
                CertificateAuthority.organization_id == organization.id
            )
        )
    )
    ca = result.scalar_one_or_none()
    
    if not ca:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Certificate Authority not found"
        )
    
    # Store original values for audit
    original_values = {
        "name": ca.name,
        "description": ca.description,
        "auto_renewal": ca.auto_renewal,
        "renewal_threshold_days": ca.renewal_threshold_days,
        "metadata": ca.metadata
    }
    
    try:
        # Update the CA
        updated_ca = await update_certificate_authority(
            db=db,
            ca=ca,
            ca_update=ca_update
        )
        
        # Create audit event
        changes = {}
        for field in ["name", "description", "auto_renewal", "renewal_threshold_days", "metadata"]:
            old_value = original_values.get(field)
            new_value = getattr(updated_ca, field)
            if old_value != new_value:
                changes[field] = {"before": old_value, "after": new_value}
        
        if changes:
            await create_audit_event(
                db=db,
                organization_id=organization.id,
                event_type="ca.updated",
                event_category="operational",
                severity="info",
                entity_type="ca",
                entity_id=ca.id,
                actor_type="user",
                actor_id=str(current_user.id),
                actor_ip=request.client.host if request.client else None,
                event_data={
                    "ca_name": updated_ca.name,
                    "ca_id": str(ca.id)
                },
                changes=changes,
                request_id=getattr(request.state, "request_id", None)
            )
        
        await db.commit()
        
        logger.info(
            "Certificate Authority updated",
            ca_id=str(ca.id),
            ca_name=updated_ca.name,
            changes=list(changes.keys()),
            organization_id=str(organization.id),
            user_id=str(current_user.id)
        )
        
        return CAResponse(
            id=updated_ca.id,
            organization_id=updated_ca.organization_id,
            name=updated_ca.name,
            description=updated_ca.description,
            type=updated_ca.type,
            parent_ca_id=updated_ca.parent_ca_id,
            subject=_parse_subject_dn(updated_ca.subject_dn),
            key_type=updated_ca.key_type,
            key_storage=updated_ca.key_storage,
            validity_years=_calculate_validity_years(updated_ca.not_before, updated_ca.not_after) if updated_ca.not_before and updated_ca.not_after else None,
            auto_renewal=updated_ca.auto_renewal,
            renewal_threshold_days=updated_ca.renewal_threshold_days,
            policy=_parse_ca_policy(updated_ca),
            metadata=updated_ca.metadata,
            status=updated_ca.status,
            subject_dn=updated_ca.subject_dn,
            serial_number=updated_ca.serial_number,
            not_before=updated_ca.not_before,
            not_after=updated_ca.not_after,
            kms_key_id=updated_ca.kms_key_id,
            kms_region=updated_ca.kms_region,
            created_at=updated_ca.created_at,
            updated_at=updated_ca.updated_at,
            created_by=updated_ca.created_by
        )
        
    except Exception as e:
        await db.rollback()
        logger.error(
            "Failed to update Certificate Authority",
            error=str(e),
            ca_id=str(ca_id),
            organization_id=str(organization.id),
            user_id=str(current_user.id)
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update Certificate Authority"
        )

# Helper functions
def _parse_subject_dn(subject_dn: str) -> dict:
    """Parse X.500 Distinguished Name into dictionary"""
    # TODO: Implement proper DN parsing
    # For now, return a simplified structure
    return {"common_name": subject_dn}

def _calculate_validity_years(not_before, not_after) -> int:
    """Calculate validity period in years"""
    if not not_before or not not_after:
        return 0
    delta = not_after - not_before
    return int(delta.days / 365)

def _parse_ca_policy(ca) -> dict:
    """Extract CA policy from database model"""
    return {
        "max_path_length": ca.max_path_length,
        "allowed_key_types": ca.allowed_key_types or [],
        "max_validity_days": ca.max_validity_days,
        "crl_distribution_points": ca.crl_distribution_points or [],
        "ocsp_responder_url": ca.ocsp_responder_url
    }