"""
API endpoints for Certificate Authority management.
"""

from typing import List, Optional, Dict, Any
from datetime import datetime
import uuid

from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, or_
from sqlalchemy.orm import selectinload

from app.core.database import get_db
from app.core.security import CurrentUser, require_admin, require_operator, require_viewer
from app.models import CaNode, Certificate, AuditEvent
from app.schemas.ca import (
    CaNodeCreate,
    CaNodeUpdate, 
    CaNodeResponse,
    CaNodeListResponse,
    CaTreeResponse,
    CaHierarchyResponse,
    CaStatsResponse
)
from app.services.ca_engine import CaEngine, CaEngineError
from app.services.key_backend import get_key_backend

router = APIRouter(prefix="/cas", tags=["Certificate Authorities"])


@router.get("", response_model=CaNodeListResponse)
async def list_cas(
    db: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(require_viewer),
    type: Optional[str] = Query(None, description="Filter by CA type (root, intermediate)"),
    status: Optional[str] = Query(None, description="Filter by status (active, suspended, revoked)"),
    page: int = Query(1, ge=1, description="Page number"),
    size: int = Query(20, ge=1, le=100, description="Page size")
):
    """
    List certificate authorities with pagination and filtering.
    """
    try:
        # Build query
        query = select(CaNode)
        
        # Apply filters
        if type:
            query = query.where(CaNode.type == type)
        if status:
            query = query.where(CaNode.status == status)
        
        # Count total records
        count_query = select(func.count()).select_from(CaNode)
        if type:
            count_query = count_query.where(CaNode.type == type)
        if status:
            count_query = count_query.where(CaNode.status == status)
        
        total_result = await db.execute(count_query)
        total = total_result.scalar()
        
        # Apply pagination
        offset = (page - 1) * size
        query = query.offset(offset).limit(size).order_by(CaNode.created_at.desc())
        
        result = await db.execute(query)
        cas = result.scalars().all()
        
        # Convert to response models
        ca_responses = []
        for ca in cas:
            ca_dict = {
                "id": ca.id,
                "name": ca.name,
                "description": ca.description,
                "type": ca.type,
                "parent_ca_id": ca.parent_ca_id,
                "subject_dn": ca.subject_dn,
                "certificate_pem": ca.certificate_pem,
                "serial_number": ca.serial_number,
                "not_before": ca.not_before,
                "not_after": ca.not_after,
                "key_type": ca.key_type,
                "key_storage": ca.key_storage,
                "kms_key_id": ca.kms_key_id,
                "kms_region": ca.kms_region,
                "max_path_length": ca.max_path_length,
                "allowed_key_types": ca.allowed_key_types,
                "max_validity_days": ca.max_validity_days,
                "crl_distribution_points": ca.crl_distribution_points,
                "ocsp_responder_url": ca.ocsp_responder_url,
                "status": ca.status,
                "auto_renewal": ca.auto_renewal,
                "renewal_threshold_days": ca.renewal_threshold_days,
                "metadata": ca.metadata_,
                "created_at": ca.created_at,
                "updated_at": ca.updated_at,
                "created_by": ca.created_by,
                "is_root": ca.is_root,
                "is_intermediate": ca.is_intermediate,
                "is_expired": ca.is_expired,
                "is_expiring_soon": ca.is_expiring_soon,
                "depth": ca.get_depth(),
            }
            ca_responses.append(CaNodeResponse(**ca_dict))
        
        pages = (total + size - 1) // size
        
        return CaNodeListResponse(
            items=ca_responses,
            total=total,
            page=page,
            size=size,
            pages=pages
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list CAs: {str(e)}"
        )


@router.get("/tree", response_model=CaTreeResponse)
async def get_ca_tree(
    db: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(require_viewer)
):
    """
    Get the complete CA hierarchy tree.
    """
    try:
        # Get all CAs with their relationships
        query = select(CaNode).options(selectinload(CaNode.children)).order_by(CaNode.created_at)
        result = await db.execute(query)
        all_cas = result.scalars().all()
        
        # Build tree structure starting from root CAs
        root_cas = [ca for ca in all_cas if ca.is_root]
        
        def build_hierarchy(ca: CaNode) -> CaHierarchyResponse:
            # Get certificate count for this CA
            cert_count_query = select(func.count()).select_from(Certificate).where(Certificate.ca_id == ca.id)
            cert_count_result = db.execute(cert_count_query)
            cert_count = cert_count_result.scalar() or 0
            
            ca_dict = {
                "id": ca.id,
                "name": ca.name,
                "description": ca.description,
                "type": ca.type,
                "parent_ca_id": ca.parent_ca_id,
                "subject_dn": ca.subject_dn,
                "certificate_pem": ca.certificate_pem,
                "serial_number": ca.serial_number,
                "not_before": ca.not_before,
                "not_after": ca.not_after,
                "key_type": ca.key_type,
                "key_storage": ca.key_storage,
                "kms_key_id": ca.kms_key_id,
                "kms_region": ca.kms_region,
                "max_path_length": ca.max_path_length,
                "allowed_key_types": ca.allowed_key_types,
                "max_validity_days": ca.max_validity_days,
                "crl_distribution_points": ca.crl_distribution_points,
                "ocsp_responder_url": ca.ocsp_responder_url,
                "status": ca.status,
                "auto_renewal": ca.auto_renewal,
                "renewal_threshold_days": ca.renewal_threshold_days,
                "metadata": ca.metadata_,
                "created_at": ca.created_at,
                "updated_at": ca.updated_at,
                "created_by": ca.created_by,
                "is_root": ca.is_root,
                "is_intermediate": ca.is_intermediate,
                "is_expired": ca.is_expired,
                "is_expiring_soon": ca.is_expiring_soon,
                "depth": ca.get_depth(),
                "certificate_count": cert_count
            }
            
            hierarchy_ca = CaHierarchyResponse(**ca_dict)
            hierarchy_ca.children = [build_hierarchy(child) for child in ca.children]
            
            return hierarchy_ca
        
        root_hierarchy = [build_hierarchy(root_ca) for root_ca in root_cas]
        
        return CaTreeResponse(
            root_cas=root_hierarchy,
            total_cas=len(all_cas)
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get CA tree: {str(e)}"
        )


@router.get("/stats", response_model=CaStatsResponse)
async def get_ca_stats(
    db: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(require_viewer)
):
    """
    Get certificate authority statistics.
    """
    try:
        # CA statistics
        total_cas_query = select(func.count()).select_from(CaNode)
        root_cas_query = select(func.count()).select_from(CaNode).where(CaNode.type == "root")
        intermediate_cas_query = select(func.count()).select_from(CaNode).where(CaNode.type == "intermediate")
        active_cas_query = select(func.count()).select_from(CaNode).where(CaNode.status == "active")
        
        total_cas = (await db.execute(total_cas_query)).scalar()
        root_cas = (await db.execute(root_cas_query)).scalar()
        intermediate_cas = (await db.execute(intermediate_cas_query)).scalar()
        active_cas = (await db.execute(active_cas_query)).scalar()
        
        # Expired and expiring CAs
        now = datetime.utcnow()
        expired_cas_query = select(func.count()).select_from(CaNode).where(CaNode.not_after < now)
        expired_cas = (await db.execute(expired_cas_query)).scalar()
        
        # Certificate statistics
        total_certs_query = select(func.count()).select_from(Certificate)
        active_certs_query = select(func.count()).select_from(Certificate).where(Certificate.status == "active")
        expired_certs_query = select(func.count()).select_from(Certificate).where(Certificate.not_after < now)
        revoked_certs_query = select(func.count()).select_from(Certificate).where(Certificate.status == "revoked")
        
        total_certificates = (await db.execute(total_certs_query)).scalar()
        active_certificates = (await db.execute(active_certs_query)).scalar()
        expired_certificates = (await db.execute(expired_certs_query)).scalar()
        revoked_certificates = (await db.execute(revoked_certs_query)).scalar()
        
        # Expiring soon (would need more complex query for CAs)
        expiring_soon_cas = 0  # Placeholder
        
        return CaStatsResponse(
            total_cas=total_cas,
            root_cas=root_cas,
            intermediate_cas=intermediate_cas,
            active_cas=active_cas,
            expired_cas=expired_cas,
            expiring_soon_cas=expiring_soon_cas,
            total_certificates=total_certificates,
            active_certificates=active_certificates,
            expired_certificates=expired_certificates,
            revoked_certificates=revoked_certificates
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get CA statistics: {str(e)}"
        )


@router.get("/{ca_id}", response_model=CaNodeResponse)
async def get_ca(
    ca_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(require_viewer)
):
    """
    Get a specific certificate authority by ID.
    """
    try:
        query = select(CaNode).where(CaNode.id == ca_id)
        result = await db.execute(query)
        ca = result.scalar_one_or_none()
        
        if not ca:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"CA not found: {ca_id}"
            )
        
        ca_dict = {
            "id": ca.id,
            "name": ca.name,
            "description": ca.description,
            "type": ca.type,
            "parent_ca_id": ca.parent_ca_id,
            "subject_dn": ca.subject_dn,
            "certificate_pem": ca.certificate_pem,
            "serial_number": ca.serial_number,
            "not_before": ca.not_before,
            "not_after": ca.not_after,
            "key_type": ca.key_type,
            "key_storage": ca.key_storage,
            "kms_key_id": ca.kms_key_id,
            "kms_region": ca.kms_region,
            "max_path_length": ca.max_path_length,
            "allowed_key_types": ca.allowed_key_types,
            "max_validity_days": ca.max_validity_days,
            "crl_distribution_points": ca.crl_distribution_points,
            "ocsp_responder_url": ca.ocsp_responder_url,
            "status": ca.status,
            "auto_renewal": ca.auto_renewal,
            "renewal_threshold_days": ca.renewal_threshold_days,
            "metadata": ca.metadata_,
            "created_at": ca.created_at,
            "updated_at": ca.updated_at,
            "created_by": ca.created_by,
            "is_root": ca.is_root,
            "is_intermediate": ca.is_intermediate,
            "is_expired": ca.is_expired,
            "is_expiring_soon": ca.is_expiring_soon,
            "depth": ca.get_depth(),
        }
        
        return CaNodeResponse(**ca_dict)
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get CA: {str(e)}"
        )


@router.post("", response_model=CaNodeResponse, status_code=status.HTTP_201_CREATED)
async def create_ca(
    ca_create: CaNodeCreate,
    db: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(require_admin)
):
    """
    Create a new certificate authority.
    """
    try:
        # Validate parent CA if this is an intermediate CA
        parent_ca = None
        if ca_create.type == "intermediate":
            if not ca_create.parent_ca_id:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Intermediate CAs must have a parent CA"
                )
            
            parent_query = select(CaNode).where(CaNode.id == ca_create.parent_ca_id)
            parent_result = await db.execute(parent_query)
            parent_ca = parent_result.scalar_one_or_none()
            
            if not parent_ca:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Parent CA not found: {ca_create.parent_ca_id}"
                )
            
            if parent_ca.status != "active":
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Parent CA must be active"
                )
        
        # Initialize CA engine
        ca_engine = CaEngine()
        
        # Generate key pair
        key_id, private_key = await ca_engine.generate_key_pair(ca_create.key_type)
        
        # Create certificate
        if ca_create.type == "root":
            # Create self-signed certificate
            certificate_pem = await ca_engine.create_self_signed_certificate(
                key_id=key_id,
                subject=ca_create.subject,
                validity_years=ca_create.validity_years,
                key_type=ca_create.key_type,
                is_ca=True,
                max_path_length=ca_create.policy.max_path_length if ca_create.policy else None
            )
        else:
            # Create intermediate CA certificate
            certificate_pem = await ca_engine.sign_certificate(
                ca_key_id=parent_ca.kms_key_id,
                ca_certificate_pem=parent_ca.certificate_pem,
                subject=ca_create.subject,
                public_key=private_key.public_key(),
                validity_days=ca_create.validity_years * 365,
                certificate_type="ca",
                is_ca=True,
                max_path_length=ca_create.policy.max_path_length if ca_create.policy else None
            )
        
        # Parse certificate to extract details
        from cryptography import x509
        cert = x509.load_pem_x509_certificate(certificate_pem.encode())
        
        # Create CA record
        ca = CaNode(
            name=ca_create.name,
            description=ca_create.description,
            type=ca_create.type,
            parent_ca_id=ca_create.parent_ca_id,
            subject_dn=cert.subject.rfc4514_string(),
            certificate_pem=certificate_pem,
            serial_number=str(cert.serial_number),
            not_before=cert.not_valid_before,
            not_after=cert.not_valid_after,
            key_type=ca_create.key_type,
            key_storage="file",  # TODO: Use configured backend
            kms_key_id=key_id,
            max_path_length=ca_create.policy.max_path_length if ca_create.policy else None,
            allowed_key_types=ca_create.policy.allowed_key_types if ca_create.policy else None,
            max_validity_days=ca_create.policy.max_validity_days if ca_create.policy else ca_create.validity_years * 365,
            auto_renewal=ca_create.auto_renewal,
            renewal_threshold_days=ca_create.renewal_threshold_days,
            created_by=current_user.user_id
        )
        
        db.add(ca)
        await db.commit()
        await db.refresh(ca)
        
        # Create audit event
        audit_event = AuditEvent.create_ca_event(
            event_type="ca.created",
            ca_id=ca.id,
            actor_id=current_user.user_id,
            event_data={
                "ca_name": ca.name,
                "ca_type": ca.type,
                "key_type": ca.key_type,
                "validity_years": ca_create.validity_years
            }
        )
        db.add(audit_event)
        await db.commit()
        
        # Return response
        ca_dict = {
            "id": ca.id,
            "name": ca.name,
            "description": ca.description,
            "type": ca.type,
            "parent_ca_id": ca.parent_ca_id,
            "subject_dn": ca.subject_dn,
            "certificate_pem": ca.certificate_pem,
            "serial_number": ca.serial_number,
            "not_before": ca.not_before,
            "not_after": ca.not_after,
            "key_type": ca.key_type,
            "key_storage": ca.key_storage,
            "kms_key_id": ca.kms_key_id,
            "kms_region": ca.kms_region,
            "max_path_length": ca.max_path_length,
            "allowed_key_types": ca.allowed_key_types,
            "max_validity_days": ca.max_validity_days,
            "crl_distribution_points": ca.crl_distribution_points,
            "ocsp_responder_url": ca.ocsp_responder_url,
            "status": ca.status,
            "auto_renewal": ca.auto_renewal,
            "renewal_threshold_days": ca.renewal_threshold_days,
            "metadata": ca.metadata_,
            "created_at": ca.created_at,
            "updated_at": ca.updated_at,
            "created_by": ca.created_by,
            "is_root": ca.is_root,
            "is_intermediate": ca.is_intermediate,
            "is_expired": ca.is_expired,
            "is_expiring_soon": ca.is_expiring_soon,
            "depth": ca.get_depth(),
        }
        
        return CaNodeResponse(**ca_dict)
        
    except HTTPException:
        raise
    except CaEngineError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"CA creation failed: {str(e)}"
        )
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create CA: {str(e)}"
        )


@router.put("/{ca_id}", response_model=CaNodeResponse)
async def update_ca(
    ca_id: uuid.UUID,
    ca_update: CaNodeUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(require_admin)
):
    """
    Update a certificate authority.
    """
    try:
        query = select(CaNode).where(CaNode.id == ca_id)
        result = await db.execute(query)
        ca = result.scalar_one_or_none()
        
        if not ca:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"CA not found: {ca_id}"
            )
        
        # Store original values for audit
        changes = {}
        
        # Update fields
        if ca_update.name is not None:
            changes["name"] = {"old": ca.name, "new": ca_update.name}
            ca.name = ca_update.name
        
        if ca_update.description is not None:
            changes["description"] = {"old": ca.description, "new": ca_update.description}
            ca.description = ca_update.description
        
        if ca_update.status is not None:
            changes["status"] = {"old": ca.status, "new": ca_update.status}
            ca.status = ca_update.status
        
        if ca_update.auto_renewal is not None:
            changes["auto_renewal"] = {"old": ca.auto_renewal, "new": ca_update.auto_renewal}
            ca.auto_renewal = ca_update.auto_renewal
        
        if ca_update.renewal_threshold_days is not None:
            changes["renewal_threshold_days"] = {"old": ca.renewal_threshold_days, "new": ca_update.renewal_threshold_days}
            ca.renewal_threshold_days = ca_update.renewal_threshold_days
        
        if ca_update.metadata is not None:
            changes["metadata"] = {"old": ca.metadata_, "new": ca_update.metadata}
            ca.metadata_ = ca_update.metadata
        
        ca.updated_at = datetime.utcnow()
        
        await db.commit()
        await db.refresh(ca)
        
        # Create audit event
        if changes:
            audit_event = AuditEvent.create_ca_event(
                event_type="ca.updated",
                ca_id=ca.id,
                actor_id=current_user.user_id,
                event_data={"ca_name": ca.name},
                changes=changes
            )
            db.add(audit_event)
            await db.commit()
        
        # Return response
        ca_dict = {
            "id": ca.id,
            "name": ca.name,
            "description": ca.description,
            "type": ca.type,
            "parent_ca_id": ca.parent_ca_id,
            "subject_dn": ca.subject_dn,
            "certificate_pem": ca.certificate_pem,
            "serial_number": ca.serial_number,
            "not_before": ca.not_before,
            "not_after": ca.not_after,
            "key_type": ca.key_type,
            "key_storage": ca.key_storage,
            "kms_key_id": ca.kms_key_id,
            "kms_region": ca.kms_region,
            "max_path_length": ca.max_path_length,
            "allowed_key_types": ca.allowed_key_types,
            "max_validity_days": ca.max_validity_days,
            "crl_distribution_points": ca.crl_distribution_points,
            "ocsp_responder_url": ca.ocsp_responder_url,
            "status": ca.status,
            "auto_renewal": ca.auto_renewal,
            "renewal_threshold_days": ca.renewal_threshold_days,
            "metadata": ca.metadata_,
            "created_at": ca.created_at,
            "updated_at": ca.updated_at,
            "created_by": ca.created_by,
            "is_root": ca.is_root,
            "is_intermediate": ca.is_intermediate,
            "is_expired": ca.is_expired,
            "is_expiring_soon": ca.is_expiring_soon,
            "depth": ca.get_depth(),
        }
        
        return CaNodeResponse(**ca_dict)
        
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update CA: {str(e)}"
        )


@router.delete("/{ca_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_ca(
    ca_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(require_admin)
):
    """
    Delete (deactivate) a certificate authority.
    This sets the status to 'revoked' rather than physically deleting.
    """
    try:
        query = select(CaNode).where(CaNode.id == ca_id)
        result = await db.execute(query)
        ca = result.scalar_one_or_none()
        
        if not ca:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"CA not found: {ca_id}"
            )
        
        # Check if CA has active children
        children_query = select(func.count()).select_from(CaNode).where(
            and_(CaNode.parent_ca_id == ca_id, CaNode.status == "active")
        )
        children_count = (await db.execute(children_query)).scalar()
        
        if children_count > 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot delete CA with active child CAs"
            )
        
        # Soft delete by setting status to revoked
        ca.status = "revoked"
        ca.updated_at = datetime.utcnow()
        
        await db.commit()
        
        # Create audit event
        audit_event = AuditEvent.create_ca_event(
            event_type="ca.revoked",
            ca_id=ca.id,
            actor_id=current_user.user_id,
            event_data={"ca_name": ca.name, "reason": "administrative_deletion"}
        )
        db.add(audit_event)
        await db.commit()
        
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete CA: {str(e)}"
        )