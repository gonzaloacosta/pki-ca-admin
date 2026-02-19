"""
Audit router for querying audit logs
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime

from app.core.database import get_db
from app.core.security import get_current_user, get_current_organization
from app.models.database import User, Organization
from app.models.schemas import AuditEventResponse, PaginatedResponse, PaginationParams
from app.services.audit_service import get_audit_events, count_audit_events

router = APIRouter()

@router.get("", response_model=PaginatedResponse)
async def get_audit_log(
    event_types: Optional[List[str]] = Query(None, description="Filter by event types"),
    entity_types: Optional[List[str]] = Query(None, description="Filter by entity types"),
    actor_ids: Optional[List[str]] = Query(None, description="Filter by actor IDs"), 
    severities: Optional[List[str]] = Query(None, description="Filter by severity levels"),
    start_date: Optional[datetime] = Query(None, description="Start date filter"),
    end_date: Optional[datetime] = Query(None, description="End date filter"),
    limit: int = Query(20, ge=1, le=100, description="Number of results per page"),
    offset: int = Query(0, ge=0, description="Number of results to skip"),
    current_user: User = Depends(get_current_user),
    organization: Organization = Depends(get_current_organization),
    db: AsyncSession = Depends(get_db)
):
    """
    Query audit events with filtering and pagination
    """
    
    # Get audit events
    events = await get_audit_events(
        db=db,
        organization_id=organization.id,
        event_types=event_types,
        entity_types=entity_types,
        actor_ids=actor_ids,
        severities=severities,
        start_date=start_date,
        end_date=end_date,
        limit=limit,
        offset=offset
    )
    
    # Get total count
    total = await count_audit_events(
        db=db,
        organization_id=organization.id,
        event_types=event_types,
        entity_types=entity_types,
        start_date=start_date,
        end_date=end_date
    )
    
    # Convert to response schemas
    event_responses = [
        AuditEventResponse(
            id=event.id,
            event_type=event.event_type,
            event_category=event.event_category,
            severity=event.severity,
            entity_type=event.entity_type,
            entity_id=event.entity_id,
            actor_type=event.actor_type,
            actor_id=event.actor_id,
            actor_ip=event.actor_ip,
            event_data=event.event_data or {},
            changes=event.changes,
            request_id=event.request_id,
            created_at=event.created_at
        )
        for event in events
    ]
    
    return PaginatedResponse(
        data=event_responses,
        total=total,
        limit=limit,
        offset=offset,
        has_more=offset + limit < total
    )

@router.get("/types")
async def get_available_event_types(
    current_user: User = Depends(get_current_user)
):
    """
    Get list of available audit event types
    """
    from app.services.audit_service import AUDIT_EVENT_TYPES
    
    return {
        "event_types": [
            {
                "type": event_type,
                "category": metadata.get("category"),
                "severity": metadata.get("severity"),
                "description": metadata.get("description")
            }
            for event_type, metadata in AUDIT_EVENT_TYPES.items()
        ]
    }

@router.get("/stats")
async def get_audit_stats(
    days: int = Query(30, ge=1, le=365, description="Number of days to analyze"),
    current_user: User = Depends(get_current_user),
    organization: Organization = Depends(get_current_organization),
    db: AsyncSession = Depends(get_db)
):
    """
    Get audit statistics for the specified time period
    """
    from datetime import timedelta
    from sqlalchemy import select, func
    from app.models.database import AuditEvent
    
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=days)
    
    # Get event counts by type
    event_type_query = select(
        AuditEvent.event_type,
        func.count(AuditEvent.id).label('count')
    ).where(
        AuditEvent.organization_id == organization.id,
        AuditEvent.created_at >= start_date,
        AuditEvent.created_at <= end_date
    ).group_by(AuditEvent.event_type)
    
    result = await db.execute(event_type_query)
    event_type_counts = dict(result.fetchall())
    
    # Get event counts by category
    category_query = select(
        AuditEvent.event_category,
        func.count(AuditEvent.id).label('count')
    ).where(
        AuditEvent.organization_id == organization.id,
        AuditEvent.created_at >= start_date,
        AuditEvent.created_at <= end_date
    ).group_by(AuditEvent.event_category)
    
    result = await db.execute(category_query)
    category_counts = dict(result.fetchall())
    
    # Get event counts by severity
    severity_query = select(
        AuditEvent.severity,
        func.count(AuditEvent.id).label('count')
    ).where(
        AuditEvent.organization_id == organization.id,
        AuditEvent.created_at >= start_date,
        AuditEvent.created_at <= end_date
    ).group_by(AuditEvent.severity)
    
    result = await db.execute(severity_query)
    severity_counts = dict(result.fetchall())
    
    # Get total count
    total_count = await count_audit_events(
        db=db,
        organization_id=organization.id,
        start_date=start_date,
        end_date=end_date
    )
    
    return {
        "period": {
            "start_date": start_date,
            "end_date": end_date,
            "days": days
        },
        "total_events": total_count,
        "by_type": event_type_counts,
        "by_category": category_counts,
        "by_severity": severity_counts
    }