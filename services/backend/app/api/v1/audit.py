"""
API endpoints for Audit event management.
"""

from typing import Optional
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, or_

from app.core.database import get_db
from app.core.security import CurrentUser, require_admin, require_viewer
from app.models import AuditEvent
from app.schemas.audit import (
    AuditEventResponse,
    AuditEventListResponse,
    AuditEventSearchRequest,
    AuditStatsResponse
)

router = APIRouter(prefix="/audit", tags=["Audit"])


@router.get("", response_model=AuditEventListResponse)
async def list_audit_events(
    db: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(require_viewer),
    event_type: Optional[str] = Query(None, description="Filter by event type"),
    event_category: Optional[str] = Query(None, description="Filter by category"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    entity_type: Optional[str] = Query(None, description="Filter by entity type"),
    actor_id: Optional[str] = Query(None, description="Filter by actor ID"),
    start_date: Optional[datetime] = Query(None, description="Start date filter"),
    end_date: Optional[datetime] = Query(None, description="End date filter"),
    page: int = Query(1, ge=1, description="Page number"),
    size: int = Query(20, ge=1, le=100, description="Page size")
):
    """
    List audit events with filtering and pagination.
    """
    try:
        # Build query with tenant filtering
        query = select(AuditEvent)
        conditions = [AuditEvent.tenant_id == current_user.tenant_id]
        
        # Apply filters
        if event_type:
            conditions.append(AuditEvent.event_type == event_type)
        if event_category:
            conditions.append(AuditEvent.event_category == event_category)
        if severity:
            conditions.append(AuditEvent.severity == severity)
        if entity_type:
            conditions.append(AuditEvent.entity_type == entity_type)
        if actor_id:
            conditions.append(AuditEvent.actor_id == actor_id)
        if start_date:
            conditions.append(AuditEvent.created_at >= start_date)
        if end_date:
            conditions.append(AuditEvent.created_at <= end_date)
        
        if conditions:
            query = query.where(and_(*conditions))
        
        # Count total records
        count_query = select(func.count()).select_from(AuditEvent)
        if conditions:
            count_query = count_query.where(and_(*conditions))
        
        total_result = await db.execute(count_query)
        total = total_result.scalar()
        
        # Apply pagination and ordering
        offset = (page - 1) * size
        query = query.offset(offset).limit(size).order_by(AuditEvent.created_at.desc())
        
        result = await db.execute(query)
        events = result.scalars().all()
        
        # Convert to response models
        event_responses = []
        for event in events:
            event_dict = {
                "id": event.id,
                "event_type": event.event_type,
                "event_category": event.event_category,
                "severity": event.severity,
                "entity_type": event.entity_type,
                "entity_id": event.entity_id,
                "actor_type": event.actor_type,
                "actor_id": event.actor_id,
                "actor_ip": event.actor_ip,
                "user_agent": event.user_agent,
                "event_data": event.event_data,
                "changes": event.changes,
                "request_id": event.request_id,
                "session_id": event.session_id,
                "created_at": event.created_at,
            }
            event_responses.append(AuditEventResponse(**event_dict))
        
        pages = (total + size - 1) // size
        
        return AuditEventListResponse(
            items=event_responses,
            total=total,
            page=page,
            size=size,
            pages=pages
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list audit events: {str(e)}"
        )


@router.get("/stats", response_model=AuditStatsResponse)
async def get_audit_stats(
    db: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(require_viewer),
    days: int = Query(30, ge=1, le=365, description="Number of days to include in stats")
):
    """
    Get audit statistics for the specified time period.
    """
    try:
        from datetime import timedelta
        
        # Calculate date range
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days)
        
        # Total events in period (with tenant filtering)
        tenant_filter = AuditEvent.tenant_id == current_user.tenant_id
        total_query = select(func.count()).select_from(AuditEvent).where(
            and_(tenant_filter, AuditEvent.created_at >= start_date)
        )
        total_events = (await db.execute(total_query)).scalar()
        
        # Events by category (with tenant filtering)
        category_query = select(
            AuditEvent.event_category,
            func.count()
        ).where(
            and_(tenant_filter, AuditEvent.created_at >= start_date)
        ).group_by(AuditEvent.event_category)
        
        category_result = await db.execute(category_query)
        events_by_category = {row[0] or "unknown": row[1] for row in category_result}
        
        # Events by severity (with tenant filtering)
        severity_query = select(
            AuditEvent.severity,
            func.count()
        ).where(
            and_(tenant_filter, AuditEvent.created_at >= start_date)
        ).group_by(AuditEvent.severity)
        
        severity_result = await db.execute(severity_query)
        events_by_severity = {row[0] or "unknown": row[1] for row in severity_result}
        
        # Events by type (top 10, with tenant filtering)
        type_query = select(
            AuditEvent.event_type,
            func.count()
        ).where(
            and_(tenant_filter, AuditEvent.created_at >= start_date)
        ).group_by(AuditEvent.event_type).order_by(func.count().desc()).limit(10)
        
        type_result = await db.execute(type_query)
        events_by_type = {row[0]: row[1] for row in type_result}
        
        # Events by day (last 30 days)
        from sqlalchemy import text
        daily_query = text("""
            SELECT DATE(created_at) as event_date, COUNT(*) as event_count
            FROM audit_events 
            WHERE created_at >= :start_date AND tenant_id = :tenant_id
            GROUP BY DATE(created_at)
            ORDER BY event_date DESC
            LIMIT 30
        """)
        
        daily_result = await db.execute(daily_query, {
            "start_date": start_date,
            "tenant_id": current_user.tenant_id
        })
        events_by_day = {row[0].isoformat(): row[1] for row in daily_result}
        
        # Top actors (top 10, with tenant filtering)
        actor_query = select(
            AuditEvent.actor_id,
            func.count()
        ).where(
            and_(
                tenant_filter,
                AuditEvent.created_at >= start_date,
                AuditEvent.actor_id.is_not(None)
            )
        ).group_by(AuditEvent.actor_id).order_by(func.count().desc()).limit(10)
        
        actor_result = await db.execute(actor_query)
        top_actors = {row[0]: row[1] for row in actor_result}
        
        return AuditStatsResponse(
            total_events=total_events,
            events_by_category=events_by_category,
            events_by_severity=events_by_severity,
            events_by_type=events_by_type,
            events_by_day=events_by_day,
            top_actors=top_actors
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get audit statistics: {str(e)}"
        )


@router.get("/{event_id}", response_model=AuditEventResponse)
async def get_audit_event(
    event_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(require_viewer)
):
    """
    Get a specific audit event by ID.
    """
    try:
        query = select(AuditEvent).where(AuditEvent.id == event_id)
        result = await db.execute(query)
        event = result.scalar_one_or_none()
        
        if not event:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Audit event not found: {event_id}"
            )
        
        event_dict = {
            "id": event.id,
            "event_type": event.event_type,
            "event_category": event.event_category,
            "severity": event.severity,
            "entity_type": event.entity_type,
            "entity_id": event.entity_id,
            "actor_type": event.actor_type,
            "actor_id": event.actor_id,
            "actor_ip": event.actor_ip,
            "user_agent": event.user_agent,
            "event_data": event.event_data,
            "changes": event.changes,
            "request_id": event.request_id,
            "session_id": event.session_id,
            "created_at": event.created_at,
        }
        
        return AuditEventResponse(**event_dict)
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get audit event: {str(e)}"
        )


@router.post("/search", response_model=AuditEventListResponse)
async def search_audit_events(
    search_request: AuditEventSearchRequest,
    db: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(require_viewer)
):
    """
    Search audit events with complex filtering.
    """
    try:
        # Build query
        query = select(AuditEvent)
        conditions = []
        
        # Apply filters from search request
        if search_request.event_type:
            conditions.append(AuditEvent.event_type == search_request.event_type)
        if search_request.event_category:
            conditions.append(AuditEvent.event_category == search_request.event_category)
        if search_request.severity:
            conditions.append(AuditEvent.severity == search_request.severity)
        if search_request.entity_type:
            conditions.append(AuditEvent.entity_type == search_request.entity_type)
        if search_request.entity_id:
            conditions.append(AuditEvent.entity_id == search_request.entity_id)
        if search_request.actor_id:
            conditions.append(AuditEvent.actor_id == search_request.actor_id)
        if search_request.actor_ip:
            conditions.append(AuditEvent.actor_ip == search_request.actor_ip)
        if search_request.start_date:
            conditions.append(AuditEvent.created_at >= search_request.start_date)
        if search_request.end_date:
            conditions.append(AuditEvent.created_at <= search_request.end_date)
        
        if conditions:
            query = query.where(and_(*conditions))
        
        # Count total records
        count_query = select(func.count()).select_from(AuditEvent)
        if conditions:
            count_query = count_query.where(and_(*conditions))
        
        total_result = await db.execute(count_query)
        total = total_result.scalar()
        
        # Apply sorting
        if search_request.sort_by == "created_at":
            sort_column = AuditEvent.created_at
        elif search_request.sort_by == "event_type":
            sort_column = AuditEvent.event_type
        elif search_request.sort_by == "severity":
            sort_column = AuditEvent.severity
        else:
            sort_column = AuditEvent.created_at
        
        if search_request.sort_desc:
            query = query.order_by(sort_column.desc())
        else:
            query = query.order_by(sort_column.asc())
        
        # Apply pagination
        offset = (search_request.page - 1) * search_request.size
        query = query.offset(offset).limit(search_request.size)
        
        result = await db.execute(query)
        events = result.scalars().all()
        
        # Convert to response models
        event_responses = []
        for event in events:
            event_dict = {
                "id": event.id,
                "event_type": event.event_type,
                "event_category": event.event_category,
                "severity": event.severity,
                "entity_type": event.entity_type,
                "entity_id": event.entity_id,
                "actor_type": event.actor_type,
                "actor_id": event.actor_id,
                "actor_ip": event.actor_ip,
                "user_agent": event.user_agent,
                "event_data": event.event_data,
                "changes": event.changes,
                "request_id": event.request_id,
                "session_id": event.session_id,
                "created_at": event.created_at,
            }
            event_responses.append(AuditEventResponse(**event_dict))
        
        pages = (total + search_request.size - 1) // search_request.size
        
        return AuditEventListResponse(
            items=event_responses,
            total=total,
            page=search_request.page,
            size=search_request.size,
            pages=pages
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to search audit events: {str(e)}"
        )