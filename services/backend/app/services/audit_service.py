"""
Audit service for logging all system events
"""

from typing import Optional, Dict, Any, List
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, and_, or_
from datetime import datetime
import uuid
import structlog

from app.models.database import AuditEvent
from app.models.schemas import AuditEventResponse

logger = structlog.get_logger()

async def create_audit_event(
    db: AsyncSession,
    organization_id: uuid.UUID,
    event_type: str,
    entity_type: str,
    entity_id: uuid.UUID,
    event_data: Dict[str, Any],
    event_category: Optional[str] = None,
    severity: Optional[str] = "info",
    actor_type: Optional[str] = None,
    actor_id: Optional[str] = None,
    actor_ip: Optional[str] = None,
    user_agent: Optional[str] = None,
    changes: Optional[Dict[str, Any]] = None,
    request_id: Optional[str] = None,
    session_id: Optional[str] = None,
) -> AuditEvent:
    """
    Create an audit event record
    
    Args:
        db: Database session
        organization_id: Organization UUID
        event_type: Type of event (e.g., 'ca.created', 'cert.issued')
        entity_type: Type of entity (e.g., 'ca', 'certificate', 'user')
        entity_id: UUID of the entity
        event_data: Event payload data
        event_category: Category (security, operational, administrative)
        severity: Event severity (info, warning, error, critical)
        actor_type: Type of actor (user, system, provisioner)
        actor_id: ID of the actor
        actor_ip: IP address of the actor
        user_agent: User agent string
        changes: Before/after data for update events
        request_id: Request ID for tracing
        session_id: Session ID
        
    Returns:
        Created AuditEvent instance
    """
    
    audit_event = AuditEvent(
        organization_id=organization_id,
        event_type=event_type,
        event_category=event_category,
        severity=severity,
        entity_type=entity_type,
        entity_id=entity_id,
        actor_type=actor_type,
        actor_id=actor_id,
        actor_ip=actor_ip,
        user_agent=user_agent,
        event_data=event_data,
        changes=changes,
        request_id=request_id,
        session_id=session_id,
    )
    
    db.add(audit_event)
    
    # Log structured event
    logger.info(
        "Audit event created",
        event_type=event_type,
        entity_type=entity_type,
        entity_id=str(entity_id),
        actor_id=actor_id,
        severity=severity,
        request_id=request_id,
    )
    
    return audit_event

async def get_audit_events(
    db: AsyncSession,
    organization_id: uuid.UUID,
    event_types: Optional[List[str]] = None,
    entity_types: Optional[List[str]] = None,
    entity_ids: Optional[List[uuid.UUID]] = None,
    actor_ids: Optional[List[str]] = None,
    severities: Optional[List[str]] = None,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    limit: int = 100,
    offset: int = 0,
) -> List[AuditEvent]:
    """
    Query audit events with filters
    
    Args:
        db: Database session
        organization_id: Organization to query
        event_types: Filter by event types
        entity_types: Filter by entity types
        entity_ids: Filter by specific entity IDs
        actor_ids: Filter by actor IDs
        severities: Filter by severities
        start_date: Filter events after this date
        end_date: Filter events before this date
        limit: Maximum number of results
        offset: Number of results to skip
        
    Returns:
        List of audit events
    """
    
    query = select(AuditEvent).where(
        AuditEvent.organization_id == organization_id
    )
    
    # Apply filters
    if event_types:
        query = query.where(AuditEvent.event_type.in_(event_types))
        
    if entity_types:
        query = query.where(AuditEvent.entity_type.in_(entity_types))
        
    if entity_ids:
        query = query.where(AuditEvent.entity_id.in_(entity_ids))
        
    if actor_ids:
        query = query.where(AuditEvent.actor_id.in_(actor_ids))
        
    if severities:
        query = query.where(AuditEvent.severity.in_(severities))
        
    if start_date:
        query = query.where(AuditEvent.created_at >= start_date)
        
    if end_date:
        query = query.where(AuditEvent.created_at <= end_date)
    
    # Order by most recent first
    query = query.order_by(desc(AuditEvent.created_at))
    
    # Apply pagination
    query = query.limit(limit).offset(offset)
    
    result = await db.execute(query)
    return result.scalars().all()

async def get_audit_events_for_entity(
    db: AsyncSession,
    organization_id: uuid.UUID,
    entity_type: str,
    entity_id: uuid.UUID,
    limit: int = 50,
    offset: int = 0,
) -> List[AuditEvent]:
    """
    Get audit events for a specific entity
    
    Args:
        db: Database session
        organization_id: Organization UUID
        entity_type: Type of entity
        entity_id: Entity UUID
        limit: Maximum number of results
        offset: Number of results to skip
        
    Returns:
        List of audit events for the entity
    """
    
    query = select(AuditEvent).where(
        and_(
            AuditEvent.organization_id == organization_id,
            AuditEvent.entity_type == entity_type,
            AuditEvent.entity_id == entity_id
        )
    ).order_by(desc(AuditEvent.created_at)).limit(limit).offset(offset)
    
    result = await db.execute(query)
    return result.scalars().all()

async def count_audit_events(
    db: AsyncSession,
    organization_id: uuid.UUID,
    event_types: Optional[List[str]] = None,
    entity_types: Optional[List[str]] = None,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
) -> int:
    """
    Count audit events matching criteria
    
    Args:
        db: Database session
        organization_id: Organization UUID
        event_types: Filter by event types
        entity_types: Filter by entity types
        start_date: Filter events after this date
        end_date: Filter events before this date
        
    Returns:
        Count of matching events
    """
    
    from sqlalchemy import func as sql_func
    
    query = select(sql_func.count(AuditEvent.id)).where(
        AuditEvent.organization_id == organization_id
    )
    
    if event_types:
        query = query.where(AuditEvent.event_type.in_(event_types))
        
    if entity_types:
        query = query.where(AuditEvent.entity_type.in_(entity_types))
        
    if start_date:
        query = query.where(AuditEvent.created_at >= start_date)
        
    if end_date:
        query = query.where(AuditEvent.created_at <= end_date)
    
    result = await db.execute(query)
    return result.scalar()

# Predefined event types and their metadata
AUDIT_EVENT_TYPES = {
    # Authentication events
    "auth.login": {
        "category": "security",
        "severity": "info",
        "description": "User successful login"
    },
    "auth.login.failed": {
        "category": "security", 
        "severity": "warning",
        "description": "User login failed"
    },
    "auth.logout": {
        "category": "security",
        "severity": "info", 
        "description": "User logout"
    },
    "auth.account.locked": {
        "category": "security",
        "severity": "warning",
        "description": "User account locked due to failed attempts"
    },
    
    # Certificate Authority events
    "ca.created": {
        "category": "operational",
        "severity": "info",
        "description": "Certificate Authority created"
    },
    "ca.updated": {
        "category": "operational",
        "severity": "info", 
        "description": "Certificate Authority updated"
    },
    "ca.revoked": {
        "category": "security",
        "severity": "critical",
        "description": "Certificate Authority revoked"
    },
    "ca.key.rotated": {
        "category": "security",
        "severity": "warning",
        "description": "Certificate Authority key rotated"
    },
    
    # Certificate events
    "cert.issued": {
        "category": "operational",
        "severity": "info",
        "description": "Certificate issued"
    },
    "cert.renewed": {
        "category": "operational",
        "severity": "info",
        "description": "Certificate renewed"
    },
    "cert.revoked": {
        "category": "security",
        "severity": "warning", 
        "description": "Certificate revoked"
    },
    "cert.expired": {
        "category": "operational",
        "severity": "info",
        "description": "Certificate expired"
    },
    
    # Administrative events
    "user.created": {
        "category": "administrative",
        "severity": "info",
        "description": "User created"
    },
    "user.updated": {
        "category": "administrative",
        "severity": "info",
        "description": "User updated"
    },
    "user.disabled": {
        "category": "security",
        "severity": "warning",
        "description": "User disabled"
    },
    "org.settings.updated": {
        "category": "administrative",
        "severity": "info",
        "description": "Organization settings updated"
    },
}

async def get_event_type_metadata(event_type: str) -> Dict[str, Any]:
    """Get metadata for an event type"""
    return AUDIT_EVENT_TYPES.get(event_type, {
        "category": "operational",
        "severity": "info",
        "description": f"Unknown event type: {event_type}"
    })