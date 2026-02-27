"""
Pydantic schemas for Audit operations.
"""

from typing import List, Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field
import uuid


class AuditEventBase(BaseModel):
    """Base audit event schema."""
    event_type: str = Field(..., min_length=1, max_length=100, description="Event type")
    event_category: Optional[str] = Field(None, max_length=50, description="Event category")
    severity: Optional[str] = Field(
        None,
        pattern="^(info|warning|error|critical)$",
        description="Event severity"
    )
    entity_type: str = Field(..., max_length=50, description="Entity type")
    entity_id: uuid.UUID = Field(..., description="Entity ID")


class AuditEventResponse(AuditEventBase):
    """Schema for audit event response."""
    id: int
    
    # Actor information
    actor_type: Optional[str]
    actor_id: Optional[str] 
    actor_ip: Optional[str]
    user_agent: Optional[str]
    
    # Event data
    event_data: Dict[str, Any]
    changes: Optional[Dict[str, Any]]
    
    # Request context
    request_id: Optional[str]
    session_id: Optional[str]
    
    # Timestamp
    created_at: datetime
    
    class Config:
        from_attributes = True


class AuditEventListResponse(BaseModel):
    """Response for listing audit events."""
    items: List[AuditEventResponse]
    total: int
    page: int = Field(default=1, ge=1)
    size: int = Field(default=20, ge=1, le=100) 
    pages: int


class AuditEventSearchRequest(BaseModel):
    """Schema for audit event search request."""
    event_type: Optional[str] = None
    event_category: Optional[str] = None
    severity: Optional[str] = None
    entity_type: Optional[str] = None
    entity_id: Optional[uuid.UUID] = None
    actor_id: Optional[str] = None
    actor_ip: Optional[str] = None
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    page: int = Field(default=1, ge=1)
    size: int = Field(default=20, ge=1, le=100)
    sort_by: str = Field(default="created_at", pattern="^(created_at|event_type|severity)$")
    sort_desc: bool = Field(default=True)


class AuditStatsResponse(BaseModel):
    """Audit statistics response."""
    total_events: int
    events_by_category: Dict[str, int] = Field(default_factory=dict)
    events_by_severity: Dict[str, int] = Field(default_factory=dict)
    events_by_type: Dict[str, int] = Field(default_factory=dict)
    events_by_day: Dict[str, int] = Field(default_factory=dict)
    top_actors: Dict[str, int] = Field(default_factory=dict)