"""
Audit Event model for comprehensive audit logging.
"""

from typing import Optional, Dict, Any
from datetime import datetime
from sqlalchemy import String, Text, DateTime, JSON, Index, BigInteger
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID, INET
import uuid

from app.core.database import Base


class AuditEvent(Base):
    """Audit event model for tracking all system activities."""
    
    __tablename__ = "audit_events"
    
    # Primary key (BigInt for high volume)
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    
    # Multi-tenancy
    tenant_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    
    # Event classification
    event_type: Mapped[str] = mapped_column(String(100), nullable=False)  # ca.created, cert.issued, cert.revoked
    event_category: Mapped[Optional[str]] = mapped_column(String(50))  # security, operational, administrative
    severity: Mapped[Optional[str]] = mapped_column(String(20))  # info, warning, error, critical
    
    # Entity context
    entity_type: Mapped[str] = mapped_column(String(50), nullable=False)  # ca, certificate, user, provisioner
    entity_id: Mapped[uuid.UUID] = mapped_column(UUID, nullable=False)
    
    # Actor context
    actor_type: Mapped[Optional[str]] = mapped_column(String(50))  # user, system, provisioner
    actor_id: Mapped[Optional[str]] = mapped_column(String(255))
    actor_ip: Mapped[Optional[str]] = mapped_column(INET)
    user_agent: Mapped[Optional[str]] = mapped_column(Text)
    
    # Event payload
    event_data: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False)
    changes: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON)  # Before/after for updates
    
    # Request context
    request_id: Mapped[Optional[str]] = mapped_column(String(255))  # For distributed tracing
    session_id: Mapped[Optional[str]] = mapped_column(String(255))
    
    # Timestamp
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    
    # Indexes for performance
    __table_args__ = (
        Index("ix_audit_events_tenant_created_at", "tenant_id", "created_at"),
        Index("ix_audit_events_tenant_event_type", "tenant_id", "event_type"),
        Index("ix_audit_events_tenant_entity", "tenant_id", "entity_type", "entity_id"),
        Index("ix_audit_events_tenant_actor", "tenant_id", "actor_type", "actor_id"),
        Index("ix_audit_events_tenant_severity", "tenant_id", "severity"),
        Index("ix_audit_events_tenant_id", "tenant_id"),
    )
    
    def __repr__(self) -> str:
        return f"<AuditEvent(id={self.id}, type='{self.event_type}', entity='{self.entity_type}:{self.entity_id}')>"
    
    @classmethod
    def create_ca_event(
        cls,
        event_type: str,
        tenant_id: str,
        ca_id: uuid.UUID,
        actor_id: Optional[str] = None,
        actor_ip: Optional[str] = None,
        event_data: Optional[Dict[str, Any]] = None,
        changes: Optional[Dict[str, Any]] = None,
        **kwargs
    ) -> "AuditEvent":
        """
        Create a CA-related audit event.
        
        Args:
            event_type: Type of event (e.g., 'ca.created', 'ca.revoked')
            tenant_id: Tenant identifier (Keycloak realm)
            ca_id: CA UUID
            actor_id: User or system that performed the action
            actor_ip: IP address of the actor
            event_data: Additional event data
            changes: Before/after changes
            **kwargs: Additional fields
            
        Returns:
            AuditEvent: New audit event instance
        """
        return cls(
            tenant_id=tenant_id,
            event_type=event_type,
            event_category="operational",
            severity="info",
            entity_type="ca",
            entity_id=ca_id,
            actor_type="user" if actor_id else "system",
            actor_id=actor_id,
            actor_ip=actor_ip,
            event_data=event_data or {},
            changes=changes,
            **kwargs
        )
    
    @classmethod
    def create_certificate_event(
        cls,
        event_type: str,
        tenant_id: str,
        certificate_id: uuid.UUID,
        actor_id: Optional[str] = None,
        actor_ip: Optional[str] = None,
        event_data: Optional[Dict[str, Any]] = None,
        changes: Optional[Dict[str, Any]] = None,
        **kwargs
    ) -> "AuditEvent":
        """
        Create a certificate-related audit event.
        
        Args:
            event_type: Type of event (e.g., 'cert.issued', 'cert.revoked')
            tenant_id: Tenant identifier (Keycloak realm)
            certificate_id: Certificate UUID
            actor_id: User or system that performed the action
            actor_ip: IP address of the actor
            event_data: Additional event data
            changes: Before/after changes
            **kwargs: Additional fields
            
        Returns:
            AuditEvent: New audit event instance
        """
        severity = "info"
        if event_type in ["cert.revoked", "cert.suspended"]:
            severity = "warning"
        elif "error" in event_type or "failed" in event_type:
            severity = "error"
        
        return cls(
            tenant_id=tenant_id,
            event_type=event_type,
            event_category="operational",
            severity=severity,
            entity_type="certificate",
            entity_id=certificate_id,
            actor_type="user" if actor_id else "system",
            actor_id=actor_id,
            actor_ip=actor_ip,
            event_data=event_data or {},
            changes=changes,
            **kwargs
        )
    
    @classmethod
    def create_security_event(
        cls,
        event_type: str,
        tenant_id: str,
        entity_id: uuid.UUID,
        actor_id: Optional[str] = None,
        actor_ip: Optional[str] = None,
        event_data: Optional[Dict[str, Any]] = None,
        severity: str = "warning",
        **kwargs
    ) -> "AuditEvent":
        """
        Create a security-related audit event.
        
        Args:
            event_type: Type of event (e.g., 'auth.failed', 'access.denied')
            tenant_id: Tenant identifier (Keycloak realm)
            entity_id: Related entity UUID
            actor_id: User or system that performed the action
            actor_ip: IP address of the actor
            event_data: Additional event data
            severity: Event severity level
            **kwargs: Additional fields
            
        Returns:
            AuditEvent: New audit event instance
        """
        return cls(
            tenant_id=tenant_id,
            event_type=event_type,
            event_category="security",
            severity=severity,
            entity_type="security",
            entity_id=entity_id,
            actor_type="user" if actor_id else "system",
            actor_id=actor_id,
            actor_ip=actor_ip,
            event_data=event_data or {},
            **kwargs
        )