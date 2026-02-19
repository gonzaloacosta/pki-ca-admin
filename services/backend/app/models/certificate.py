"""
Certificate model for issued certificates.
"""

from typing import Optional, List, Dict, Any
from datetime import datetime
from sqlalchemy import String, Text, DateTime, Boolean, ForeignKey, JSON, Index, LargeBinary
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID, ARRAY
import uuid

from app.core.database import Base


class Certificate(Base):
    """Certificate database model for issued certificates."""
    
    __tablename__ = "certificates"
    
    # Primary key
    id: Mapped[uuid.UUID] = mapped_column(UUID, primary_key=True, default=uuid.uuid4)
    
    # Multi-tenancy
    tenant_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    
    # CA relationship
    ca_id: Mapped[uuid.UUID] = mapped_column(UUID, ForeignKey("ca_nodes.id"), nullable=False)
    
    # Certificate identifiers
    serial_number: Mapped[str] = mapped_column(String(128), nullable=False)
    fingerprint_sha256: Mapped[Optional[str]] = mapped_column(String(64))
    
    # Subject information
    common_name: Mapped[str] = mapped_column(String(255), nullable=False)
    subject_dn: Mapped[Optional[str]] = mapped_column(String(500))
    subject_alternative_names: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON)
    
    # Certificate content
    certificate_pem: Mapped[Optional[str]] = mapped_column(Text)
    certificate_der: Mapped[Optional[bytes]] = mapped_column(LargeBinary)
    
    # Validity period
    not_before: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    not_after: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    
    # Certificate classification
    certificate_type: Mapped[str] = mapped_column(String(50), nullable=False)  # server, client, email, codesigning
    key_type: Mapped[Optional[str]] = mapped_column(String(50))  # rsa-2048, ecdsa-p256
    key_usage: Mapped[Optional[List[str]]] = mapped_column(ARRAY(String(100)))
    extended_key_usage: Mapped[Optional[List[str]]] = mapped_column(ARRAY(String(100)))
    
    # Issuance context
    provisioner_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID)  # Foreign key to provisioners when implemented
    template_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID)  # Foreign key to templates when implemented
    requester: Mapped[Optional[str]] = mapped_column(String(255))  # Who requested the certificate
    request_source: Mapped[Optional[str]] = mapped_column(String(100))  # api, acme, ui, import
    
    # Status and revocation
    status: Mapped[str] = mapped_column(String(50), default="active")  # active, expired, revoked, suspended
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    revocation_reason: Mapped[Optional[str]] = mapped_column(String(100))
    revoked_by: Mapped[Optional[str]] = mapped_column(String(255))
    
    # Extensions and custom data
    certificate_transparency_scts: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON)
    metadata_: Mapped[Optional[Dict[str, Any]]] = mapped_column("metadata", JSON)
    
    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    ca: Mapped["CaNode"] = relationship("CaNode", back_populates="certificates")
    
    # Indexes
    __table_args__ = (
        Index("ix_certificates_ca_serial", "ca_id", "serial_number", unique=True),
        Index("ix_certificates_fingerprint", "fingerprint_sha256"),
        Index("ix_certificates_tenant_not_after", "tenant_id", "not_after"),
        Index("ix_certificates_tenant_status", "tenant_id", "status"),
        Index("ix_certificates_tenant_common_name", "tenant_id", "common_name"),
        Index("ix_certificates_tenant_type", "tenant_id", "certificate_type"),
        Index("ix_certificates_tenant_id", "tenant_id"),
    )
    
    def __repr__(self) -> str:
        return f"<Certificate(id={self.id}, cn='{self.common_name}', serial='{self.serial_number}')>"
    
    @property
    def is_expired(self) -> bool:
        """Check if the certificate has expired."""
        return self.not_after < datetime.utcnow()
    
    @property
    def is_expiring_soon(self, days_threshold: int = 30) -> bool:
        """Check if the certificate is expiring within the specified threshold."""
        days_until_expiry = (self.not_after - datetime.utcnow()).days
        return days_until_expiry <= days_threshold
    
    @property
    def is_revoked(self) -> bool:
        """Check if the certificate is revoked."""
        return self.status == "revoked"
    
    @property
    def is_valid(self) -> bool:
        """Check if the certificate is currently valid (not expired, not revoked)."""
        now = datetime.utcnow()
        return (
            self.status == "active" and
            self.not_before <= now <= self.not_after
        )
    
    @property
    def validity_period_days(self) -> int:
        """Get the validity period in days."""
        return (self.not_after - self.not_before).days
    
    @property
    def days_until_expiry(self) -> int:
        """Get days until expiration (negative if expired)."""
        return (self.not_after - datetime.utcnow()).days
    
    def get_san_domains(self) -> List[str]:
        """Get list of DNS names from Subject Alternative Names."""
        if not self.subject_alternative_names:
            return []
        return self.subject_alternative_names.get("dns", [])
    
    def get_san_ips(self) -> List[str]:
        """Get list of IP addresses from Subject Alternative Names."""
        if not self.subject_alternative_names:
            return []
        return self.subject_alternative_names.get("ip", [])
    
    def get_san_emails(self) -> List[str]:
        """Get list of email addresses from Subject Alternative Names."""
        if not self.subject_alternative_names:
            return []
        return self.subject_alternative_names.get("email", [])