"""
Certificate Authority Node model.
"""

from typing import Optional, List
from datetime import datetime
from sqlalchemy import String, Text, DateTime, Boolean, Integer, ForeignKey, JSON, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID, ARRAY
import uuid

from app.core.database import Base


class CaNode(Base):
    """Certificate Authority database model."""
    
    __tablename__ = "ca_nodes"
    
    # Primary key
    id: Mapped[uuid.UUID] = mapped_column(UUID, primary_key=True, default=uuid.uuid4)
    
    # Multi-tenancy
    tenant_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    
    # Hierarchy
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
    type: Mapped[str] = mapped_column(String(50), nullable=False)  # 'root', 'intermediate'
    parent_ca_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID, ForeignKey("ca_nodes.id"))
    
    # Certificate information
    subject_dn: Mapped[str] = mapped_column(String(500), nullable=False)
    certificate_pem: Mapped[Optional[str]] = mapped_column(Text)
    certificate_chain_pem: Mapped[Optional[str]] = mapped_column(Text)
    serial_number: Mapped[Optional[str]] = mapped_column(String(128))
    not_before: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    not_after: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    
    # Key information
    key_type: Mapped[str] = mapped_column(String(50), nullable=False)  # 'rsa-2048', 'ecdsa-p256'
    key_storage: Mapped[str] = mapped_column(String(50), nullable=False)  # 'kms', 'hsm', 'file'
    kms_key_id: Mapped[Optional[str]] = mapped_column(String(512))
    kms_region: Mapped[Optional[str]] = mapped_column(String(50))
    
    # Policy and limits
    max_path_length: Mapped[Optional[int]] = mapped_column(Integer)
    allowed_key_types: Mapped[Optional[List[str]]] = mapped_column(ARRAY(String(100)))
    max_validity_days: Mapped[int] = mapped_column(Integer, default=365)
    
    # Distribution points
    crl_distribution_points: Mapped[Optional[List[str]]] = mapped_column(ARRAY(Text))
    ocsp_responder_url: Mapped[Optional[str]] = mapped_column(String(255))
    
    # Operational status
    status: Mapped[str] = mapped_column(String(50), default="active")  # active, suspended, revoked
    auto_renewal: Mapped[bool] = mapped_column(Boolean, default=False)
    renewal_threshold_days: Mapped[int] = mapped_column(Integer, default=30)
    
    # Metadata
    metadata_: Mapped[Optional[dict]] = mapped_column("metadata", JSON)
    
    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by: Mapped[Optional[str]] = mapped_column(String(255))
    
    # Relationships
    parent: Mapped[Optional["CaNode"]] = relationship("CaNode", remote_side=[id], back_populates="children")
    children: Mapped[List["CaNode"]] = relationship("CaNode", back_populates="parent")
    certificates: Mapped[List["Certificate"]] = relationship("Certificate", back_populates="ca")
    
    # Indexes
    __table_args__ = (
        Index("ix_ca_nodes_tenant_type", "tenant_id", "type"),
        Index("ix_ca_nodes_tenant_status", "tenant_id", "status"),
        Index("ix_ca_nodes_parent_id", "parent_ca_id"),
        Index("ix_ca_nodes_not_after", "not_after"),
        Index("ix_ca_nodes_tenant_id", "tenant_id"),
    )
    
    def __repr__(self) -> str:
        return f"<CaNode(id={self.id}, name='{self.name}', type='{self.type}')>"
    
    @property
    def is_root(self) -> bool:
        """Check if this is a root CA."""
        return self.type == "root"
    
    @property
    def is_intermediate(self) -> bool:
        """Check if this is an intermediate CA."""
        return self.type == "intermediate"
    
    @property
    def is_expired(self) -> bool:
        """Check if the CA certificate has expired."""
        if not self.not_after:
            return False
        return self.not_after < datetime.utcnow()
    
    @property
    def is_expiring_soon(self) -> bool:
        """Check if the CA certificate is expiring within the renewal threshold."""
        if not self.not_after:
            return False
        days_until_expiry = (self.not_after - datetime.utcnow()).days
        return days_until_expiry <= self.renewal_threshold_days
    
    def get_full_chain(self) -> List["CaNode"]:
        """Get the full certificate chain from root to this CA."""
        chain = [self]
        current = self.parent
        while current:
            chain.append(current)
            current = current.parent
        return list(reversed(chain))  # Root first
    
    def get_depth(self) -> int:
        """Get the depth of this CA in the hierarchy (root = 0)."""
        depth = 0
        current = self.parent
        while current:
            depth += 1
            current = current.parent
        return depth