"""
SQLAlchemy database models for PKI-CA-ADMIN

Based on the comprehensive schema design for multi-tier PKI hierarchies.
"""

from sqlalchemy import (
    Column, String, Text, Boolean, Integer, DateTime, BigInteger,
    ForeignKey, UniqueConstraint, CheckConstraint, Index, ARRAY
)
from sqlalchemy.dialects.postgresql import UUID, JSONB, INET, BYTEA
from sqlalchemy.orm import relationship, declarative_base
from sqlalchemy.sql import func
import uuid
from datetime import datetime
from typing import Optional, List, Dict, Any

from app.core.database import Base

# Organizations table - multi-tenancy
class Organization(Base):
    __tablename__ = "organizations"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    domain = Column(String(255), unique=True)
    
    # Billing and limits
    plan_type = Column(String(50), default="free")  # free, pro, enterprise
    max_cas = Column(Integer, default=5)
    max_certificates = Column(Integer, default=1000)
    
    # Security settings
    mfa_required = Column(Boolean, default=False)
    ip_whitelist = Column(ARRAY(INET))
    
    # Notification settings
    alert_email = Column(String(255))
    webhook_endpoints = Column(JSONB)
    
    settings = Column(JSONB)  # Flexible configuration
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    
    # Relationships
    certificate_authorities = relationship("CertificateAuthority", back_populates="organization")
    certificates = relationship("Certificate", back_populates="organization")
    users = relationship("User", back_populates="organization")
    audit_events = relationship("AuditEvent", back_populates="organization")

class CertificateAuthority(Base):
    __tablename__ = "certificate_authorities"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False)
    name = Column(String(255), nullable=False)
    description = Column(Text)
    type = Column(String(50), nullable=False)  # 'root', 'intermediate'
    parent_ca_id = Column(UUID(as_uuid=True), ForeignKey("certificate_authorities.id"))
    
    # Certificate information
    subject_dn = Column(String(500), nullable=False)
    certificate_pem = Column(Text)
    certificate_chain_pem = Column(Text)  # Full chain
    serial_number = Column(String(128))
    not_before = Column(DateTime(timezone=True))
    not_after = Column(DateTime(timezone=True))
    
    # Key information
    key_type = Column(String(50), nullable=False)  # 'rsa-2048', 'ecdsa-p256', 'ed25519'
    key_storage = Column(String(50), nullable=False)  # 'kms', 'hsm', 'file'
    kms_key_id = Column(String(512))  # KMS key ARN/identifier
    kms_region = Column(String(50))  # AWS region for key
    
    # Policy and limits
    max_path_length = Column(Integer)  # CA path length constraint
    allowed_key_types = Column(ARRAY(String(100)))  # Restrict key types
    max_validity_days = Column(Integer, default=365)
    crl_distribution_points = Column(ARRAY(Text))
    ocsp_responder_url = Column(String(255))
    
    # Operational
    status = Column(String(50), default="active")  # active, suspended, revoked
    auto_renewal = Column(Boolean, default=False)
    renewal_threshold_days = Column(Integer, default=30)
    
    metadata = Column(JSONB)  # Custom attributes
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    created_by = Column(String(255))
    
    # Constraints
    __table_args__ = (
        CheckConstraint("type IN ('root', 'intermediate')", name='valid_ca_type'),
        CheckConstraint(
            "(type = 'root' AND parent_ca_id IS NULL) OR (type = 'intermediate' AND parent_ca_id IS NOT NULL)",
            name='root_has_no_parent'
        ),
        Index('idx_ca_parent', 'parent_ca_id'),
        Index('idx_ca_type', 'type'),
        Index('idx_ca_status', 'status'),
        Index('idx_ca_org', 'organization_id'),
    )
    
    # Relationships
    organization = relationship("Organization", back_populates="certificate_authorities")
    parent_ca = relationship("CertificateAuthority", remote_side=[id])
    certificates = relationship("Certificate", back_populates="certificate_authority")
    key_rotations = relationship("CAKeyRotation", back_populates="certificate_authority")

class Certificate(Base):
    __tablename__ = "certificates"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    ca_id = Column(UUID(as_uuid=True), ForeignKey("certificate_authorities.id"), nullable=False)
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False)
    
    # Certificate identifiers
    serial_number = Column(String(128), nullable=False)
    fingerprint_sha256 = Column(String(64))  # For fast lookups
    
    # Subject information
    common_name = Column(String(255), nullable=False)
    subject_dn = Column(String(500))
    subject_alternative_names = Column(JSONB)  # {dns: [...], ip: [...], email: [...]}
    
    # Certificate content
    certificate_pem = Column(Text)
    certificate_der = Column(BYTEA)  # For OCSP/CRL
    
    # Validity
    not_before = Column(DateTime(timezone=True), nullable=False)
    not_after = Column(DateTime(timezone=True), nullable=False)
    
    # Classification
    certificate_type = Column(String(50), nullable=False)  # server, client, email, codesigning
    key_type = Column(String(50))  # rsa-2048, ecdsa-p256
    key_usage = Column(ARRAY(String(100)))
    extended_key_usage = Column(ARRAY(String(100)))
    
    # Issuance context
    provisioner_id = Column(UUID(as_uuid=True), ForeignKey("provisioners.id"))
    template_id = Column(UUID(as_uuid=True), ForeignKey("certificate_templates.id"))
    requester = Column(String(255))  # Who requested the certificate
    request_source = Column(String(100))  # api, acme, ui, import
    
    # Status and revocation
    status = Column(String(50), default="active")  # active, expired, revoked, suspended
    revoked_at = Column(DateTime(timezone=True))
    revocation_reason = Column(String(100))  # RFC5280 revocation reasons
    revoked_by = Column(String(255))
    
    # Extensions and custom data
    certificate_transparency_scts = Column(JSONB)  # Signed Certificate Timestamps
    metadata = Column(JSONB)  # Custom attributes, tags
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    
    # Constraints
    __table_args__ = (
        UniqueConstraint('ca_id', 'serial_number', name='uq_cert_serial_ca'),
        Index('idx_cert_fingerprint', 'fingerprint_sha256'),
        Index('idx_cert_expiry', 'not_after'),
        Index('idx_cert_org_status', 'organization_id', 'status'),
        Index('idx_cert_ca', 'ca_id'),
        Index('idx_cert_cn', 'common_name'),
    )
    
    # Relationships
    certificate_authority = relationship("CertificateAuthority", back_populates="certificates")
    organization = relationship("Organization", back_populates="certificates")
    provisioner = relationship("Provisioner", back_populates="certificates")
    template = relationship("CertificateTemplate", back_populates="certificates")
    lifecycle_events = relationship("CertificateLifecycleEvent", back_populates="certificate")

class Provisioner(Base):
    __tablename__ = "provisioners"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False)
    name = Column(String(255), nullable=False)
    type = Column(String(50), nullable=False)  # 'JWK', 'OIDC', 'ACME', 'X5C', 'K8sSA'
    
    # Type-specific configuration
    configuration = Column(JSONB, nullable=False)
    
    # Default claims/constraints
    claims = Column(JSONB)  # TTL limits, renewal settings
    
    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    created_by = Column(String(255))
    
    # Constraints
    __table_args__ = (
        UniqueConstraint('organization_id', 'name', name='uq_provisioner_org_name'),
        CheckConstraint(
            "type IN ('JWK', 'OIDC', 'ACME', 'X5C', 'K8sSA', 'SCEP', 'SSHPOP')",
            name='valid_provisioner_type'
        ),
    )
    
    # Relationships
    certificates = relationship("Certificate", back_populates="provisioner")

class CertificateTemplate(Base):
    __tablename__ = "certificate_templates"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False)
    name = Column(String(255), nullable=False)
    description = Column(Text)
    
    # Template content (Jinja2)
    template_data = Column(JSONB, nullable=False)
    
    # Policy constraints
    allowed_key_types = Column(ARRAY(String(100)))
    max_validity_days = Column(Integer)
    required_sans = Column(Boolean, default=False)
    allowed_san_patterns = Column(ARRAY(String(255)))  # Regex patterns
    
    # Certificate extensions
    key_usage = Column(ARRAY(String(100)))  # digitalSignature, keyEncipherment, etc.
    extended_key_usage = Column(ARRAY(String(100)))  # serverAuth, clientAuth, etc.
    
    enabled = Column(Boolean, default=True)
    version = Column(Integer, default=1)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    created_by = Column(String(255))
    
    __table_args__ = (
        UniqueConstraint('organization_id', 'name', name='uq_template_org_name'),
    )
    
    # Relationships
    certificates = relationship("Certificate", back_populates="template")

class AuditEvent(Base):
    __tablename__ = "audit_events"
    
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False)
    
    # Event classification
    event_type = Column(String(100), nullable=False)  # ca.created, cert.issued, cert.revoked
    event_category = Column(String(50))  # security, operational, administrative
    severity = Column(String(20))  # info, warning, error, critical
    
    # Entity context
    entity_type = Column(String(50), nullable=False)  # ca, certificate, user, provisioner
    entity_id = Column(UUID(as_uuid=True), nullable=False)
    
    # Actor context
    actor_type = Column(String(50))  # user, system, provisioner
    actor_id = Column(String(255))
    actor_ip = Column(INET)
    user_agent = Column(Text)
    
    # Event payload
    event_data = Column(JSONB, nullable=False)
    changes = Column(JSONB)  # Before/after for updates
    
    # Request context
    request_id = Column(String(255))  # For tracing
    session_id = Column(String(255))
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    __table_args__ = (
        Index('idx_audit_org_time', 'organization_id', 'created_at'),
        Index('idx_audit_type', 'event_type'),
        Index('idx_audit_entity', 'entity_type', 'entity_id'),
        Index('idx_audit_actor', 'actor_id'),
    )
    
    # Relationships
    organization = relationship("Organization", back_populates="audit_events")

class User(Base):
    __tablename__ = "users"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = Column(String(255), unique=True, nullable=False)
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False)
    
    # Authentication
    hashed_password = Column(String(128))
    enabled = Column(Boolean, default=True)
    last_login = Column(DateTime(timezone=True))
    failed_login_attempts = Column(Integer, default=0)
    locked_until = Column(DateTime(timezone=True))
    
    # Profile
    full_name = Column(String(255))
    
    # Settings
    preferences = Column(JSONB)
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    
    # Relationships
    organization = relationship("Organization", back_populates="users")

class CAKeyRotation(Base):
    __tablename__ = "ca_key_rotations"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    ca_id = Column(UUID(as_uuid=True), ForeignKey("certificate_authorities.id"), nullable=False)
    old_key_id = Column(String(512))  # Previous KMS key
    new_key_id = Column(String(512))  # New KMS key
    rotation_reason = Column(String(255))
    initiated_by = Column(String(255))
    completed_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    certificate_authority = relationship("CertificateAuthority", back_populates="key_rotations")

class CertificateLifecycleEvent(Base):
    __tablename__ = "certificate_lifecycle_events"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    certificate_id = Column(UUID(as_uuid=True), ForeignKey("certificates.id", ondelete="CASCADE"), nullable=False)
    event_type = Column(String(50), nullable=False)  # issued, renewed, revoked, expired
    event_data = Column(JSONB)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    certificate = relationship("Certificate", back_populates="lifecycle_events")