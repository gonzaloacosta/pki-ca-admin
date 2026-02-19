"""
Pydantic schemas for Certificate operations.
"""

from typing import Optional, List, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field, validator, EmailStr
import uuid


class SubjectAlternativeNames(BaseModel):
    """Subject Alternative Names configuration."""
    dns: Optional[List[str]] = Field(default_factory=list, description="DNS names")
    ip: Optional[List[str]] = Field(default_factory=list, description="IP addresses") 
    email: Optional[List[EmailStr]] = Field(default_factory=list, description="Email addresses")
    uri: Optional[List[str]] = Field(default_factory=list, description="URI values")


class CertificateBase(BaseModel):
    """Base certificate schema."""
    common_name: str = Field(..., min_length=1, max_length=255, description="Common Name")
    certificate_type: str = Field(
        ...,
        pattern="^(server|client|email|codesigning|timestamping)$",
        description="Certificate type"
    )


class CertificateIssueRequest(CertificateBase):
    """Schema for certificate issuance request."""
    subject_alternative_names: Optional[SubjectAlternativeNames] = Field(
        None, 
        description="Subject Alternative Names"
    )
    key_type: str = Field(
        default="ecdsa-p256",
        pattern="^(rsa-2048|rsa-3072|rsa-4096|ecdsa-p256|ecdsa-p384|ed25519)$",
        description="Private key type"
    )
    validity_days: int = Field(
        default=365, 
        ge=1, 
        le=3650, 
        description="Certificate validity in days"
    )
    
    # Extended attributes
    organization: Optional[str] = Field(None, max_length=255, description="Organization")
    organizational_unit: Optional[str] = Field(None, max_length=255, description="Organizational Unit")
    country: Optional[str] = Field(None, min_length=2, max_length=2, description="Country code")
    state: Optional[str] = Field(None, max_length=255, description="State or Province")
    locality: Optional[str] = Field(None, max_length=255, description="Locality")
    email: Optional[EmailStr] = Field(None, description="Email address")
    
    # Key usage extensions
    key_usage: Optional[List[str]] = Field(
        default_factory=lambda: ["digital_signature", "key_encipherment"],
        description="Key usage extensions"
    )
    extended_key_usage: Optional[List[str]] = Field(
        default_factory=list,
        description="Extended key usage extensions"
    )
    
    # Custom metadata
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Custom metadata")
    
    @validator('key_usage')
    def validate_key_usage(cls, v):
        valid_usages = [
            'digital_signature', 'content_commitment', 'key_encipherment', 
            'data_encipherment', 'key_agreement', 'key_cert_sign', 
            'crl_sign', 'encipher_only', 'decipher_only'
        ]
        if v:
            for usage in v:
                if usage not in valid_usages:
                    raise ValueError(f'Invalid key usage: {usage}')
        return v
    
    @validator('extended_key_usage')
    def validate_extended_key_usage(cls, v):
        valid_ext_usages = [
            'server_auth', 'client_auth', 'code_signing', 'email_protection',
            'time_stamping', 'ocsp_signing', 'any_extended_key_usage'
        ]
        if v:
            for usage in v:
                if usage not in valid_ext_usages:
                    raise ValueError(f'Invalid extended key usage: {usage}')
        return v


class CertificateSignRequest(BaseModel):
    """Schema for signing a Certificate Signing Request (CSR)."""
    csr_pem: str = Field(..., description="PEM-encoded Certificate Signing Request")
    certificate_type: str = Field(
        ...,
        pattern="^(server|client|email|codesigning|timestamping)$",
        description="Certificate type"
    )
    validity_days: int = Field(
        default=365,
        ge=1,
        le=3650,
        description="Certificate validity in days"
    )
    
    # Optional overrides for CSR attributes
    subject_alternative_names: Optional[SubjectAlternativeNames] = None
    key_usage: Optional[List[str]] = None
    extended_key_usage: Optional[List[str]] = None
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict)


class CertificateCreate(CertificateBase):
    """Schema for creating certificate records (for imports)."""
    ca_id: uuid.UUID
    serial_number: str
    subject_dn: Optional[str]
    subject_alternative_names: Optional[SubjectAlternativeNames]
    certificate_pem: str
    not_before: datetime
    not_after: datetime
    key_type: Optional[str]
    key_usage: Optional[List[str]]
    extended_key_usage: Optional[List[str]]
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict)


class CertificateResponse(CertificateBase):
    """Schema for certificate response."""
    id: uuid.UUID
    ca_id: uuid.UUID
    
    # Identifiers
    serial_number: str
    fingerprint_sha256: Optional[str]
    
    # Subject info
    subject_dn: Optional[str]
    subject_alternative_names: Optional[Dict[str, Any]]
    
    # Certificate data
    certificate_pem: Optional[str]
    not_before: datetime
    not_after: datetime
    
    # Certificate properties
    key_type: Optional[str]
    key_usage: Optional[List[str]]
    extended_key_usage: Optional[List[str]]
    
    # Issuance context
    provisioner_id: Optional[uuid.UUID]
    template_id: Optional[uuid.UUID]
    requester: Optional[str]
    request_source: Optional[str]
    
    # Status
    status: str
    revoked_at: Optional[datetime]
    revocation_reason: Optional[str]
    revoked_by: Optional[str]
    
    # Extensions
    certificate_transparency_scts: Optional[Dict[str, Any]]
    metadata_: Optional[Dict[str, Any]] = Field(None, alias="metadata")
    
    # Timestamps
    created_at: datetime
    updated_at: datetime
    
    # Computed properties
    is_expired: bool
    is_revoked: bool
    is_valid: bool
    validity_period_days: int
    days_until_expiry: int
    
    class Config:
        from_attributes = True
        populate_by_name = True


class CertificateListResponse(BaseModel):
    """Response for listing certificates."""
    items: List[CertificateResponse]
    total: int
    page: int = Field(default=1, ge=1)
    size: int = Field(default=20, ge=1, le=100)
    pages: int


class CertificateRevokeRequest(BaseModel):
    """Schema for certificate revocation request."""
    reason: str = Field(
        default="unspecified",
        pattern="^(unspecified|key_compromise|ca_compromise|affiliation_changed|superseded|cessation_of_operation|certificate_hold|remove_from_crl|privilege_withdrawn|aa_compromise)$",
        description="Revocation reason"
    )
    revocation_date: Optional[datetime] = Field(None, description="Revocation date (defaults to now)")


class CertificateSearchRequest(BaseModel):
    """Schema for certificate search request."""
    common_name: Optional[str] = None
    serial_number: Optional[str] = None
    certificate_type: Optional[str] = None
    status: Optional[str] = None
    ca_id: Optional[uuid.UUID] = None
    expires_before: Optional[datetime] = None
    expires_after: Optional[datetime] = None
    created_before: Optional[datetime] = None
    created_after: Optional[datetime] = None
    page: int = Field(default=1, ge=1)
    size: int = Field(default=20, ge=1, le=100)
    sort_by: str = Field(default="created_at", pattern="^(created_at|not_after|common_name|status)$")
    sort_desc: bool = Field(default=True)


class CertificateStatsResponse(BaseModel):
    """Certificate statistics response."""
    total_certificates: int
    active_certificates: int
    expired_certificates: int
    revoked_certificates: int
    expiring_within_30_days: int
    expiring_within_90_days: int
    by_type: Dict[str, int] = Field(default_factory=dict)
    by_ca: Dict[str, int] = Field(default_factory=dict)
    by_month: Dict[str, int] = Field(default_factory=dict)