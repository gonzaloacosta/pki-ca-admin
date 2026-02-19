"""
Pydantic schemas for API request/response models
"""

from pydantic import BaseModel, Field, validator
from typing import Optional, List, Dict, Any, Union
from datetime import datetime
from enum import Enum
import uuid
from ipaddress import IPv4Address, IPv6Address


class CAType(str, Enum):
    ROOT = "root"
    INTERMEDIATE = "intermediate"


class CAStatus(str, Enum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    REVOKED = "revoked"
    PENDING = "pending"


class CertificateType(str, Enum):
    SERVER = "server"
    CLIENT = "client"
    EMAIL = "email"
    CODE_SIGNING = "codesigning"
    MTLS = "mtls"


class CertificateStatus(str, Enum):
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"
    SUSPENDED = "suspended"


class KeyType(str, Enum):
    RSA_2048 = "rsa-2048"
    RSA_4096 = "rsa-4096"
    ECDSA_P256 = "ecdsa-p256"
    ECDSA_P384 = "ecdsa-p384"
    ED25519 = "ed25519"


class KeyStorage(str, Enum):
    KMS = "kms"
    HSM = "hsm"
    FILE = "file"


# Base schemas
class BaseSchema(BaseModel):
    class Config:
        from_attributes = True


# Organization schemas
class OrganizationBase(BaseSchema):
    name: str = Field(..., min_length=1, max_length=255)
    domain: Optional[str] = Field(None, max_length=255)
    plan_type: str = Field("free", regex="^(free|pro|enterprise)$")
    max_cas: int = Field(5, ge=1)
    max_certificates: int = Field(1000, ge=1)
    mfa_required: bool = False
    alert_email: Optional[str] = Field(None, max_length=255)
    settings: Optional[Dict[str, Any]] = None


class OrganizationCreate(OrganizationBase):
    pass


class OrganizationResponse(OrganizationBase):
    id: uuid.UUID
    created_at: datetime
    updated_at: datetime


# Certificate Authority schemas
class CASubject(BaseSchema):
    common_name: str = Field(..., min_length=1, max_length=255)
    organization: Optional[str] = Field(None, max_length=255)
    organizational_unit: Optional[str] = Field(None, max_length=255)
    country: Optional[str] = Field(None, min_length=2, max_length=2)
    state: Optional[str] = Field(None, max_length=255)
    locality: Optional[str] = Field(None, max_length=255)
    email: Optional[str] = Field(None, max_length=255)


class CAPolicy(BaseSchema):
    max_path_length: Optional[int] = Field(None, ge=0)
    allowed_key_types: List[KeyType] = Field(default_factory=lambda: [KeyType.ECDSA_P256, KeyType.RSA_2048])
    max_validity_days: int = Field(365, ge=1, le=3650)  # Max 10 years
    crl_distribution_points: List[str] = Field(default_factory=list)
    ocsp_responder_url: Optional[str] = None


class CABase(BaseSchema):
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    type: CAType
    parent_ca_id: Optional[uuid.UUID] = None
    subject: CASubject
    key_type: KeyType = KeyType.ECDSA_P256
    key_storage: KeyStorage = KeyStorage.KMS
    validity_years: int = Field(10, ge=1, le=30)
    auto_renewal: bool = False
    renewal_threshold_days: int = Field(30, ge=1, le=365)
    policy: Optional[CAPolicy] = None
    metadata: Optional[Dict[str, Any]] = None

    @validator('parent_ca_id')
    def validate_parent_ca_id(cls, v, values):
        ca_type = values.get('type')
        if ca_type == CAType.ROOT and v is not None:
            raise ValueError('Root CAs cannot have a parent')
        if ca_type == CAType.INTERMEDIATE and v is None:
            raise ValueError('Intermediate CAs must have a parent')
        return v


class CACreate(CABase):
    kms_key_arn: Optional[str] = None  # For existing KMS keys
    

class CAUpdate(BaseSchema):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    auto_renewal: Optional[bool] = None
    renewal_threshold_days: Optional[int] = Field(None, ge=1, le=365)
    policy: Optional[CAPolicy] = None
    metadata: Optional[Dict[str, Any]] = None


class CAResponse(CABase):
    id: uuid.UUID
    organization_id: uuid.UUID
    status: CAStatus
    subject_dn: str
    serial_number: Optional[str]
    not_before: Optional[datetime]
    not_after: Optional[datetime]
    kms_key_id: Optional[str]
    kms_region: Optional[str]
    certificate_pem: Optional[str] = None  # Exclude by default for performance
    created_at: datetime
    updated_at: datetime
    created_by: Optional[str]


class CADetailResponse(CAResponse):
    certificate_pem: Optional[str]
    certificate_chain_pem: Optional[str]
    children_count: int = 0
    issued_certificates_count: int = 0
    active_certificates_count: int = 0


# Certificate schemas
class SubjectAlternativeNames(BaseSchema):
    dns: List[str] = Field(default_factory=list)
    ip: List[Union[IPv4Address, IPv6Address]] = Field(default_factory=list)
    email: List[str] = Field(default_factory=list)
    uri: List[str] = Field(default_factory=list)


class CertificateRequest(BaseSchema):
    common_name: str = Field(..., min_length=1, max_length=255)
    subject_alternative_names: Optional[SubjectAlternativeNames] = None
    certificate_type: CertificateType = CertificateType.SERVER
    key_type: KeyType = KeyType.ECDSA_P256
    validity_days: int = Field(365, ge=1, le=3650)
    key_usage: List[str] = Field(default_factory=lambda: ["digitalSignature", "keyEncipherment"])
    extended_key_usage: List[str] = Field(default_factory=lambda: ["serverAuth"])
    provisioner_name: Optional[str] = None
    template_id: Optional[uuid.UUID] = None
    metadata: Optional[Dict[str, Any]] = None


class CSRSigningRequest(BaseSchema):
    csr_pem: str = Field(..., min_length=1)
    certificate_type: CertificateType = CertificateType.SERVER
    validity_days: int = Field(365, ge=1, le=3650)
    provisioner_name: Optional[str] = None
    template_id: Optional[uuid.UUID] = None
    metadata: Optional[Dict[str, Any]] = None


class CertificateBase(BaseSchema):
    serial_number: str
    common_name: str
    subject_dn: Optional[str]
    subject_alternative_names: Optional[Dict[str, List[str]]]
    certificate_type: CertificateType
    key_type: Optional[KeyType]
    not_before: datetime
    not_after: datetime
    status: CertificateStatus
    requester: Optional[str]
    request_source: Optional[str]
    metadata: Optional[Dict[str, Any]]


class CertificateResponse(CertificateBase):
    id: uuid.UUID
    ca_id: uuid.UUID
    organization_id: uuid.UUID
    fingerprint_sha256: Optional[str]
    provisioner_id: Optional[uuid.UUID]
    template_id: Optional[uuid.UUID]
    created_at: datetime


class CertificateDetailResponse(CertificateResponse):
    certificate_pem: Optional[str]
    revoked_at: Optional[datetime]
    revocation_reason: Optional[str]
    revoked_by: Optional[str]


class CertificateRevocationRequest(BaseSchema):
    reason: str = Field("unspecified", regex="^(unspecified|keyCompromise|caCompromise|affiliationChanged|superseded|cessationOfOperation|certificateHold)$")


# Audit schemas
class AuditEventResponse(BaseSchema):
    id: int
    event_type: str
    event_category: Optional[str]
    severity: Optional[str]
    entity_type: str
    entity_id: uuid.UUID
    actor_type: Optional[str]
    actor_id: Optional[str]
    actor_ip: Optional[str]
    event_data: Dict[str, Any]
    changes: Optional[Dict[str, Any]]
    request_id: Optional[str]
    created_at: datetime


# Authentication schemas
class UserLogin(BaseSchema):
    email: str = Field(..., max_length=255)
    password: str = Field(..., min_length=8, max_length=128)
    organization_domain: Optional[str] = Field(None, max_length=255)


class UserResponse(BaseSchema):
    id: uuid.UUID
    email: str
    organization_id: uuid.UUID
    full_name: Optional[str]
    enabled: bool
    last_login: Optional[datetime]
    created_at: datetime


class TokenResponse(BaseSchema):
    access_token: str
    refresh_token: str
    token_type: str = "Bearer"
    expires_in: int
    user: UserResponse


# Statistics schemas
class CAStatistics(BaseSchema):
    total_cas: int
    active_cas: int
    root_cas: int
    intermediate_cas: int


class CertificateStatistics(BaseSchema):
    total_certificates: int
    active_certificates: int
    expiring_30d: int
    expiring_7d: int
    expired_certificates: int
    revoked_certificates: int


class DashboardStats(BaseSchema):
    ca_stats: CAStatistics
    cert_stats: CertificateStatistics
    recent_issuance_count: int
    organization: OrganizationResponse


# Pagination schemas
class PaginationParams(BaseSchema):
    limit: int = Field(20, ge=1, le=100)
    offset: int = Field(0, ge=0)


class PaginatedResponse(BaseSchema):
    data: List[Any]
    total: int
    limit: int
    offset: int
    has_more: bool

    @validator('has_more', pre=True, always=True)
    def calculate_has_more(cls, v, values):
        total = values.get('total', 0)
        limit = values.get('limit', 20)
        offset = values.get('offset', 0)
        return offset + limit < total


# Error schemas
class ErrorResponse(BaseSchema):
    error: str
    detail: Optional[str] = None
    request_id: Optional[str] = None


class ValidationErrorResponse(BaseSchema):
    error: str = "Validation error"
    detail: List[Dict[str, Any]]
    request_id: Optional[str] = None