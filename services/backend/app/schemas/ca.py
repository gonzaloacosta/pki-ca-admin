"""
Pydantic schemas for Certificate Authority operations.
"""

from typing import Optional, List, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field, validator
import uuid


class SubjectInfo(BaseModel):
    """Certificate subject information."""
    common_name: str = Field(..., min_length=1, max_length=255, description="Common Name (CN)")
    organization: Optional[str] = Field(None, max_length=255, description="Organization (O)")
    organizational_unit: Optional[str] = Field(None, max_length=255, description="Organizational Unit (OU)")
    country: Optional[str] = Field(None, min_length=2, max_length=2, description="Country code (C)")
    state: Optional[str] = Field(None, max_length=255, description="State or Province (ST)")
    locality: Optional[str] = Field(None, max_length=255, description="Locality or City (L)")
    email: Optional[str] = Field(None, description="Email address")


class CaPolicy(BaseModel):
    """CA policy configuration."""
    max_path_length: Optional[int] = Field(None, ge=0, description="Maximum certificate chain length")
    allowed_key_types: Optional[List[str]] = Field(
        default=["rsa-2048", "ecdsa-p256"], 
        description="Allowed key types for issued certificates"
    )
    max_validity_days: int = Field(default=365, ge=1, le=3650, description="Maximum certificate validity in days")
    require_san: bool = Field(default=True, description="Require Subject Alternative Names")


class CaNodeBase(BaseModel):
    """Base CA node schema."""
    name: str = Field(..., min_length=1, max_length=255, description="CA name")
    description: Optional[str] = Field(None, description="CA description")
    type: str = Field(..., pattern="^(root|intermediate)$", description="CA type")
    
    @validator('type')
    def validate_ca_type(cls, v):
        if v not in ['root', 'intermediate']:
            raise ValueError('CA type must be either "root" or "intermediate"')
        return v


class CaNodeCreate(CaNodeBase):
    """Schema for creating a new CA."""
    parent_ca_id: Optional[uuid.UUID] = Field(None, description="Parent CA ID for intermediate CAs")
    subject: SubjectInfo = Field(..., description="Certificate subject information")
    key_type: str = Field(
        default="ecdsa-p256",
        pattern="^(rsa-2048|rsa-3072|rsa-4096|ecdsa-p256|ecdsa-p384|ed25519)$",
        description="Private key type"
    )
    key_storage: str = Field(
        default="file",
        pattern="^(file|kms|hsm)$", 
        description="Key storage backend"
    )
    validity_years: int = Field(default=10, ge=1, le=30, description="Certificate validity in years")
    policy: Optional[CaPolicy] = Field(default_factory=CaPolicy, description="CA policy configuration")
    auto_renewal: bool = Field(default=False, description="Enable automatic renewal")
    renewal_threshold_days: int = Field(default=30, ge=1, le=365, description="Renewal threshold in days")
    
    @validator('parent_ca_id')
    def validate_parent_ca(cls, v, values):
        ca_type = values.get('type')
        if ca_type == 'root' and v is not None:
            raise ValueError('Root CAs cannot have a parent CA')
        if ca_type == 'intermediate' and v is None:
            raise ValueError('Intermediate CAs must have a parent CA')
        return v


class CaNodeUpdate(BaseModel):
    """Schema for updating CA properties."""
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    status: Optional[str] = Field(None, pattern="^(active|suspended|revoked)$")
    auto_renewal: Optional[bool] = None
    renewal_threshold_days: Optional[int] = Field(None, ge=1, le=365)
    policy: Optional[CaPolicy] = None
    metadata: Optional[Dict[str, Any]] = None


class CaNodeResponse(CaNodeBase):
    """Schema for CA response."""
    id: uuid.UUID
    parent_ca_id: Optional[uuid.UUID]
    
    # Certificate information
    subject_dn: str
    certificate_pem: Optional[str]
    serial_number: Optional[str]
    not_before: Optional[datetime]
    not_after: Optional[datetime]
    
    # Key information
    key_type: str
    key_storage: str
    kms_key_id: Optional[str]
    kms_region: Optional[str]
    
    # Policy
    max_path_length: Optional[int]
    allowed_key_types: Optional[List[str]]
    max_validity_days: int
    
    # Distribution points
    crl_distribution_points: Optional[List[str]]
    ocsp_responder_url: Optional[str]
    
    # Status
    status: str
    auto_renewal: bool
    renewal_threshold_days: int
    
    # Metadata
    metadata_: Optional[Dict[str, Any]] = Field(None, alias="metadata")
    
    # Timestamps
    created_at: datetime
    updated_at: datetime
    created_by: Optional[str]
    
    # Computed properties
    is_root: bool
    is_intermediate: bool
    is_expired: bool
    is_expiring_soon: bool
    depth: Optional[int] = None
    
    class Config:
        from_attributes = True
        populate_by_name = True


class CaHierarchyResponse(CaNodeResponse):
    """CA response with hierarchy information."""
    children: List["CaHierarchyResponse"] = Field(default_factory=list)
    certificate_count: int = Field(default=0, description="Number of certificates issued by this CA")


# Update forward references
CaHierarchyResponse.model_rebuild()


class CaNodeListResponse(BaseModel):
    """Response for listing CAs."""
    items: List[CaNodeResponse]
    total: int
    page: int = Field(default=1, ge=1)
    size: int = Field(default=20, ge=1, le=100)
    pages: int


class CaTreeResponse(BaseModel):
    """Response for CA hierarchy tree."""
    root_cas: List[CaHierarchyResponse]
    total_cas: int


class CaStatsResponse(BaseModel):
    """CA statistics response."""
    total_cas: int
    root_cas: int
    intermediate_cas: int
    active_cas: int
    expired_cas: int
    expiring_soon_cas: int
    total_certificates: int
    active_certificates: int
    expired_certificates: int
    revoked_certificates: int