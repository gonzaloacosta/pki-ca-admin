"""
Configuration settings for the PKI CA Admin application.
Uses pydantic-settings for environment variable management.
"""

from typing import Optional, List
from pydantic import field_validator
from pydantic_settings import BaseSettings
from functools import lru_cache
import os


class Settings(BaseSettings):
    """Application configuration settings."""

    # Application
    app_name: str = "PKI CA Admin"
    app_version: str = "1.0.0"
    debug: bool = False
    environment: str = "development"

    # Database
    database_url: str = "postgresql+asyncpg://pki:pki_dev@localhost:5432/pki_ca_admin"
    db_echo: bool = False  # Set to True to log SQL queries

    # Keycloak Configuration
    keycloak_url: str = "http://localhost:8080"
    keycloak_realm: str = "pki-ca-admin"
    keycloak_client_id: str = "pki-api"
    keycloak_client_secret: str = "pki-api-client-secret"

    # JWT Configuration
    jwt_algorithm: str = "RS256"
    jwt_audience: str = "pki-api"

    # Security
    secret_key: str = "your-super-secret-key-change-this-in-production"
    access_token_expire_minutes: int = 60

    # CORS
    allowed_origins: List[str] = ["http://localhost:3000", "http://localhost:8080"]
    allowed_origin_regex: Optional[str] = None

    # Key Storage Backend
    key_backend: str = "file"  # "file", "kms", "hsm"

    # File Backend Settings (for development)
    file_key_storage_path: str = "/app/data/keys"
    file_key_encryption_password: str = "dev-key-encryption-password"

    # KMS Settings (for production)
    aws_region: str = "us-west-2"
    kms_key_id: Optional[str] = None

    # Certificate Authority Defaults
    default_ca_key_type: str = "ecdsa-p256"  # "rsa-2048", "ecdsa-p256", "ed25519"
    default_cert_validity_days: int = 365
    default_ca_validity_years: int = 10

    # OCSP Configuration
    ocsp_responder_url: Optional[str] = None
    ocsp_cache_ttl: int = 3600  # 1 hour

    # CRL Configuration
    crl_distribution_point: Optional[str] = None
    crl_generation_interval_hours: int = 24

    # Audit Logging
    audit_log_level: str = "INFO"
    audit_retention_days: int = 365

    # Rate Limiting
    rate_limit_requests_per_minute: int = 100

    # Development Settings
    create_default_org: bool = True
    default_org_name: str = "Default Organization"
    default_org_domain: str = "default.local"

    @field_validator('database_url', mode='before')
    @classmethod
    def assemble_database_url(cls, v: Optional[str]) -> str:
        """Build database URL from environment variables if not provided directly."""
        if v:
            return v

        # Fallback to individual components
        db_user = os.getenv('DB_USER', 'pki')
        db_password = os.getenv('DB_PASSWORD', 'pki_dev')
        db_host = os.getenv('DB_HOST', 'localhost')
        db_port = os.getenv('DB_PORT', '5432')
        db_name = os.getenv('DB_NAME', 'pki_ca_admin')

        return f"postgresql+asyncpg://{db_user}:{db_password}@{db_host}:{db_port}/{db_name}"

    @field_validator('keycloak_url', mode='before')
    @classmethod
    def build_keycloak_url(cls, v: str) -> str:
        """Ensure Keycloak URL doesn't have trailing slash."""
        return v.rstrip('/')

    @field_validator('file_key_storage_path', mode='before')
    @classmethod
    def create_key_storage_path(cls, v: str) -> str:
        """Ensure key storage directory exists."""
        if not os.path.exists(v):
            os.makedirs(v, mode=0o700, exist_ok=True)
        return v

    @property
    def keycloak_realm_url(self) -> str:
        """Full Keycloak realm URL."""
        return f"{self.keycloak_url}/realms/{self.keycloak_realm}"

    @property
    def keycloak_certs_url(self) -> str:
        """Keycloak public keys endpoint."""
        return f"{self.keycloak_realm_url}/protocol/openid-connect/certs"

    @property
    def keycloak_token_url(self) -> str:
        """Keycloak token endpoint."""
        return f"{self.keycloak_realm_url}/protocol/openid-connect/token"

    @property
    def keycloak_userinfo_url(self) -> str:
        """Keycloak user info endpoint."""
        return f"{self.keycloak_realm_url}/protocol/openid-connect/userinfo"

    model_config = {
        "env_file": ".env",
        "case_sensitive": False,
    }


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()
