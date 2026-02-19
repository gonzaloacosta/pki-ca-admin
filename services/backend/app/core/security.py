"""
Security and authentication module for PKI CA Admin.
Handles JWT token validation against Keycloak.
"""

from typing import Optional, List, Dict, Any
from datetime import datetime, timezone
from fastapi import HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import httpx
import jwt
from jwt import PyJWKClient
from functools import lru_cache
import logging

from app.core.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()
security = HTTPBearer()


class JWTError(HTTPException):
    """Custom JWT validation error."""
    
    def __init__(self, detail: str = "Could not validate credentials"):
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=detail,
            headers={"WWW-Authenticate": "Bearer"},
        )


class InsufficientPermissions(HTTPException):
    """Insufficient permissions error."""
    
    def __init__(self, required_role: str):
        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Insufficient permissions. Required role: {required_role}",
        )


@lru_cache()
def get_jwks_client() -> PyJWKClient:
    """Get cached JWKS client for Keycloak public keys."""
    return PyJWKClient(
        settings.keycloak_certs_url,
        cache_keys=True,
        max_cached_keys=16,
    )


async def get_keycloak_public_key(token: str) -> str:
    """
    Get the public key from Keycloak for JWT verification.
    
    Args:
        token: JWT token to get the key for
        
    Returns:
        str: PEM-formatted public key
        
    Raises:
        JWTError: If key cannot be retrieved
    """
    try:
        jwks_client = get_jwks_client()
        signing_key = jwks_client.get_signing_key_from_jwt(token)
        return signing_key.key
    except Exception as e:
        logger.error(f"Failed to get public key from Keycloak: {e}")
        raise JWTError("Could not validate token signature")


async def verify_token(token: str) -> Dict[str, Any]:
    """
    Verify and decode JWT token from Keycloak.
    
    Args:
        token: JWT token to verify
        
    Returns:
        Dict[str, Any]: Token payload
        
    Raises:
        JWTError: If token is invalid
    """
    try:
        # Get public key for verification
        public_key = await get_keycloak_public_key(token)
        
        # Decode and verify token
        payload = jwt.decode(
            token,
            public_key,
            algorithms=[settings.jwt_algorithm],
            audience=settings.jwt_audience,
            options={
                "verify_exp": True,
                "verify_aud": True,
                "verify_iss": True,
            }
        )
        
        # Verify issuer
        expected_issuer = settings.keycloak_realm_url
        if payload.get("iss") != expected_issuer:
            raise JWTError("Invalid token issuer")
        
        # Check if token is expired
        if "exp" in payload:
            exp_timestamp = payload["exp"]
            if datetime.fromtimestamp(exp_timestamp, tz=timezone.utc) < datetime.now(timezone.utc):
                raise JWTError("Token has expired")
        
        return payload
        
    except jwt.InvalidTokenError as e:
        logger.error(f"JWT validation error: {e}")
        raise JWTError(f"Invalid token: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error during token validation: {e}")
        raise JWTError("Token validation failed")


class CurrentUser:
    """Current authenticated user information."""
    
    def __init__(self, payload: Dict[str, Any]):
        self.payload = payload
        self.user_id: str = payload.get("sub", "")
        self.username: str = payload.get("preferred_username", "")
        self.email: str = payload.get("email", "")
        self.first_name: str = payload.get("given_name", "")
        self.last_name: str = payload.get("family_name", "")
        self.full_name: str = f"{self.first_name} {self.last_name}".strip()
        
        # Extract roles from realm_access
        realm_access = payload.get("realm_access", {})
        self.roles: List[str] = realm_access.get("roles", [])
        
        # Organization info (if available)
        self.organization_id: Optional[str] = payload.get("org_id")
        self.organization_domain: Optional[str] = payload.get("org_domain")
    
    def has_role(self, role: str) -> bool:
        """Check if user has a specific role."""
        return role in self.roles
    
    def has_any_role(self, roles: List[str]) -> bool:
        """Check if user has any of the specified roles."""
        return any(role in self.roles for role in roles)
    
    def has_all_roles(self, roles: List[str]) -> bool:
        """Check if user has all of the specified roles."""
        return all(role in self.roles for role in roles)
    
    @property
    def is_admin(self) -> bool:
        """Check if user is an administrator."""
        return self.has_role("admin")
    
    @property
    def is_operator(self) -> bool:
        """Check if user is an operator."""
        return self.has_role("operator")
    
    @property
    def is_viewer(self) -> bool:
        """Check if user is a viewer."""
        return self.has_role("viewer")


async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> CurrentUser:
    """
    Dependency to get the current authenticated user.
    
    Args:
        credentials: HTTP Bearer token credentials
        
    Returns:
        CurrentUser: Current user information
        
    Raises:
        JWTError: If authentication fails
    """
    token = credentials.credentials
    payload = await verify_token(token)
    return CurrentUser(payload)


def require_role(required_role: str):
    """
    Dependency factory for role-based access control.
    
    Args:
        required_role: Role required to access the endpoint
        
    Returns:
        Dependency function that checks for the required role
    """
    async def role_checker(current_user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        if not current_user.has_role(required_role):
            raise InsufficientPermissions(required_role)
        return current_user
    
    return role_checker


def require_any_role(required_roles: List[str]):
    """
    Dependency factory for role-based access control (any of multiple roles).
    
    Args:
        required_roles: List of roles, user needs at least one
        
    Returns:
        Dependency function that checks for any of the required roles
    """
    async def role_checker(current_user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        if not current_user.has_any_role(required_roles):
            raise InsufficientPermissions(f"one of: {', '.join(required_roles)}")
        return current_user
    
    return role_checker


# Common role dependencies
require_admin = require_role("admin")
require_operator = require_any_role(["admin", "operator"])
require_viewer = require_any_role(["admin", "operator", "viewer"])


async def authenticate_with_keycloak(username: str, password: str) -> Optional[Dict[str, Any]]:
    """
    Authenticate user with Keycloak using username/password.
    
    Args:
        username: Username or email
        password: User password
        
    Returns:
        Dict with token information or None if authentication fails
    """
    try:
        async with httpx.AsyncClient() as client:
            token_data = {
                "grant_type": "password",
                "client_id": settings.keycloak_client_id,
                "client_secret": settings.keycloak_client_secret,
                "username": username,
                "password": password,
            }
            
            response = await client.post(
                settings.keycloak_token_url,
                data=token_data,
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                logger.warning(f"Keycloak authentication failed for user {username}: {response.status_code}")
                return None
                
    except Exception as e:
        logger.error(f"Error authenticating with Keycloak: {e}")
        return None