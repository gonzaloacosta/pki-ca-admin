"""
Authentication router for user login and token management
"""

from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
import structlog

from app.core.database import get_db
from app.core.security import (
    verify_password, create_access_token, create_refresh_token,
    get_current_user, check_rate_limit, rate_limiter
)
from app.models.database import User, Organization, AuditEvent
from app.models.schemas import UserLogin, TokenResponse, UserResponse
from app.services.audit_service import create_audit_event

logger = structlog.get_logger()

router = APIRouter()

@router.post("/login", response_model=TokenResponse)
async def login(
    user_credentials: UserLogin,
    request: Request,
    db: AsyncSession = Depends(get_db),
    _rate_check = Depends(check_rate_limit)
):
    """
    Authenticate user and return JWT tokens
    """
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "")
    
    # Find user by email
    query = select(User).where(User.email == user_credentials.email.lower())
    
    # If organization domain is specified, filter by it
    if user_credentials.organization_domain:
        query = query.join(Organization).where(
            Organization.domain == user_credentials.organization_domain
        )
    
    result = await db.execute(query)
    user = result.scalar_one_or_none()
    
    # Verify user exists and password is correct
    if not user or not verify_password(user_credentials.password, user.hashed_password):
        # Record failed attempt
        rate_limiter.record_attempt(client_ip)
        
        # Log failed attempt
        logger.warning(
            "Failed login attempt",
            email=user_credentials.email,
            client_ip=client_ip,
            user_agent=user_agent,
        )
        
        # Increment failed attempts for user if found
        if user:
            await db.execute(
                update(User)
                .where(User.id == user.id)
                .values(failed_login_attempts=User.failed_login_attempts + 1)
            )
            await db.commit()
        
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )
    
    # Check if user is enabled
    if not user.enabled:
        logger.warning(
            "Login attempt by disabled user",
            user_id=str(user.id),
            email=user.email,
            client_ip=client_ip,
        )
        
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Account is disabled",
        )
    
    # Check if account is locked due to failed attempts
    if user.locked_until and user.locked_until > datetime.utcnow():
        remaining_time = user.locked_until - datetime.utcnow()
        logger.warning(
            "Login attempt by locked user",
            user_id=str(user.id),
            email=user.email,
            client_ip=client_ip,
            locked_until=user.locked_until,
        )
        
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Account locked. Try again in {int(remaining_time.total_seconds() / 60)} minutes",
        )
    
    # Check if user needs to be locked due to too many failed attempts
    if user.failed_login_attempts >= 5:
        lock_until = datetime.utcnow() + timedelta(minutes=15)
        await db.execute(
            update(User)
            .where(User.id == user.id)
            .values(locked_until=lock_until)
        )
        await db.commit()
        
        logger.warning(
            "User account locked due to failed attempts",
            user_id=str(user.id),
            email=user.email,
            failed_attempts=user.failed_login_attempts,
        )
        
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Account locked due to too many failed attempts",
        )
    
    # Successful login - reset failed attempts and update last login
    await db.execute(
        update(User)
        .where(User.id == user.id)
        .values(
            failed_login_attempts=0,
            locked_until=None,
            last_login=datetime.utcnow()
        )
    )
    
    # Create audit event
    await create_audit_event(
        db=db,
        organization_id=user.organization_id,
        event_type="auth.login",
        event_category="security",
        severity="info",
        entity_type="user",
        entity_id=user.id,
        actor_type="user",
        actor_id=str(user.id),
        actor_ip=client_ip,
        event_data={
            "email": user.email,
            "user_agent": user_agent,
            "method": "password"
        },
        request_id=getattr(request.state, "request_id", None)
    )
    
    await db.commit()
    
    # Create JWT tokens
    token_data = {
        "sub": str(user.id),
        "email": user.email,
        "organization_id": str(user.organization_id),
    }
    
    access_token = create_access_token(token_data)
    refresh_token = create_refresh_token(token_data)
    
    logger.info(
        "User login successful",
        user_id=str(user.id),
        email=user.email,
        organization_id=str(user.organization_id),
        client_ip=client_ip,
    )
    
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=60 * 60 * 24,  # 24 hours
        user=UserResponse(
            id=user.id,
            email=user.email,
            organization_id=user.organization_id,
            full_name=user.full_name,
            enabled=user.enabled,
            last_login=user.last_login,
            created_at=user.created_at,
        )
    )

@router.post("/logout")
async def logout(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Logout current user (token invalidation would be handled by client)
    """
    client_ip = request.client.host if request.client else "unknown"
    
    # Create audit event
    await create_audit_event(
        db=db,
        organization_id=current_user.organization_id,
        event_type="auth.logout",
        event_category="security", 
        severity="info",
        entity_type="user",
        entity_id=current_user.id,
        actor_type="user",
        actor_id=str(current_user.id),
        actor_ip=client_ip,
        event_data={
            "email": current_user.email,
        },
        request_id=getattr(request.state, "request_id", None)
    )
    
    await db.commit()
    
    logger.info(
        "User logout",
        user_id=str(current_user.id),
        email=current_user.email,
        client_ip=client_ip,
    )
    
    return {"message": "Successfully logged out"}

@router.get("/me", response_model=UserResponse)
async def get_current_user_info(
    current_user: User = Depends(get_current_user)
):
    """
    Get current user information
    """
    return UserResponse(
        id=current_user.id,
        email=current_user.email,
        organization_id=current_user.organization_id,
        full_name=current_user.full_name,
        enabled=current_user.enabled,
        last_login=current_user.last_login,
        created_at=current_user.created_at,
    )