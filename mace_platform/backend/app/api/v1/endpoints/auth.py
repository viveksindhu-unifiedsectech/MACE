"""Auth endpoints — login, register, refresh, logout, MFA, SSO."""
from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from datetime import timedelta
from app.db.base import get_db
from app.models.user import User, UserRole
from app.models.tenant import Tenant, TenantPlan
from app.models.audit import AuditLog
from app.auth.jwt import (hash_password, verify_password,
                           create_access_token, create_refresh_token, decode_token)
from app.auth.dependencies import get_current_user, CurrentUser
from app.schemas.auth import (LoginRequest, TokenResponse, RegisterRequest,
                               RefreshRequest, PasswordResetRequest)
from app.core.config import settings
import uuid
from datetime import datetime

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
async def register(req: RegisterRequest, db: AsyncSession = Depends(get_db)):
    """Register a new tenant + admin user. Creates isolated tenant workspace."""
    # Check slug uniqueness
    existing = await db.execute(select(Tenant).where(Tenant.slug == req.tenant_slug))
    if existing.scalar_one_or_none():
        raise HTTPException(400, "Tenant slug already taken")

    # Check email uniqueness globally
    existing_user = await db.execute(select(User).where(User.email == req.email))
    if existing_user.scalar_one_or_none():
        raise HTTPException(400, "Email already registered")

    # Create tenant
    juris_to_profile = {
        "US": "usa_fedramp", "IN": "india_cii", "EU": "eu_gdpr",
        "CA": "canada_pipeda", "AE": "uae_nesa"
    }
    tenant = Tenant(
        id=str(uuid.uuid4()),
        name=req.tenant_name,
        slug=req.tenant_slug,
        jurisdiction=req.jurisdiction,
        weight_profile=juris_to_profile.get(req.jurisdiction, "usa_fedramp"),
        plan=TenantPlan.STARTER,
    )
    db.add(tenant)
    await db.flush()

    # Create tenant admin user
    user = User(
        id=str(uuid.uuid4()),
        tenant_id=tenant.id,
        email=req.email,
        full_name=req.full_name,
        hashed_password=hash_password(req.password),
        role=UserRole.TENANT_ADMIN,
        is_verified=False,
    )
    db.add(user)
    await db.flush()

    # Audit
    db.add(AuditLog(tenant_id=tenant.id, user_id=user.id, user_email=user.email,
                    action="user.register", resource_type="user", resource_id=user.id))

    access_token = create_access_token({
        "sub": user.id, "tenant_id": tenant.id,
        "role": user.role.value, "email": user.email
    })
    refresh_token = create_refresh_token(user.id, tenant.id)

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user_id=user.id,
        tenant_id=tenant.id,
        role=user.role.value,
    )


@router.post("/login", response_model=TokenResponse)
async def login(req: LoginRequest, request: Request, db: AsyncSession = Depends(get_db)):
    """Login with email + password + tenant slug."""
    tenant_result = await db.execute(select(Tenant).where(Tenant.slug == req.tenant_slug))
    tenant = tenant_result.scalar_one_or_none()
    if not tenant or not tenant.is_active:
        raise HTTPException(401, "Invalid credentials")

    user_result = await db.execute(
        select(User).where(User.email == req.email, User.tenant_id == tenant.id)
    )
    user = user_result.scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(401, "Invalid credentials")

    # Check lockout
    if user.locked_until and user.locked_until > datetime.utcnow():
        raise HTTPException(429, f"Account locked until {user.locked_until.isoformat()}")

    if not user.hashed_password or not verify_password(req.password, user.hashed_password):
        user.failed_login_count += 1
        if user.failed_login_count >= 5:
            from datetime import timedelta
            user.locked_until = datetime.utcnow() + timedelta(minutes=15)
        db.add(AuditLog(tenant_id=tenant.id, user_id=user.id, user_email=user.email,
                        action="user.login_failed", ip_address=request.client.host, success=False))
        raise HTTPException(401, "Invalid credentials")

    # Success
    user.failed_login_count = 0
    user.locked_until = None
    user.last_login_at = datetime.utcnow()
    user.last_login_ip = request.client.host

    db.add(AuditLog(tenant_id=tenant.id, user_id=user.id, user_email=user.email,
                    action="user.login", ip_address=request.client.host, success=True))

    access_token = create_access_token({
        "sub": user.id, "tenant_id": tenant.id,
        "role": user.role.value, "email": user.email
    })
    refresh_token = create_refresh_token(user.id, tenant.id)

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user_id=user.id,
        tenant_id=tenant.id,
        role=user.role.value,
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(req: RefreshRequest, db: AsyncSession = Depends(get_db)):
    payload = decode_token(req.refresh_token)
    if not payload or payload.get("type") != "refresh":
        raise HTTPException(401, "Invalid refresh token")

    user = await db.get(User, payload["sub"])
    tenant = await db.get(Tenant, payload["tenant_id"])
    if not user or not tenant or not user.is_active:
        raise HTTPException(401, "Invalid token")

    access_token = create_access_token({
        "sub": user.id, "tenant_id": tenant.id,
        "role": user.role.value, "email": user.email
    })
    new_refresh = create_refresh_token(user.id, tenant.id)

    return TokenResponse(
        access_token=access_token, refresh_token=new_refresh,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user_id=user.id, tenant_id=tenant.id, role=user.role.value,
    )


@router.post("/logout")
async def logout(current: CurrentUser = Depends(get_current_user),
                 db: AsyncSession = Depends(get_db)):
    """Invalidate session — client should discard tokens."""
    db.add(AuditLog(tenant_id=current.tenant_id, user_id=current.id,
                    user_email=current.email, action="user.logout", success=True))
    return {"message": "Logged out successfully"}


@router.get("/me")
async def get_me(current: CurrentUser = Depends(get_current_user)):
    return {
        "user_id": current.id,
        "email": current.email,
        "full_name": current.user.full_name,
        "role": current.role.value,
        "tenant_id": current.tenant_id,
        "tenant_name": current.tenant.name,
        "tenant_slug": current.tenant.slug,
        "jurisdiction": current.tenant.jurisdiction,
        "weight_profile": current.tenant.weight_profile,
        "plan": current.tenant.plan.value,
        "mfa_enabled": current.user.mfa_enabled,
    }
