"""
Auth Extensions — SSO, MFA (TOTP), Password Reset, Email Verification

New endpoints added to /auth/* router:
  GET  /auth/mfa/setup               — Generate TOTP secret + QR code URL
  POST /auth/mfa/verify              — Confirm TOTP code + enable MFA + issue backup codes
  POST /auth/mfa/disable             — Disable MFA (requires current TOTP code)
  POST /auth/mfa/login               — Second-factor step (returns full JWT)
  POST /auth/password/reset          — Request password reset email
  POST /auth/password/reset/confirm  — Set new password with reset token
  POST /auth/email/verify            — Verify email via token
  POST /auth/email/resend            — Resend verification email
  POST /auth/sso/google              — Google OAuth2 SSO
  POST /auth/sso/microsoft           — Microsoft OAuth2 SSO (via Graph API)
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from datetime import datetime, timedelta
import secrets

from app.db.base import get_db
from app.auth.dependencies import get_current_user, CurrentUser
from app.auth.jwt import hash_password, verify_password, create_access_token, create_refresh_token
from app.models.user import User
from app.models.tenant import Tenant
from app.models.audit import AuditLog
from app.core.config import settings
from app.schemas.auth import TokenResponse, MFASetupResponse, MFAVerifyRequest

router = APIRouter(prefix="/auth", tags=["Auth Extensions"])


# ── MFA ─────────────────────────────────────────────────────────────────────

@router.get("/mfa/setup", response_model=MFASetupResponse)
async def mfa_setup(
    current: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Generate TOTP secret and QR code URL. User scans with Authenticator app."""
    import pyotp
    user = await db.get(User, current.id)
    secret = pyotp.random_base32()
    user.mfa_secret = secret  # Stored but not active until verified
    qr_url = pyotp.TOTP(secret).provisioning_uri(
        name=current.email, issuer_name="UnifiedSec MACE"
    )
    db.add(AuditLog(tenant_id=current.tenant_id, user_id=current.id,
                    user_email=current.email, action="user.mfa_setup_initiated", success=True))
    return MFASetupResponse(secret=secret, qr_code_url=qr_url)


@router.post("/mfa/verify")
async def mfa_verify(
    req: MFAVerifyRequest,
    current: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Confirm TOTP code, enable MFA, and return 8 one-time backup codes."""
    import pyotp
    user = await db.get(User, current.id)
    if not user.mfa_secret:
        raise HTTPException(400, "Call GET /auth/mfa/setup first")
    if not pyotp.TOTP(user.mfa_secret).verify(req.code, valid_window=1):
        raise HTTPException(400, "Invalid TOTP code")
    user.mfa_enabled = True
    backup_codes = [secrets.token_hex(4).upper() for _ in range(8)]
    user.mfa_backup_codes = [hash_password(c) for c in backup_codes]
    db.add(AuditLog(tenant_id=current.tenant_id, user_id=current.id,
                    user_email=current.email, action="user.mfa_enabled", success=True))
    return {
        "message": "MFA enabled",
        "backup_codes": backup_codes,
        "warning": "Save these backup codes now. They will NOT be shown again.",
    }


@router.post("/mfa/disable")
async def mfa_disable(
    req: MFAVerifyRequest,
    current: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Disable MFA. Requires current valid TOTP code."""
    import pyotp
    user = await db.get(User, current.id)
    if not user.mfa_enabled:
        return {"message": "MFA is not enabled"}
    if not pyotp.TOTP(user.mfa_secret).verify(req.code, valid_window=1):
        raise HTTPException(400, "Invalid TOTP code")
    user.mfa_enabled = False
    user.mfa_secret = None
    user.mfa_backup_codes = None
    db.add(AuditLog(tenant_id=current.tenant_id, user_id=current.id,
                    user_email=current.email, action="user.mfa_disabled", success=True))
    return {"message": "MFA disabled"}


@router.post("/mfa/login")
async def mfa_login(
    mfa_session_token: str,
    code: str,
    db: AsyncSession = Depends(get_db),
):
    """
    Second step of MFA login flow.
    Password login returns mfa_session_token (5-min challenge JWT) when MFA is on.
    Present it here with TOTP code to receive the full access token.
    """
    import pyotp
    from app.auth.jwt import decode_token
    payload = decode_token(mfa_session_token)
    if not payload or payload.get("type") != "mfa_challenge":
        raise HTTPException(401, "Invalid or expired MFA session")
    user = await db.get(User, payload["sub"])
    if not user or not user.is_active or not user.mfa_enabled:
        raise HTTPException(401, "Invalid session")
    # Check TOTP code
    code_valid = pyotp.TOTP(user.mfa_secret).verify(code, valid_window=1)
    # Fallback: check backup codes
    if not code_valid and user.mfa_backup_codes:
        for i, hashed in enumerate(list(user.mfa_backup_codes)):
            if verify_password(code.upper(), hashed):
                codes = list(user.mfa_backup_codes)
                codes.pop(i)
                user.mfa_backup_codes = codes
                code_valid = True
                break
    if not code_valid:
        raise HTTPException(401, "Invalid TOTP or backup code")
    tenant = await db.get(Tenant, user.tenant_id)
    access_token = create_access_token({
        "sub": user.id, "tenant_id": tenant.id,
        "role": user.role.value, "email": user.email,
    })
    refresh_token = create_refresh_token(user.id, tenant.id)
    return TokenResponse(
        access_token=access_token, refresh_token=refresh_token,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user_id=user.id, tenant_id=tenant.id, role=user.role.value,
    )


# ── PASSWORD RESET ───────────────────────────────────────────────────────────

@router.post("/password/reset")
async def password_reset_request(
    email: str,
    tenant_slug: str,
    db: AsyncSession = Depends(get_db),
):
    """Request password reset. Always returns 200 to prevent user enumeration."""
    tenant_result = await db.execute(select(Tenant).where(Tenant.slug == tenant_slug))
    tenant = tenant_result.scalar_one_or_none()
    if tenant:
        user_result = await db.execute(
            select(User).where(User.email == email, User.tenant_id == tenant.id)
        )
        user = user_result.scalar_one_or_none()
        if user and user.is_active:
            token = secrets.token_urlsafe(32)
            user.password_reset_token = token
            user.password_reset_expires = datetime.utcnow() + timedelta(hours=2)
            await _send_reset_email(email, user.full_name or email, token, tenant_slug)
            db.add(AuditLog(tenant_id=tenant.id, user_id=user.id, user_email=email,
                            action="user.password_reset_requested", success=True))
    return {"message": "If that email exists, a reset link has been sent. Expires in 2 hours."}


@router.post("/password/reset/confirm")
async def password_reset_confirm(
    token: str,
    new_password: str,
    tenant_slug: str,
    db: AsyncSession = Depends(get_db),
):
    """Set new password using reset token."""
    if len(new_password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters")
    tenant_result = await db.execute(select(Tenant).where(Tenant.slug == tenant_slug))
    tenant = tenant_result.scalar_one_or_none()
    if not tenant:
        raise HTTPException(400, "Invalid reset link")
    user_result = await db.execute(
        select(User).where(User.tenant_id == tenant.id, User.password_reset_token == token)
    )
    user = user_result.scalar_one_or_none()
    if not user:
        raise HTTPException(400, "Invalid or already used reset link")
    if not user.password_reset_expires or user.password_reset_expires < datetime.utcnow():
        raise HTTPException(400, "Reset link expired. Request a new one.")
    user.hashed_password = hash_password(new_password)
    user.password_reset_token = None
    user.password_reset_expires = None
    user.failed_login_count = 0
    user.locked_until = None
    db.add(AuditLog(tenant_id=tenant.id, user_id=user.id, user_email=user.email,
                    action="user.password_reset_completed", success=True))
    return {"message": "Password updated. You can now log in."}


# ── EMAIL VERIFICATION ───────────────────────────────────────────────────────

@router.post("/email/verify")
async def email_verify(
    token: str,
    tenant_slug: str,
    db: AsyncSession = Depends(get_db),
):
    """Verify email using token from verification email."""
    tenant_result = await db.execute(select(Tenant).where(Tenant.slug == tenant_slug))
    tenant = tenant_result.scalar_one_or_none()
    if not tenant:
        raise HTTPException(400, "Invalid verification link")
    user_result = await db.execute(
        select(User).where(User.tenant_id == tenant.id, User.email_verify_token == token)
    )
    user = user_result.scalar_one_or_none()
    if not user:
        raise HTTPException(400, "Invalid or already used verification link")
    user.is_verified = True
    user.email_verify_token = None
    db.add(AuditLog(tenant_id=tenant.id, user_id=user.id, user_email=user.email,
                    action="user.email_verified", success=True))
    return {"message": "Email verified"}


@router.post("/email/resend")
async def email_resend_verification(
    current: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Resend email verification link."""
    user = await db.get(User, current.id)
    if user.is_verified:
        return {"message": "Email already verified"}
    token = secrets.token_urlsafe(32)
    user.email_verify_token = token
    await _send_verify_email(user.email, user.full_name or user.email, token, current.tenant.slug)
    return {"message": "Verification email sent"}


# ── SSO ─────────────────────────────────────────────────────────────────────

@router.post("/sso/google")
async def sso_google(
    id_token: str,
    tenant_slug: str,
    db: AsyncSession = Depends(get_db),
):
    """Google OAuth2 SSO. Frontend obtains id_token via Google Sign-In / OAuth2 flow."""
    if not getattr(settings, 'GOOGLE_CLIENT_ID', None):
        raise HTTPException(503, "Google SSO not configured")
    try:
        from google.oauth2 import id_token as g_id_token
        from google.auth.transport import requests as g_requests
        info = g_id_token.verify_oauth2_token(id_token, g_requests.Request(), settings.GOOGLE_CLIENT_ID)
        email = info.get("email")
        name = info.get("name")
        sub = info.get("sub")
        if not email or not sub:
            raise HTTPException(400, "Invalid Google token")
    except Exception as e:
        raise HTTPException(401, f"Google token verification failed: {str(e)[:100]}")
    return await _sso_login(email, name, "google", sub, tenant_slug, db)


@router.post("/sso/microsoft")
async def sso_microsoft(
    access_token_ms: str,
    tenant_slug: str,
    db: AsyncSession = Depends(get_db),
):
    """Microsoft OAuth2 SSO. Frontend obtains token via MSAL.js."""
    if not getattr(settings, 'MICROSOFT_CLIENT_ID', None):
        raise HTTPException(503, "Microsoft SSO not configured")
    try:
        import httpx as _httpx
        async with _httpx.AsyncClient() as client:
            resp = await client.get(
                "https://graph.microsoft.com/v1.0/me",
                headers={"Authorization": f"Bearer {access_token_ms}"}, timeout=10,
            )
            resp.raise_for_status()
            profile = resp.json()
        email = profile.get("mail") or profile.get("userPrincipalName")
        name = profile.get("displayName")
        sub = profile.get("id")
        if not email or not sub:
            raise HTTPException(400, "Could not read profile from Microsoft")
    except Exception as e:
        raise HTTPException(401, f"Microsoft token validation failed: {str(e)[:100]}")
    return await _sso_login(email, name, "microsoft", sub, tenant_slug, db)


# ── SHARED HELPERS ───────────────────────────────────────────────────────────

async def _sso_login(email, name, provider, sub, tenant_slug, db):
    """Find or create user from SSO, return JWT tokens."""
    from app.models.user import UserRole
    import uuid
    tenant_result = await db.execute(select(Tenant).where(Tenant.slug == tenant_slug))
    tenant = tenant_result.scalar_one_or_none()
    if not tenant or not tenant.is_active:
        raise HTTPException(404, "Workspace not found")
    user_result = await db.execute(
        select(User).where(User.email == email, User.tenant_id == tenant.id)
    )
    user = user_result.scalar_one_or_none()
    if not user:
        user = User(
            id=str(uuid.uuid4()), tenant_id=tenant.id, email=email, full_name=name,
            sso_provider=provider, sso_subject=sub,
            role=UserRole.SOC_ANALYST, is_active=True, is_verified=True,
        )
        db.add(user)
        await db.flush()
    else:
        user.sso_provider = provider
        user.sso_subject = sub
    if not user.is_active:
        raise HTTPException(403, "Account disabled")
    user.last_login_at = datetime.utcnow()
    db.add(AuditLog(tenant_id=tenant.id, user_id=user.id, user_email=email,
                    action="user.sso_login", extra={"provider": provider}, success=True))
    access_token = create_access_token({
        "sub": user.id, "tenant_id": tenant.id,
        "role": user.role.value, "email": user.email,
    })
    refresh_token = create_refresh_token(user.id, tenant.id)
    return TokenResponse(
        access_token=access_token, refresh_token=refresh_token,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user_id=user.id, tenant_id=tenant.id, role=user.role.value,
    )


async def _send_reset_email(to_email: str, name: str, token: str, slug: str):
    """Send password reset email via SMTP. Silently skips if SMTP not configured."""
    if not getattr(settings, 'SMTP_PASSWORD', None):
        return
    url = f"https://app.unifiedsec.com/auth/reset?token={token}&workspace={slug}"
    await _smtp_send(to_email, "Reset your UnifiedSec MACE password",
                     f"Hi {name},\n\nReset your password: {url}\n\nExpires in 2 hours.\n\n— UnifiedSec MACE")


async def _send_verify_email(to_email: str, name: str, token: str, slug: str):
    """Send email verification link."""
    if not getattr(settings, 'SMTP_PASSWORD', None):
        return
    url = f"https://app.unifiedsec.com/auth/verify?token={token}&workspace={slug}"
    await _smtp_send(to_email, "Verify your UnifiedSec MACE email",
                     f"Hi {name},\n\nVerify your email: {url}\n\n— UnifiedSec MACE")


async def _smtp_send(to_email: str, subject: str, body: str):
    """Send via configured SMTP (SendGrid compatible)."""
    try:
        import aiosmtplib
        from email.message import EmailMessage
        msg = EmailMessage()
        msg["From"] = f"UnifiedSec MACE <{settings.EMAILS_FROM}>"
        msg["To"] = to_email
        msg["Subject"] = subject
        msg.set_content(body)
        await aiosmtplib.send(msg, hostname=settings.SMTP_HOST, port=settings.SMTP_PORT,
                               username=settings.SMTP_USER, password=settings.SMTP_PASSWORD,
                               start_tls=True)
    except Exception as e:
        import logging
        logging.getLogger(__name__).error(f"Email to {to_email} failed: {e}")
