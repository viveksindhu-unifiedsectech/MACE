"""FastAPI dependency injection for auth — get_current_user, require_role, get_tenant."""
from fastapi import Depends, HTTPException, status, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials, APIKeyHeader
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.db.base import get_db
from app.auth.jwt import decode_token
from app.models.user import User, UserRole
from app.models.tenant import Tenant
from app.models.user import APIKey as APIKeyModel
from typing import Optional
import hashlib

bearer = HTTPBearer(auto_error=False)
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

class CurrentUser:
    def __init__(self, user: User, tenant: Tenant):
        self.user = user
        self.tenant = tenant
        self.id = user.id
        self.tenant_id = user.tenant_id
        self.role = user.role
        self.email = user.email

async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(bearer),
    api_key: Optional[str] = Security(api_key_header),
    db: AsyncSession = Depends(get_db),
) -> CurrentUser:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    # Try Bearer JWT first
    if credentials:
        payload = decode_token(credentials.credentials)
        if not payload:
            raise credentials_exception
        user_id = payload.get("sub")
        tenant_id = payload.get("tenant_id")
        if not user_id or not tenant_id:
            raise credentials_exception

        user = await db.get(User, user_id)
        if not user or not user.is_active:
            raise credentials_exception
        tenant = await db.get(Tenant, tenant_id)
        if not tenant or not tenant.is_active:
            raise credentials_exception
        return CurrentUser(user=user, tenant=tenant)

    # Try API key
    if api_key:
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        result = await db.execute(
            select(APIKeyModel).where(APIKeyModel.key_hash == key_hash, APIKeyModel.is_active == True)
        )
        api_key_record = result.scalar_one_or_none()
        if not api_key_record:
            raise credentials_exception
        user = await db.get(User, api_key_record.user_id)
        tenant = await db.get(Tenant, api_key_record.tenant_id)
        if not user or not tenant:
            raise credentials_exception
        return CurrentUser(user=user, tenant=tenant)

    raise credentials_exception

def require_role(*roles: UserRole):
    """Decorator dependency — requires user to have one of the given roles."""
    async def _check(current: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        if current.role == UserRole.SUPER_ADMIN:
            return current  # super admin bypasses role checks
        if current.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Required role: {[r.value for r in roles]}"
            )
        return current
    return _check

# Common shorthand dependencies
get_analyst = require_role(UserRole.TENANT_ADMIN, UserRole.SOC_ANALYST)
get_admin   = require_role(UserRole.TENANT_ADMIN)
get_any     = require_role(UserRole.TENANT_ADMIN, UserRole.SOC_ANALYST, UserRole.READ_ONLY, UserRole.API_USER)
