from pydantic import BaseModel, EmailStr, field_validator
from typing import Optional
from datetime import datetime


class LoginRequest(BaseModel):
    email: EmailStr
    password: str
    tenant_slug: str

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user_id: str
    tenant_id: str
    role: str

class RefreshRequest(BaseModel):
    refresh_token: str

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    full_name: str
    tenant_name: str
    tenant_slug: str
    jurisdiction: str = "US"

    @field_validator("tenant_slug")
    @classmethod
    def slug_valid(cls, v):
        import re
        if not re.match(r'^[a-z0-9-]{3,50}$', v):
            raise ValueError("Slug must be lowercase letters, numbers, hyphens, 3-50 chars")
        return v

class PasswordResetRequest(BaseModel):
    email: EmailStr

class PasswordResetConfirm(BaseModel):
    token: str
    new_password: str

class MFASetupResponse(BaseModel):
    secret: str
    qr_code_url: str

class MFAVerifyRequest(BaseModel):
    code: str
