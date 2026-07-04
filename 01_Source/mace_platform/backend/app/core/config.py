"""
UnifiedSec MACE Platform — Core Configuration
Supports: US (AWS us-east-1 + GovCloud), UAE (me-central-1), EU (Azure), India (ap-south-1)
"""
from pydantic_settings import BaseSettings
from pydantic import field_validator
from typing import List, Optional
from functools import lru_cache
import os
import secrets


class Settings(BaseSettings):
    # ── App ────────────────────────────────────────────────────
    APP_NAME: str = "UnifiedSec MACE Platform"
    APP_VERSION: str = "2.0.0"
    API_V1_PREFIX: str = "/api/v1"
    DEBUG: bool = False
    ENVIRONMENT: str = "production"      # development | staging | production

    # ── Security ───────────────────────────────────────────────
    # SECRET_KEY MUST be set via env in production. In dev/test we synthesize
    # one for ergonomics but fail loud if production mode launches without it.
    SECRET_KEY: str = ""
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    REFRESH_TOKEN_EXPIRE_DAYS: int = 30
    API_KEY_PREFIX: str = "mace_"

    @field_validator("SECRET_KEY", mode="before")
    @classmethod
    def _validate_secret_key(cls, v, info):
        env_mode = (
            (info.data or {}).get("ENVIRONMENT")
            or os.environ.get("ENVIRONMENT", "production")
        )
        if not v:
            if env_mode in ("development", "test"):
                return secrets.token_urlsafe(64)
            raise ValueError(
                "SECRET_KEY env var is required in production. "
                "Generate one with: python -c "
                "'import secrets; print(secrets.token_urlsafe(64))'"
            )
        if len(v) < 32:
            raise ValueError(
                "SECRET_KEY must be at least 32 characters "
                "(use 64+ for production)."
            )
        return v

    # ── Database ───────────────────────────────────────────────
    DATABASE_URL: str = "postgresql+asyncpg://mace:mace@localhost:5432/mace_platform"
    DATABASE_POOL_SIZE: int = 20
    DATABASE_MAX_OVERFLOW: int = 40

    # ── Redis ──────────────────────────────────────────────────
    REDIS_URL: str = "redis://localhost:6379/0"
    REDIS_CACHE_TTL: int = 300           # seconds

    # ── Celery ─────────────────────────────────────────────────
    CELERY_BROKER_URL: str = "redis://localhost:6379/1"
    CELERY_RESULT_BACKEND: str = "redis://localhost:6379/2"

    # ── CORS ───────────────────────────────────────────────────
    ALLOWED_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://localhost:3001",
        "https://app.unifiedsec.com",
        "https://admin.unifiedsec.com",
        "https://soc.unifiedsec.com",
    ]

    # ── OAuth2 / SSO ───────────────────────────────────────────
    GOOGLE_CLIENT_ID: Optional[str] = None
    GOOGLE_CLIENT_SECRET: Optional[str] = None
    MICROSOFT_CLIENT_ID: Optional[str] = None
    MICROSOFT_CLIENT_SECRET: Optional[str] = None
    OKTA_DOMAIN: Optional[str] = None
    OKTA_CLIENT_ID: Optional[str] = None

    # ── Stripe Billing ─────────────────────────────────────────
    STRIPE_SECRET_KEY: Optional[str] = None
    STRIPE_WEBHOOK_SECRET: Optional[str] = None
    STRIPE_PRICE_ID_STARTER: Optional[str] = None
    STRIPE_PRICE_ID_PROFESSIONAL: Optional[str] = None
    STRIPE_PRICE_ID_ENTERPRISE: Optional[str] = None

    # ── Email ──────────────────────────────────────────────────
    SMTP_HOST: str = "smtp.sendgrid.net"
    SMTP_PORT: int = 587
    SMTP_USER: str = "apikey"
    SMTP_PASSWORD: Optional[str] = None
    EMAILS_FROM: str = "noreply@unifiedsec.com"
    EMAILS_FROM_NAME: str = "UnifiedSec MACE"

    # ── Storage (S3-compatible) ─────────────────────────────────
    S3_BUCKET: Optional[str] = None
    S3_REGION: str = "us-east-1"
    AWS_ACCESS_KEY_ID: Optional[str] = None
    AWS_SECRET_ACCESS_KEY: Optional[str] = None

    # ── Secure Files (envelope encryption + AI guard) ───────────
    # KMS wraps every per-file data key in production; local HKDF wrapping is
    # used automatically when KMS is disabled (dev / demo / CI).
    MACE_KMS_ENABLED: bool = False
    MACE_KMS_KEY_ID: Optional[str] = None          # arn:aws:kms:... or alias/mace
    MACE_FILE_STORE: str = "/tmp/mace-secure-files" # local backend root (dev/demo)
    MACE_REDACT_BY_DEFAULT: bool = False
    ANTHROPIC_API_KEY: Optional[str] = None         # enables the AI-guard LLM pass
    MACE_AI_GUARD_MODEL: str = "claude-sonnet-4-6"

    # ── Elasticsearch / Kibana (encrypted-file audit search) ────
    ELASTIC_ENABLED: bool = False
    ELASTIC_URL: str = "http://localhost:9200"
    ELASTIC_AUDIT_INDEX: str = "mace-secure-file-audit"

    # ── Multi-Region Deployment ─────────────────────────────────
    # US → AWS us-east-1 (primary) + us-gov-west-1 (FedRAMP)
    # UAE → AWS me-central-1 or Azure UAE North
    # EU  → Azure West Europe (GDPR data residency)
    # India → AWS ap-south-1 or NIC Cloud (DPDP data residency)
    DEPLOYMENT_REGION: str = "us-east-1"
    DATA_RESIDENCY_JURISDICTION: str = "US"   # US | AE | EU | IN

    # ── MACE Engine ────────────────────────────────────────────
    MACE_DEFAULT_WEIGHT_PROFILE: str = "usa_fedramp"
    MACE_CDCS_ALERT_THRESHOLD: float = 7.0
    MACE_REA_CDCS_THRESHOLD: float = 6.5
    MACE_MATCH_THRESHOLD: float = 0.38

    # ── Connectors ─────────────────────────────────────────────
    CROWDSTRIKE_BASE_URL: str = "https://api.crowdstrike.com"
    TENABLE_BASE_URL: str = "https://cloud.tenable.com"
    SPLUNK_BASE_URL: Optional[str] = None
    MISP_BASE_URL: Optional[str] = None

    # ── Rate Limiting ──────────────────────────────────────────
    RATE_LIMIT_PER_MINUTE: int = 600
    RATE_LIMIT_BURST: int = 100

    # ── Websockets ─────────────────────────────────────────────
    WS_HEARTBEAT_INTERVAL: int = 30   # seconds

    class Config:
        env_file = ".env"
        case_sensitive = True


@lru_cache()
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
