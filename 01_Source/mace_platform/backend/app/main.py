"""
UnifiedSec MACE Platform — FastAPI Application Entry Point
==========================================================
Patent: IN/2026/UNISEC/MACE-001 + PCT → US / CA / EU / UAE

Multi-region deployment:
  US Primary:   AWS us-east-1   (EKS)
  US GovCloud:  AWS us-gov-west-1 (FedRAMP FIPS 140-2)
  UAE:          AWS me-central-1 / Azure UAE North
  EU:           Azure West Europe (GDPR data residency)
  India:        AWS ap-south-1 / NIC Cloud (DPDP data residency)
"""
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from contextlib import asynccontextmanager
import logging
import time

from app.core.config import settings
from app.api.v1 import api_router
from app.db.base import engine, Base
from app.middleware.rate_limit import RateLimitMiddleware
from app.middleware.tenant import RequestTimingMiddleware
from app.middleware.security_headers import SecurityHeadersMiddleware

logging.basicConfig(
    level=logging.DEBUG if settings.DEBUG else logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup / shutdown lifecycle."""
    logger.info(f"🚀 UnifiedSec MACE Platform v{settings.APP_VERSION} starting")
    logger.info(f"   Environment:  {settings.ENVIRONMENT}")
    logger.info(f"   Region:       {settings.DEPLOYMENT_REGION}")
    logger.info(f"   Jurisdiction: {settings.DATA_RESIDENCY_JURISDICTION}")

    # In production, schema is managed by Alembic migrations only.
    # In dev/test we permit create_all as a convenience.
    if settings.ENVIRONMENT in ("development", "test"):
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        logger.info("✅ Database tables created/verified (dev mode)")
    else:
        logger.info("ℹ️  Production mode — run `alembic upgrade head` for schema changes")

    yield

    logger.info("🛑 MACE Platform shutting down")
    await engine.dispose()


app = FastAPI(
    title="UnifiedSec MACE Platform API",
    description="""
## UnifiedSec MACE v2 — Multi-Domain Adaptive Correlation Engine

**Patent:** IN/2026/UNISEC/MACE-001 + PCT → US / CA / EU / UAE

### Three-component pipeline:
1. **UTAG** — Universal Temporal Asset Graph (probabilistic asset identity)
2. **CDCS v2** — Cross-Domain Correlation Score (6-domain pre-alert scoring)
3. **UREA** — Universal Regulatory Evidence Automaton (22 frameworks, 5 jurisdictions)

### Markets:
- 🇺🇸 **USA** — AWS us-east-1 + GovCloud (FedRAMP FIPS 140-2)
- 🇦🇪 **UAE** — AWS me-central-1 / Azure UAE North (NESA IAS 2023)
- 🇪🇺 **EU** — Azure West Europe (GDPR Art.33, NIS2, DORA)
- 🇮🇳 **India** — AWS ap-south-1 / NIC Cloud (CERT-In 6h, DPDP 72h)
- 🇨🇦 **Canada** — AWS ca-central-1 (PIPEDA, OSFI B-13)
""",
    version=settings.APP_VERSION,
    docs_url="/docs" if settings.DEBUG else None,
    redoc_url="/redoc" if settings.DEBUG else None,
    lifespan=lifespan,
)

# ── Middleware (order matters — outermost runs first) ───────────────
app.add_middleware(GZipMiddleware, minimum_size=1000)
app.add_middleware(CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["X-Response-Time", "X-MACE-Version", "X-Request-ID"],
)
app.add_middleware(RateLimitMiddleware)
app.add_middleware(RequestTimingMiddleware)
app.add_middleware(SecurityHeadersMiddleware)


# ── Exception handlers ──────────────────────────────────────────────
@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": exc.errors(), "body": str(exc.body)[:500] if exc.body else None},
    )

@app.exception_handler(Exception)
async def global_error_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Internal server error. Our team has been notified."},
    )


# ── Routes ─────────────────────────────────────────────────────────
app.include_router(api_router, prefix=settings.API_V1_PREFIX)


@app.get("/health", tags=["Health"])
async def health():
    return {
        "status": "ok",
        "engine": "MACE v2",
        "version": settings.APP_VERSION,
        "environment": settings.ENVIRONMENT,
        "region": settings.DEPLOYMENT_REGION,
        "jurisdiction": settings.DATA_RESIDENCY_JURISDICTION,
        "patent": "IN/2026/UNISEC/MACE-001",
        "timestamp": time.time(),
    }


@app.get("/metrics", tags=["Health"])
async def metrics():
    """Prometheus-compatible metrics endpoint."""
    return {"mace_platform_up": 1, "version": settings.APP_VERSION}
