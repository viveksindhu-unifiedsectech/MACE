"""
Security headers middleware.

Adds the OWASP-recommended response headers on every API response. The
Content-Security-Policy here is API-safe (no inline scripts/styles allowed);
the SOC and Admin frontends each ship their own CSP via nginx.
"""
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi import Request

from app.core.config import settings


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        # Avoid leaking framework version
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault(
            "Permissions-Policy",
            "accelerometer=(), camera=(), geolocation=(), microphone=(), payment=()",
        )
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
        )
        # HSTS only when not in development (the dev stack runs over plain HTTP)
        if settings.ENVIRONMENT not in ("development", "test"):
            response.headers.setdefault(
                "Strict-Transport-Security",
                "max-age=31536000; includeSubDomains; preload",
            )
        return response
