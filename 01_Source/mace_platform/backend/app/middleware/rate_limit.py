"""Rate limiting middleware using Redis sliding window."""
from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from app.db.redis import get_redis, CacheService
from app.core.config import settings


class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Skip health check
        if request.url.path in ["/health", "/metrics"]:
            return await call_next(request)

        # Get client key (IP or API key prefix)
        client_ip = request.client.host if request.client else "unknown"
        api_key = request.headers.get("X-API-Key", "")
        key = f"rl:{api_key[:20] if api_key else client_ip}"

        try:
            redis = await get_redis()
            cache = CacheService(redis)
            count = await cache.increment(key, ttl=60)
            if count > settings.RATE_LIMIT_PER_MINUTE:
                raise HTTPException(429, "Rate limit exceeded. Reduce your request frequency.")
        except HTTPException:
            raise
        except Exception:
            pass  # Redis unavailable — fail open

        return await call_next(request)
