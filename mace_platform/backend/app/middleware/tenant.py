"""Request-scoped tenant context — attaches tenant info to request state."""
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi import Request
import time


class RequestTimingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        start = time.perf_counter()
        response = await call_next(request)
        duration = (time.perf_counter() - start) * 1000
        response.headers["X-Response-Time"] = f"{duration:.2f}ms"
        response.headers["X-MACE-Version"] = "2.0.0"
        return response
