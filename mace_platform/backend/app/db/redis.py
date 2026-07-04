"""Redis client — cache, pub/sub, rate limiting."""
import redis.asyncio as aioredis
from app.core.config import settings
from typing import Optional, Any
import json

_redis_client: Optional[aioredis.Redis] = None

async def get_redis() -> aioredis.Redis:
    global _redis_client
    if _redis_client is None:
        _redis_client = await aioredis.from_url(
            settings.REDIS_URL, encoding="utf-8", decode_responses=True
        )
    return _redis_client

class CacheService:
    def __init__(self, redis: aioredis.Redis):
        self.r = redis

    async def get(self, key: str) -> Optional[Any]:
        val = await self.r.get(key)
        return json.loads(val) if val else None

    async def set(self, key: str, value: Any, ttl: int = 300):
        await self.r.setex(key, ttl, json.dumps(value, default=str))

    async def delete(self, key: str):
        await self.r.delete(key)

    async def publish(self, channel: str, message: dict):
        await self.r.publish(channel, json.dumps(message, default=str))

    async def increment(self, key: str, ttl: int = 60) -> int:
        pipe = self.r.pipeline()
        await pipe.incr(key)
        await pipe.expire(key, ttl)
        results = await pipe.execute()
        return results[0]
