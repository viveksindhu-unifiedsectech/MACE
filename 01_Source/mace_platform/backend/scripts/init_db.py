"""
init_db.py — create all tables from the live SQLAlchemy models.

Used by the docker-compose `mace-migrate` service in dev. In production,
use `alembic upgrade head` instead so schema changes are versioned and
reversible.
"""
import asyncio
import logging

from app.db.base import Base, engine
from app import models  # noqa: F401 — register all model classes with Base.metadata

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("init_db")


async def main() -> None:
    log.info("Bootstrapping schema from SQLAlchemy models")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    log.info("Created %d tables", len(Base.metadata.tables))
    for t in sorted(Base.metadata.tables):
        log.info("  · %s", t)
    await engine.dispose()


if __name__ == "__main__":
    asyncio.run(main())
