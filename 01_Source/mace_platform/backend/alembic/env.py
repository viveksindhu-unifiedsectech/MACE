from logging.config import fileConfig
from sqlalchemy import engine_from_config, pool
from sqlalchemy.ext.asyncio import AsyncEngine
from alembic import context
import asyncio
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.db.base import Base
from app.models import *   # Import all models to register with metadata
from app.core.config import settings

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    url = settings.DATABASE_URL.replace("+asyncpg", "")
    context.configure(url=url, target_metadata=target_metadata,
                      literal_binds=True, dialect_opts={"paramstyle": "named"})
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    from sqlalchemy.ext.asyncio import create_async_engine
    connectable = create_async_engine(settings.DATABASE_URL, poolclass=pool.NullPool)

    async def do_run_migrations():
        async with connectable.connect() as connection:
            await connection.run_sync(do_run_sync)

    def do_run_sync(sync_conn):
        context.configure(connection=sync_conn, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()

    asyncio.run(do_run_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
