"""Database session management for async SQLAlchemy."""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncGenerator

from sqlalchemy import event
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from loguru import logger

from securetransfer.db.models import Base
from securetransfer.config import DB_PATH

# Build async SQLite URL (aiosqlite); use absolute path for reliability
_db_path = Path(DB_PATH).resolve()
DATABASE_URL = f"sqlite+aiosqlite:///{_db_path.as_posix()}"

async_engine = create_async_engine(
    DATABASE_URL,
    echo=False,
)


@event.listens_for(async_engine.sync_engine, "connect")
def _set_sqlite_pragma(dbapi_conn, connection_record):
    """Enable WAL for better concurrent read/write (e.g. server + client in tests)."""
    dbapi_conn.execute("PRAGMA journal_mode=WAL")

AsyncSessionLocal = async_sessionmaker(
    bind=async_engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


async def init_db() -> None:
    """Create all tables in the database."""
    async with async_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database tables created: {}", list(Base.metadata.tables.keys()))


@asynccontextmanager
async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """Async context manager yielding an AsyncSession. Commits on success, rolls back on error."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
