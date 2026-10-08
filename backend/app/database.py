"""SQLite persistence layer using SQLModel."""
from __future__ import annotations

from collections.abc import Iterator

from sqlmodel import Session, SQLModel, create_engine, text

from .config import settings

connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
engine = create_engine(settings.database_url, echo=False, connect_args=connect_args)


def init_db() -> None:
    """Create all tables. Import models so metadata is populated."""
    from . import models  # noqa: F401  (ensures models are registered)
    import sqlite3

    SQLModel.metadata.create_all(engine)
    
    # Safe, idempotent migration to add `source` column to existing persistent DB
    if settings.database_url.startswith("sqlite"):
        with engine.connect() as conn:
            try:
                conn.execute(text("ALTER TABLE events ADD COLUMN source VARCHAR DEFAULT 'demo'"))
            except Exception as e:
                pass # Usually OperationalError: duplicate column name
            try:
                conn.execute(text("ALTER TABLE incidents ADD COLUMN source VARCHAR DEFAULT 'demo'"))
            except Exception as e:
                pass
            conn.commit()


def get_session() -> Iterator[Session]:
    with Session(engine) as session:
        yield session
