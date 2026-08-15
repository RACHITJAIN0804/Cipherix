"""
database/database.py
--------------------
SQLAlchemy engine, session factory, and FastAPI dependency for Cipherix.

Architecture
------------
* A single synchronous :class:`~sqlalchemy.engine.Engine` is created once
  at module import time, using the ``DATABASE_URL`` from settings.
* ``SessionLocal`` is a session factory; every request obtains its own
  session via the ``get_db()`` FastAPI dependency.
* ``check_same_thread=False`` is required for SQLite when the session is
  shared across threads (FastAPI runs handlers in a thread pool).

Why synchronous?
    The existing service layer (VaultService, DocumentService,
    SecurityService) is fully synchronous.  Introducing async sessions
    here would require converting all services to async, which is a
    larger refactor outside the scope of this task.  The synchronous
    SQLAlchemy session is correct and safe with FastAPI's thread pool.

Database path
    The database file lives at ``DATABASE_DIR / database_filename``
    (resolved via settings).  The parent directory is created at startup
    if it does not exist.
"""

from collections.abc import Generator
from pathlib import Path

from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import settings
from app.core.logger import get_logger

logger = get_logger(__name__)



def _create_engine():
    """
    Build the SQLAlchemy engine for the configured SQLite database.

    SQLite-specific settings:
    * ``check_same_thread=False`` — allows the engine to be used from
      FastAPI's thread pool (multiple threads, same process).
    * WAL journal mode — Write-Ahead Logging gives better concurrency for
      concurrent readers + a single writer.  Enabled via a ``connect``
      event so it is set for every new connection.
    * Foreign-key enforcement — SQLite does not enforce FK constraints by
      default; the ``PRAGMA foreign_keys = ON`` call activates them so
      CASCADE DELETE works as expected.
    """
    db_path = Path(settings.DATABASE_DIR)
    db_path.mkdir(parents=True, exist_ok=True)

    engine = create_engine(
        settings.database_url,
        connect_args={"check_same_thread": False},
        # Echo SQL only in debug mode — avoids leaking SQL to production logs.
        echo=settings.debug,
    )

    # Activate WAL mode and FK enforcement on every new connection.
    @event.listens_for(engine, "connect")
    def _set_sqlite_pragmas(dbapi_connection, connection_record) -> None:  # noqa: ANN001
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    logger.debug("SQLAlchemy engine created | url=%s", settings.database_url)
    return engine


engine = _create_engine()


SessionLocal: sessionmaker[Session] = sessionmaker(
    bind=engine,
    autocommit=False,
    autoflush=False,
    expire_on_commit=False,
)



def get_db() -> Generator[Session, None, None]:
    """
    FastAPI dependency that yields a database session per request.

    Usage in a route
    ----------------
    ::

        from fastapi import Depends
        from sqlalchemy.orm import Session
        from app.database.database import get_db

        @router.post("/vaults/")
        def create_vault(db: Session = Depends(get_db)):
            ...

    The session is committed or rolled back by the service layer.  This
    dependency ensures the session is **always closed** after the request
    completes, even if an exception is raised.
    """
    db: Session = SessionLocal()
    try:
        yield db
    finally:
        db.close()



def init_db() -> None:
    """
    Create all tables defined in the ORM models if they do not exist.

    This is a **safety net** for development and tests.  In production,
    Alembic migrations are the canonical way to create and evolve the
    schema.  Running ``init_db()`` on a database that already has the
    correct schema is a no-op.

    Call this from the FastAPI ``lifespan`` startup hook.
    """
    # Import models here to ensure their table metadata is registered
    # on ``Base.metadata`` before ``create_all`` is called.
    from app.database.models import Base  # noqa: F401 — side-effect import

    Base.metadata.create_all(bind=engine)
    logger.info(
        "Database initialised | tables=%s",
        list(Base.metadata.tables.keys()),
    )
