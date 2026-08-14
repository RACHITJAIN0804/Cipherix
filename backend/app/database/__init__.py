"""
database/__init__.py
--------------------
Public re-exports for the database package.

Import from here rather than from the submodules directly so that call
sites are decoupled from the internal module layout.

Usage
-----
::

    from app.database import Base, get_db, SessionLocal, engine, init_db
"""

from app.database.database import SessionLocal, engine, get_db, init_db
from app.database.models import Base, Document, SecurityMetadata, User, Vault

__all__ = [
    "Base",
    "Document",
    "SecurityMetadata",
    "SessionLocal",
    "User",
    "Vault",
    "engine",
    "get_db",
    "init_db",
]
