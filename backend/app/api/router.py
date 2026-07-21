"""
api/router.py
-------------
Top-level API router that aggregates all route sub-modules.

Every feature area (vaults, auth, files, …) exposes its own
``APIRouter`` in ``api/routes/<feature>.py`` and is *included* here
under the shared ``/api/v1`` prefix.

Adding a new feature
--------------------
1. Create ``api/routes/<feature>.py`` and define a ``router``.
2. Import that router below and call ``api_router.include_router()``.

This file should never contain endpoint logic — only routing wiring.
"""

from fastapi import APIRouter

from app.core.constants import API_V1_PREFIX
from app.api.routes.vault import router as vault_router

api_router = APIRouter(prefix=API_V1_PREFIX)

# ---------------------------------------------------------------------------
# Feature routers
# ---------------------------------------------------------------------------

api_router.include_router(vault_router)
