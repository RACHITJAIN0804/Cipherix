from fastapi import APIRouter

from app.core.constants import API_V1_PREFIX
from app.api.routes.auth import router as auth_router
from app.api.routes.document import router as document_router
from app.api.routes.security import router as security_router
from app.api.routes.vault import router as vault_router

api_router = APIRouter(prefix=API_V1_PREFIX)

# ---------------------------------------------------------------------------
# Feature routers
# ---------------------------------------------------------------------------

api_router.include_router(auth_router)
api_router.include_router(vault_router)
api_router.include_router(document_router)
api_router.include_router(security_router)
