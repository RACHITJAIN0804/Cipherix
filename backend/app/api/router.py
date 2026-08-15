from fastapi import APIRouter

from app.core.constants import API_V1_PREFIX
from app.api.routes.auth import router as auth_router
from app.api.routes.blockchain import router as blockchain_router
from app.api.routes.computer_access import router as computer_access_router
from app.api.routes.document import router as document_router
from app.api.routes.rag import router as rag_router
from app.api.routes.search import router as search_router
from app.api.routes.security import router as security_router
from app.api.routes.vault import router as vault_router

api_router = APIRouter(prefix=API_V1_PREFIX)

api_router.include_router(auth_router)
api_router.include_router(vault_router)
api_router.include_router(document_router)
api_router.include_router(security_router)
api_router.include_router(search_router, prefix="/search")
api_router.include_router(rag_router, prefix="/rag")
api_router.include_router(computer_access_router)
api_router.include_router(blockchain_router)



