from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.core.config import settings
from app.core.constants import APP_DESCRIPTION, APP_VERSION
from app.core.logger import configure_logging, get_logger
from app.api.router import api_router
from app.database import init_db

configure_logging()
logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    logger.info(
        "Starting %s v%s [env=%s, debug=%s]",
        settings.app_name,
        APP_VERSION,
        settings.app_env,
        settings.debug,
    )

    init_db()

    yield
    logger.info("Shutting down %s. Goodbye.", settings.app_name)


def create_app() -> FastAPI:
    application = FastAPI(
        title=settings.app_name,
        description=APP_DESCRIPTION,
        version=APP_VERSION,
        debug=settings.debug,
        lifespan=lifespan,
        docs_url="/docs" if settings.debug else None,
        redoc_url="/redoc" if settings.debug else None,
    )

    application.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=settings.cors_allow_credentials,
        allow_methods=settings.cors_allow_methods,
        allow_headers=settings.cors_allow_headers,
    )

    @application.exception_handler(Exception)
    async def global_exception_handler(
        request: Request, exc: Exception
    ) -> JSONResponse:
        logger.exception(
            "Unhandled exception on %s %s",
            request.method,
            request.url.path,
        )
        return JSONResponse(
            status_code=500,
            content={"detail": "An internal server error occurred."},
        )

    application.include_router(api_router)

    @application.get("/", tags=["General"])
    async def root() -> dict:
        return {
            "project": settings.app_name,
            "status": "running",
            "version": APP_VERSION,
        }

    @application.get("/health", tags=["General"])
    async def health_check() -> dict:
        return {"status": "healthy"}

    return application


app: FastAPI = create_app()
