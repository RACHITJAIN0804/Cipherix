"""
main.py
-------
FastAPI application factory for Cipherix.

This module is the single entry point that:
* Calls ``configure_logging()`` before anything else.
* Creates the :class:`FastAPI` application instance.
* Registers CORS middleware (configurable from .env).
* Registers startup / shutdown lifecycle handlers.
* Mounts the global exception handler.
* Declares the root (``GET /``) and health (``GET /health``) endpoints.

Run the server
--------------
    uvicorn app.main:app --reload
"""

from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.core.config import settings
from app.core.constants import APP_DESCRIPTION, APP_VERSION
from app.core.logger import configure_logging, get_logger
from app.api.router import api_router

# ---------------------------------------------------------------------------
# Bootstrap logging before anything else so that all subsequent imports
# (including FastAPI internals) already have handlers attached.
# ---------------------------------------------------------------------------

configure_logging()
logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Lifespan – startup & shutdown events
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """
    Manage application lifecycle.

    Everything *before* ``yield`` runs at startup;
    everything *after* ``yield`` runs at shutdown.
    """
    # ---- Startup ----
    logger.info(
        "Starting %s v%s [env=%s, debug=%s]",
        settings.app_name,
        APP_VERSION,
        settings.app_env,
        settings.debug,
    )
    yield
    # ---- Shutdown ----
    logger.info("Shutting down %s. Goodbye.", settings.app_name)


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------


def create_app() -> FastAPI:
    """
    Construct and configure the FastAPI application.

    Keeping the factory in its own function makes the app trivially
    testable — tests can call ``create_app()`` without importing a
    module-level singleton.

    Returns
    -------
    FastAPI
        A fully configured application instance.
    """
    application = FastAPI(
        title=settings.app_name,
        description=APP_DESCRIPTION,
        version=APP_VERSION,
        debug=settings.debug,
        lifespan=lifespan,
        # Disable default /docs and /redoc in production for security
        docs_url="/docs" if settings.debug else None,
        redoc_url="/redoc" if settings.debug else None,
    )

    # ----------------------------------------------------------------
    # CORS middleware
    # ----------------------------------------------------------------

    application.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=settings.cors_allow_credentials,
        allow_methods=settings.cors_allow_methods,
        allow_headers=settings.cors_allow_headers,
    )

    # ----------------------------------------------------------------
    # Global exception handler
    # ----------------------------------------------------------------

    @application.exception_handler(Exception)
    async def global_exception_handler(
        request: Request, exc: Exception
    ) -> JSONResponse:
        """
        Catch-all handler for any unhandled exception.

        Returns a generic 500 response to the client while logging the
        full traceback server-side.  This prevents internal stack traces
        from leaking to API consumers.
        """
        logger.exception(
            "Unhandled exception on %s %s",
            request.method,
            request.url.path,
        )
        return JSONResponse(
            status_code=500,
            content={"detail": "An internal server error occurred."},
        )

    # ----------------------------------------------------------------
    # Feature routers
    # ----------------------------------------------------------------

    application.include_router(api_router)

    # ----------------------------------------------------------------
    # Routes
    # ----------------------------------------------------------------

    @application.get("/", tags=["General"])
    async def root() -> dict:
        """
        Project identity endpoint.

        Returns
        -------
        dict
            Basic metadata confirming the service is alive.
        """
        return {
            "project": settings.app_name,
            "status": "running",
            "version": APP_VERSION,
        }

    @application.get("/health", tags=["General"])
    async def health_check() -> dict:
        """
        Health-check endpoint for load-balancers and uptime monitors.

        Returns
        -------
        dict
            ``{"status": "healthy"}`` when the application is ready to
            serve traffic.
        """
        return {"status": "healthy"}

    return application


# ---------------------------------------------------------------------------
# Module-level app instance (used by uvicorn: ``app.main:app``)
# ---------------------------------------------------------------------------

app: FastAPI = create_app()
