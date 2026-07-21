"""
api/routes/vault.py
-------------------
FastAPI route handlers for vault-related endpoints.

This module is intentionally thin.  Each handler:

1. Receives and validates the request (Pydantic does the heavy lifting).
2. Delegates to :class:`~app.services.vault_service.VaultService`.
3. Maps domain exceptions to appropriate HTTP responses.
4. Returns the response model.

No business logic, no filesystem code, no UUID generation lives here.

Dependency wiring
-----------------
``_get_vault_service()`` is a FastAPI dependency that constructs the
full object graph (VaultManager → VaultService) on every request.
This is intentionally simple for now; once the project grows, this
can be replaced with a proper DI container or a singleton pattern
for the manager.
"""

from fastapi import APIRouter, Depends, HTTPException, status

from app.core.config import settings
from app.core.exceptions import CipherixError, VaultCreationError, VaultValidationError
from app.core.logger import get_logger
from app.schemas.vault import CreateVaultRequest, VaultResponse
from app.services.vault_service import VaultService
from app.vault.vault_manager import VaultManager

logger = get_logger(__name__)

router = APIRouter(
    prefix="/vaults",
    tags=["Vaults"],
)


# ---------------------------------------------------------------------------
# Dependency
# ---------------------------------------------------------------------------


def _get_vault_service() -> VaultService:
    """
    FastAPI dependency that wires together the VaultManager and VaultService.

    Constructing the object graph here (rather than at module import time)
    means:

    * Each request gets a fresh service instance, avoiding shared state.
    * Tests can override this dependency with ``app.dependency_overrides``.
    * The vault base directory is read from ``settings`` at request time,
      respecting any runtime configuration changes.
    """
    manager = VaultManager(vault_base_dir=settings.VAULT_DIR)
    return VaultService(manager=manager)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post(
    "/",
    response_model=VaultResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new vault",
    description=(
        "Scaffold a new vault on disk with a UUID4 identifier. "
        "The vault name is stored in the manifest but is never used as a "
        "filesystem path."
    ),
    responses={
        201: {"description": "Vault created successfully."},
        400: {"description": "Invalid request payload or business-rule violation."},
        500: {"description": "Unexpected server error during vault creation."},
    },
)
async def create_vault(
    request: CreateVaultRequest,
    service: VaultService = Depends(_get_vault_service),
) -> VaultResponse:
    """
    ``POST /vaults`` — create a new vault.

    Parameters
    ----------
    request:
        Pydantic-validated vault creation payload.
    service:
        Injected :class:`~app.services.vault_service.VaultService` instance.

    Returns
    -------
    VaultResponse
        Metadata of the newly created vault, with HTTP 201.

    Raises
    ------
    HTTPException(400)
        For validation failures or business-rule violations.
    HTTPException(500)
        For unexpected filesystem or server errors.
    """
    try:
        response = service.create_vault(request)
        logger.info("POST /vaults succeeded | vault_id=%s", response.vault_id)
        return response

    except VaultValidationError as exc:
        logger.warning("Vault creation rejected | %s", exc.detail)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=exc.detail,
        ) from exc

    except VaultCreationError as exc:
        logger.error("Vault creation failed | %s", exc.detail)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=exc.detail,
        ) from exc

    except CipherixError as exc:
        # Catch-all for any other domain error not handled above.
        logger.error("Unexpected domain error | %s", exc.detail)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=exc.detail,
        ) from exc
