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
from fastapi.responses import Response

from app.core.config import settings
from app.core.exceptions import (
    CipherixError,
    VaultCreationError,
    VaultDeletionError,
    VaultManifestError,
    VaultNotFoundError,
    VaultValidationError,
)
from app.core.logger import get_logger
from app.schemas.vault import CreateVaultRequest, VaultResponse, VaultSummary
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


@router.get(
    "/",
    response_model=list[VaultSummary],
    status_code=status.HTTP_200_OK,
    summary="List all vaults",
    description=(
        "Return a summary of every valid vault on disk, sorted by creation "
        "date descending (newest first). Returns an empty list if no vaults "
        "exist. Vaults with malformed or missing manifest.json are silently "
        "skipped and logged server-side."
    ),
    responses={
        200: {"description": "List of vault summaries (may be empty)."},
        500: {"description": "Unexpected server error during vault discovery."},
    },
)
async def list_vaults(
    service: VaultService = Depends(_get_vault_service),
) -> list[VaultSummary]:
    """
    ``GET /vaults`` — list all vaults.

    Returns
    -------
    list[VaultSummary]
        Zero or more vault summaries ordered newest-first.
        An empty list is a valid, non-error response.

    Raises
    ------
    HTTPException(500)
        Only for unexpected server-level failures — not for missing or
        corrupt individual vaults (those are skipped gracefully).
    """
    try:
        vaults = service.list_vaults()
        logger.info("GET /vaults succeeded | count=%d", len(vaults))
        return vaults

    except CipherixError as exc:
        logger.error("Vault listing failed unexpectedly | %s", exc.detail)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=exc.detail,
        ) from exc


@router.delete(
    "/{vault_id}",
    response_model=None,
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Permanently delete a vault",
    description=(
        "Permanently and recursively delete the vault identified by ``vault_id``. "
        "The entire vault directory — including its manifest, encrypted data, "
        "metadata, and temp folders — is removed from disk. "
        "This action is **irreversible**."
    ),
    responses={
        204: {"description": "Vault deleted successfully. No body is returned."},
        400: {"description": "Invalid vault_id format (not a UUID)."},
        404: {"description": "Vault with the given ID does not exist."},
        409: {"description": "Vault exists but has an invalid structure (no manifest.json)."},
        500: {"description": "Filesystem error prevented vault deletion."},
    },
)
async def delete_vault(
    vault_id: str,
    service: VaultService = Depends(_get_vault_service),
) -> Response:
    """
    ``DELETE /vaults/{vault_id}`` — permanently delete a vault.

    Parameters
    ----------
    vault_id:
        UUID4 string that identifies the vault to remove.
    service:
        Injected :class:`~app.services.vault_service.VaultService` instance.

    Returns
    -------
    Response
        HTTP 204 No Content on success.

    Raises
    ------
    HTTPException(400)
        If ``vault_id`` is not a valid UUID.
    HTTPException(404)
        If no vault with that ID exists on disk.
    HTTPException(409)
        If the vault directory exists but lacks ``manifest.json``.
    HTTPException(500)
        If the OS cannot remove the directory tree.
    """
    try:
        service.delete_vault(vault_id)
        logger.info("DELETE /vaults/%s succeeded", vault_id)
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    except VaultValidationError as exc:
        logger.warning("Vault deletion rejected: invalid ID | %s", exc.detail)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=exc.detail,
        ) from exc

    except VaultNotFoundError as exc:
        logger.warning("Vault deletion failed: not found | vault_id=%s", vault_id)
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=exc.detail,
        ) from exc

    except VaultManifestError as exc:
        logger.error(
            "Vault deletion aborted: corrupt structure | vault_id=%s | %s",
            vault_id,
            exc.detail,
        )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=exc.detail,
        ) from exc

    except VaultDeletionError as exc:
        logger.error(
            "Vault deletion failed: OS error | vault_id=%s | %s",
            vault_id,
            exc.detail,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=exc.detail,
        ) from exc

    except CipherixError as exc:
        # Final safety net for any other unforeseen domain error.
        logger.error("Unexpected domain error during deletion | %s", exc.detail)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=exc.detail,
        ) from exc
