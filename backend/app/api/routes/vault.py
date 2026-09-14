from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import Response
from sqlalchemy.orm import Session

from app.api.dependencies import get_current_user, get_db, get_user_vault
from app.core.config import settings
from app.core.exceptions import (
    CipherixError,
    VaultCreationError,
    VaultDeletionError,
    VaultManifestError,
    VaultNotFoundError,
    VaultStateError,
    VaultValidationError,
)
from app.core.logger import get_logger
from app.database.models import User, Vault
from app.schemas.vault import (
    CreateVaultRequest,
    VaultResponse,
    VaultStateResponse,
    VaultSummary,
)
from app.services.vault_service import VaultService
from app.vault.vault_manager import VaultManager

logger = get_logger(__name__)

router = APIRouter(
    prefix="/vaults",
    tags=["Vaults"],
)


def _get_vault_service() -> VaultService:
    manager = VaultManager(vault_base_dir=settings.VAULT_DIR)
    return VaultService(manager=manager)


def _handle_state_transition(
    action: str,
    vault_id: str,
    result: VaultStateResponse,
) -> VaultStateResponse:
    logger.info("POST /vaults/%s/%s succeeded", vault_id, action)
    return result


def _map_state_exception(
    action: str,
    vault_id: str,
    exc: Exception,
) -> None:
    if isinstance(exc, VaultValidationError):
        logger.warning(
            "%s rejected: invalid vault_id | vault_id=%s | %s",
            action.capitalize(),
            vault_id,
            exc.detail,
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=exc.detail,
        ) from exc

    if isinstance(exc, VaultNotFoundError):
        logger.warning(
            "%s failed: vault not found | vault_id=%s", action.capitalize(), vault_id
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=exc.detail,
        ) from exc

    if isinstance(exc, VaultStateError):
        logger.warning(
            "%s rejected: vault already %sed | vault_id=%s",
            action.capitalize(),
            action,
            vault_id,
        )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=exc.detail,
        ) from exc

    if isinstance(exc, VaultManifestError):
        logger.error(
            "%s failed: manifest error | vault_id=%s | %s",
            action.capitalize(),
            vault_id,
            exc.detail,
        )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=exc.detail,
        ) from exc

    if isinstance(exc, CipherixError):
        logger.error(
            "Unexpected domain error during %s | %s", action, exc.detail
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=exc.detail,
        ) from exc

    raise exc


@router.post(
    "",
    response_model=VaultResponse,
    status_code=status.HTTP_201_CREATED,
    include_in_schema=False,
)
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
        401: {"description": "Missing, expired, or invalid JWT token."},
        500: {"description": "Unexpected server error during vault creation."},
    },
)
async def create_vault(
    request: CreateVaultRequest,
    current_user: User = Depends(get_current_user),
    service: VaultService = Depends(_get_vault_service),
    db: Session = Depends(get_db),
) -> VaultResponse:
    try:
        response = service.create_vault(request, user_id=current_user.id, db=db)
        logger.info("POST /vaults succeeded | vault_id=%s | user_id=%s", response.vault_id, current_user.id)
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
        logger.error("Unexpected domain error | %s", exc.detail)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=exc.detail,
        ) from exc


@router.get(
    "",
    response_model=list[VaultSummary],
    status_code=status.HTTP_200_OK,
    include_in_schema=False,
)
@router.get(
    "/",
    response_model=list[VaultSummary],
    status_code=status.HTTP_200_OK,
    summary="List all vaults",
    description=(
        "Return a summary of every valid vault on disk belonging to the "
        "authenticated user, sorted by creation date descending (newest first). "
        "Returns an empty list if no vaults exist for this user."
    ),
    responses={
        200: {"description": "List of vault summaries (may be empty)."},
        401: {"description": "Missing, expired, or invalid JWT token."},
        500: {"description": "Unexpected server error during vault discovery."},
    },
)
async def list_vaults(
    current_user: User = Depends(get_current_user),
    service: VaultService = Depends(_get_vault_service),
    db: Session = Depends(get_db),
) -> list[VaultSummary]:
    try:
        vaults = service.list_vaults(user_id=current_user.id, db=db)
        logger.info("GET /vaults succeeded | count=%d | user_id=%s", len(vaults), current_user.id)
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
        "This action is **irreversible**."
    ),
    responses={
        204: {"description": "Vault deleted successfully. No body is returned."},
        400: {"description": "Invalid vault_id format (not a UUID)."},
        401: {"description": "Missing, expired, or invalid JWT token."},
        404: {"description": "Vault with the given ID does not exist or is not owned."},
        500: {"description": "Filesystem error prevented vault deletion."},
    },
)
async def delete_vault(
    vault_id: str,
    vault: Vault = Depends(get_user_vault),
    service: VaultService = Depends(_get_vault_service),
    db: Session = Depends(get_db),
) -> Response:
    try:
        service.delete_vault(vault.id, db=db)
        logger.info("DELETE /vaults/%s succeeded", vault.id)
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    except VaultValidationError as exc:
        logger.warning("Vault deletion rejected: invalid ID | %s", exc.detail)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=exc.detail,
        ) from exc

    except VaultNotFoundError as exc:
        logger.warning("Vault deletion failed: not found | vault_id=%s", vault.id)
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=exc.detail,
        ) from exc

    except VaultManifestError as exc:
        logger.error(
            "Vault deletion aborted: corrupt structure | vault_id=%s | %s",
            vault.id,
            exc.detail,
        )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=exc.detail,
        ) from exc

    except VaultDeletionError as exc:
        logger.error(
            "Vault deletion failed: OS error | vault_id=%s | %s",
            vault.id,
            exc.detail,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=exc.detail,
        ) from exc

    except CipherixError as exc:
        logger.error("Unexpected domain error during deletion | %s", exc.detail)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=exc.detail,
        ) from exc


@router.post(
    "/{vault_id}/lock",
    response_model=VaultStateResponse,
    status_code=status.HTTP_200_OK,
    summary="Lock a vault",
    description=(
        "Transition the vault identified by ``vault_id`` to the ``locked`` state."
    ),
    responses={
        200: {"description": "Vault is now locked."},
        400: {"description": "Invalid vault_id format (not a UUID)."},
        401: {"description": "Missing, expired, or invalid JWT token."},
        404: {"description": "Vault with the given ID does not exist or is not owned."},
        409: {"description": "Vault is already locked, or has an invalid structure."},
        500: {"description": "Filesystem error prevented the status update."},
    },
)
async def lock_vault(
    vault_id: str,
    vault: Vault = Depends(get_user_vault),
    service: VaultService = Depends(_get_vault_service),
    db: Session = Depends(get_db),
) -> VaultStateResponse:
    try:
        return _handle_state_transition(
            "lock", vault.id, service.lock_vault(vault.id, db=db)
        )
    except Exception as exc:  # noqa: BLE001
        _map_state_exception("lock", vault.id, exc)


@router.post(
    "/{vault_id}/unlock",
    response_model=VaultStateResponse,
    status_code=status.HTTP_200_OK,
    summary="Unlock a vault",
    description=(
        "Transition the vault identified by ``vault_id`` to the ``unlocked`` state."
    ),
    responses={
        200: {"description": "Vault is now unlocked."},
        400: {"description": "Invalid vault_id format (not a UUID)."},
        401: {"description": "Missing, expired, or invalid JWT token."},
        404: {"description": "Vault with the given ID does not exist or is not owned."},
        409: {"description": "Vault is already unlocked, or has an invalid structure."},
        500: {"description": "Filesystem error prevented the status update."},
    },
)
async def unlock_vault(
    vault_id: str,
    vault: Vault = Depends(get_user_vault),
    service: VaultService = Depends(_get_vault_service),
    db: Session = Depends(get_db),
) -> VaultStateResponse:
    try:
        return _handle_state_transition(
            "unlock", vault.id, service.unlock_vault(vault.id, db=db)
        )
    except Exception as exc:  # noqa: BLE001
        _map_state_exception("unlock", vault.id, exc)
