"""
api/routes/security.py
-----------------------
FastAPI route handlers for vault security operations.

Each handler follows the project pattern:

1. Extract and forward request data to :class:`~app.services.security_service.SecurityService`.
2. Map domain exceptions to HTTP status codes.
3. Return the appropriate response.

No business logic, no filesystem code, and no cryptography belongs here.

Password handling
-----------------
Passwords are supplied as JSON body fields.  They are forwarded immediately
to the service layer and are never logged, never stored, and never echoed
in any response.
"""

from fastapi import APIRouter, Depends, HTTPException, status

from app.core.config import settings
from app.core.exceptions import (
    CipherixError,
    InvalidPasswordError,
    PasswordChangeError,
    VaultLockedError,
    VaultNotFoundError,
)
from app.core.logger import get_logger
from app.schemas.security import ChangePasswordRequest, ChangePasswordResponse
from app.services.security_service import SecurityService

logger = get_logger(__name__)

router = APIRouter(
    prefix="/vaults",
    tags=["Security"],
)


# ---------------------------------------------------------------------------
# Dependency
# ---------------------------------------------------------------------------


def _get_security_service() -> SecurityService:
    """
    FastAPI dependency that constructs :class:`SecurityService` per request.

    Reading ``settings.VAULT_DIR`` at request time (not at module import)
    means the value can be overridden in tests via ``app.dependency_overrides``.
    """
    return SecurityService(vault_base_dir=settings.VAULT_DIR)


# ---------------------------------------------------------------------------
# Exception mapper
# ---------------------------------------------------------------------------


def _map_security_exception(exc: Exception) -> None:
    """
    Map a domain exception to the appropriate :class:`HTTPException`.

    Raises
    ------
    HTTPException
        Always.  Non-domain exceptions are re-raised unmodified so the global
        handler in ``main.py`` can log the full traceback.
    """
    if isinstance(exc, VaultNotFoundError):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=exc.detail
        ) from exc

    if isinstance(exc, VaultLockedError):
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED, detail=exc.detail
        ) from exc

    if isinstance(exc, InvalidPasswordError):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=exc.detail
        ) from exc

    if isinstance(exc, PasswordChangeError):
        # PasswordChangeError wraps VaultKeyDecryptionError (wrong old password)
        # and surfaces it as 401.  Other PasswordChangeError causes (storage
        # failures, unexpected errors) are 500.
        # We use the detail string as-is — it is already safe to expose.
        if "old password" in exc.detail.lower() or "incorrect" in exc.detail.lower():
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail=exc.detail
            ) from exc
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=exc.detail
        ) from exc

    if isinstance(exc, CipherixError):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=exc.detail
        ) from exc

    raise exc


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post(
    "/{vault_id}/change-password",
    response_model=ChangePasswordResponse,
    status_code=status.HTTP_200_OK,
    summary="Change vault password (Vault Key rewrap)",
    description=(
        "Change the vault password by re-deriving the Master Key and "
        "re-encrypting (rewrapping) the Vault Key.  The vault must be "
        "unlocked.  All encrypted documents remain intact — only the "
        "Vault Key wrapper changes.  Requires both the current and the "
        "new password in the request body."
    ),
    responses={
        200: {"description": "Password changed and Vault Key rewrapped."},
        401: {"description": "Old password is incorrect."},
        404: {"description": "Vault not found."},
        422: {"description": "Invalid password format."},
        423: {"description": "Vault is locked."},
        500: {"description": "Encryption or storage failure."},
    },
)
async def change_password(
    vault_id: str,
    payload: ChangePasswordRequest,
    service: SecurityService = Depends(_get_security_service),
) -> ChangePasswordResponse:
    """
    ``POST /vaults/{vault_id}/change-password`` — rewrap the Vault Key.

    Decrypts the Vault Key using the old password, then re-encrypts it
    with a freshly derived Master Key from the new password and a new
    random salt.  No document is ever decrypted or re-encrypted.
    """
    try:
        result = service.change_password(
            vault_id=vault_id,
            old_password=payload.old_password,
            new_password=payload.new_password,
        )
        logger.info(
            "POST /vaults/%s/change-password succeeded | changed_at=%s",
            vault_id,
            result.changed_at,
        )
        return result
    except Exception as exc:  # noqa: BLE001
        _map_security_exception(exc)
