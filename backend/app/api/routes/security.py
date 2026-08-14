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
Passwords and recovery seeds are supplied as JSON body fields.  They are
forwarded immediately to the service layer and are never logged, stored,
or echoed in any response other than the single, one-time seed generation
response.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.exceptions import (
    CipherixError,
    InvalidPasswordError,
    InvalidRecoverySeedError,
    PasswordChangeError,
    RecoveryMetadataMissingError,
    UnsupportedRecoveryVersionError,
    VaultLockedError,
    VaultNotFoundError,
)
from app.core.logger import get_logger
from app.database import get_db
from app.schemas.security import (
    ChangePasswordRequest,
    ChangePasswordResponse,
    RecoverySeedResponse,
    VerifySeedRequest,
    VerifySeedResponse,
)
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
        # Wrong old password -> 401; storage/crypto failures -> 500.
        if "old password" in exc.detail.lower() or "incorrect" in exc.detail.lower():
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail=exc.detail
            ) from exc
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=exc.detail
        ) from exc

    if isinstance(exc, RecoveryMetadataMissingError):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=exc.detail
        ) from exc

    if isinstance(exc, (InvalidRecoverySeedError, UnsupportedRecoveryVersionError)):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=exc.detail
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
    db: Session = Depends(get_db),
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
            db=db,
        )
        logger.info(
            "POST /vaults/%s/change-password succeeded | changed_at=%s",
            vault_id,
            result.changed_at,
        )
        return result
    except Exception as exc:  # noqa: BLE001
        _map_security_exception(exc)


@router.post(
    "/{vault_id}/recovery-seed",
    response_model=RecoverySeedResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Generate BIP-39 recovery seed",
    description=(
        "Generate a 24-word BIP-39 recovery mnemonic for the vault.  "
        "The vault must be unlocked.  The seed is returned ONCE in this "
        "response and is never stored server-side.  Write it down immediately "
        "and store it in a secure physical location."
    ),
    responses={
        201: {"description": "Recovery seed generated. Returned once — store it safely."},
        404: {"description": "Vault not found."},
        423: {"description": "Vault is locked."},
        500: {"description": "Seed generation or metadata storage failed."},
    },
)
async def generate_recovery_seed(
    vault_id: str,
    service: SecurityService = Depends(_get_security_service),
    db: Session = Depends(get_db),
) -> RecoverySeedResponse:
    """
    ``POST /vaults/{vault_id}/recovery-seed`` — generate and return the seed.

    This endpoint has no request body.  The seed is generated server-side
    from OS CSPRNG entropy and returned in the HTTP 201 response.  The
    plaintext seed is never written to disk or logged.
    """
    try:
        result = service.generate_recovery_seed(vault_id=vault_id, db=db)
        logger.info(
            "POST /vaults/%s/recovery-seed succeeded | word_count=%d",
            vault_id,
            result.word_count,
        )
        return result
    except Exception as exc:  # noqa: BLE001
        _map_security_exception(exc)


@router.post(
    "/{vault_id}/recovery-seed/verify",
    response_model=VerifySeedResponse,
    status_code=status.HTTP_200_OK,
    summary="Verify recovery seed",
    description=(
        "Verify that a 24-word BIP-39 recovery seed is valid and matches "
        "the fingerprint stored for this vault.  Returns ``valid: true`` "
        "or ``valid: false``.  This endpoint does NOT grant access to the "
        "vault or any key material."
    ),
    responses={
        200: {"description": "Verification result (valid or invalid)."},
        404: {"description": "Vault not found or no recovery seed configured."},
        422: {"description": "Seed fails BIP-39 validation or unsupported version."},
        500: {"description": "Internal error."},
    },
)
async def verify_recovery_seed(
    vault_id: str,
    payload: VerifySeedRequest,
    service: SecurityService = Depends(_get_security_service),
    db: Session = Depends(get_db),
) -> VerifySeedResponse:
    """
    ``POST /vaults/{vault_id}/recovery-seed/verify`` — validate a seed.

    Accepts the 24-word mnemonic, checks BIP-39 structure and checksum,
    then compares the seed fingerprint against the stored metadata.
    When a DB session is available, the fingerprint is fetched from SQLite.
    """
    try:
        result = service.verify_recovery_seed(
            vault_id=vault_id,
            candidate_seed=payload.seed,
            db=db,
        )
        logger.info(
            "POST /vaults/%s/recovery-seed/verify | valid=%s",
            vault_id,
            result.valid,
        )
        return result
    except Exception as exc:  # noqa: BLE001
        _map_security_exception(exc)
