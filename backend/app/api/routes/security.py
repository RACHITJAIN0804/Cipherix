from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.dependencies import get_db, get_user_vault
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
from app.database.models import Vault
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


def _get_security_service() -> SecurityService:
    return SecurityService(vault_base_dir=settings.VAULT_DIR)


def _map_security_exception(exc: Exception) -> None:
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


@router.post(
    "/{vault_id}/change-password",
    response_model=ChangePasswordResponse,
    status_code=status.HTTP_200_OK,
    summary="Change vault password (Vault Key rewrap)",
    description=(
        "Change the vault password by re-deriving the Master Key and "
        "re-encrypting (rewrapping) the Vault Key.  The vault must be "
        "unlocked."
    ),
    responses={
        200: {"description": "Password changed and Vault Key rewrapped."},
        401: {"description": "Missing/invalid JWT or old password incorrect."},
        404: {"description": "Vault not found or not owned."},
        422: {"description": "Invalid password format."},
        423: {"description": "Vault is locked."},
        500: {"description": "Encryption or storage failure."},
    },
)
async def change_password(
    vault_id: str,
    payload: ChangePasswordRequest,
    vault: Vault = Depends(get_user_vault),
    service: SecurityService = Depends(_get_security_service),
    db: Session = Depends(get_db),
) -> ChangePasswordResponse:
    try:
        result = service.change_password(
            vault_id=vault.id,
            old_password=payload.old_password,
            new_password=payload.new_password,
            db=db,
        )
        logger.info(
            "POST /vaults/%s/change-password succeeded | changed_at=%s",
            vault.id,
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
        "Generate a 24-word BIP-39 recovery mnemonic for the vault."
    ),
    responses={
        201: {"description": "Recovery seed generated. Returned once — store it safely."},
        401: {"description": "Missing, expired, or invalid JWT token."},
        404: {"description": "Vault not found or not owned."},
        423: {"description": "Vault is locked."},
        500: {"description": "Seed generation or metadata storage failed."},
    },
)
async def generate_recovery_seed(
    vault_id: str,
    vault: Vault = Depends(get_user_vault),
    service: SecurityService = Depends(_get_security_service),
    db: Session = Depends(get_db),
) -> RecoverySeedResponse:
    try:
        result = service.generate_recovery_seed(vault_id=vault.id, db=db)
        logger.info(
            "POST /vaults/%s/recovery-seed succeeded | word_count=%d",
            vault.id,
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
        "the fingerprint stored for this vault."
    ),
    responses={
        200: {"description": "Verification result (valid or invalid)."},
        401: {"description": "Missing, expired, or invalid JWT token."},
        404: {"description": "Vault not found or no recovery seed configured."},
        422: {"description": "Seed fails BIP-39 validation or unsupported version."},
        500: {"description": "Internal error."},
    },
)
async def verify_recovery_seed(
    vault_id: str,
    payload: VerifySeedRequest,
    vault: Vault = Depends(get_user_vault),
    service: SecurityService = Depends(_get_security_service),
    db: Session = Depends(get_db),
) -> VerifySeedResponse:
    try:
        result = service.verify_recovery_seed(
            vault_id=vault.id,
            candidate_seed=payload.seed,
            db=db,
        )
        logger.info(
            "POST /vaults/%s/recovery-seed/verify | valid=%s",
            vault.id,
            result.valid,
        )
        return result
    except Exception as exc:  # noqa: BLE001
        _map_security_exception(exc)
