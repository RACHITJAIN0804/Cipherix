import uuid

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.exceptions import (
    AuthError,
    ExpiredTokenError,
    InactiveUserError,
    InvalidTokenError,
    UserNotFoundError,
)
from app.core.logger import get_logger
from app.database import get_db
from app.database.models import User, Vault
from app.security.jwt_manager import JWTManager
from app.services.auth_service import AuthService
from app.vault.vault_manager import VaultManager

logger = get_logger(__name__)

__all__ = ["get_db", "get_current_user", "get_user_vault"]

_bearer = HTTPBearer(auto_error=False)

_auth_service = AuthService()


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
    db: Session = Depends(get_db),
) -> User:
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = credentials.credentials

    try:
        payload = JWTManager.decode_access_token(token)
    except ExpiredTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or malformed token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_id: str = payload["sub"]

    try:
        user = _auth_service.get_user_by_id(db, user_id)
    except UserNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account not found.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This account has been deactivated.",
        )

    return user


def get_user_vault(
    vault_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Vault:
    try:
        uuid.UUID(vault_id, version=4)
    except (ValueError, AttributeError):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"'{vault_id}' is not a valid UUID4 string.",
        )

    vault_record = db.get(Vault, vault_id)

    vault_root = settings.VAULT_DIR / vault_id
    if not (vault_root.is_dir() and (vault_root / "manifest.json").is_file()):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Vault with ID '{vault_id}' was not found.",
        )

    vault_record = db.get(Vault, vault_id)
    if vault_record is None or (
        vault_record.user_id is not None and vault_record.user_id != current_user.id
    ):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Vault with ID '{vault_id}' was not found.",
        )

    return vault_record
