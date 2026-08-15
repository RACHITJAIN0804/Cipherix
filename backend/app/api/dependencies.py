"""
api/dependencies.py
-------------------
Reusable FastAPI dependencies for Cipherix.

Currently exports:
* ``get_db``          — yields a per-request SQLAlchemy session.
* ``get_current_user`` — extracts and validates the Bearer JWT, loads and
  returns the authenticated :class:`~app.database.models.User` row.

Adding new dependencies
-----------------------
Place them here so every route module imports from a single location.
Never put business logic in dependencies — delegate to services.
"""

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

# HTTPBearer extracts the ``Authorization: Bearer <token>`` header.
# ``auto_error=False`` lets us return a custom 401 instead of FastAPI's default.
_bearer = HTTPBearer(auto_error=False)

_auth_service = AuthService()


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
    db: Session = Depends(get_db),
) -> User:
    """
    FastAPI dependency — authenticate the current request via JWT.

    Extracts the ``Authorization: Bearer <token>`` header, validates the JWT,
    loads the user from the database, and verifies the account is active.

    Usage in a route
    ----------------
    ::

        from app.api.dependencies import get_current_user
        from app.database.models import User

        @router.get("/auth/me")
        def me(current_user: User = Depends(get_current_user)) -> UserResponse:
            return UserResponse.model_validate(current_user)

    Returns
    -------
    User
        The authenticated, active user ORM row.

    Raises
    ------
    HTTPException(401)
        Missing token, malformed token, invalid signature, expired token,
        wrong token type, or user no longer exists.
    HTTPException(403)
        Account is deactivated.
    """
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
    """
    FastAPI dependency — authenticate the user and verify vault ownership.

    1. Validate that ``vault_id`` is a valid UUID4 string.
    2. Retrieve the requested vault from SQLite.
    3. Verify that the vault belongs to the authenticated user.
    4. Reject unauthorized access with 404 (prevents leaking existence).
    5. Return the authorized Vault ORM row.

    Parameters
    ----------
    vault_id:
        UUID4 string from path parameter.
    current_user:
        Authenticated User row (from get_current_user).
    db:
        Active SQLAlchemy session.

    Returns
    -------
    Vault
        The authorized Vault ORM model instance.

    Raises
    ------
    HTTPException(400)
        If vault_id is not a valid UUID string.
    HTTPException(404)
        If the vault does not exist or does not belong to current_user.
    """
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
