"""
services/auth_service.py
------------------------
Authentication business logic for Cipherix.

Responsibilities
----------------
* **register**: validate the username is unique, hash the password with
  Argon2id, persist the user row, return a safe ``UserResponse``.
* **login**: look up the user, verify the password, reject inactive accounts,
  generate and return access + refresh tokens.
* **get_user_by_id**: load a user row by primary key (used by
  ``get_current_user`` dependency).
* **refresh**: validate a refresh token, load the user, issue new tokens.

Security guarantees
-------------------
* Passwords are **never** logged, stored as plaintext, or returned via any
  response.  Only the Argon2id hash is written to the database.
* ``argon2.PasswordHasher`` (Argon2id) is used for both hashing and
  verification.  This reuses the ``argon2-cffi`` library already present
  in requirements for vault key derivation.
* Login errors use a generic ``InvalidCredentialsError`` for both "user not
  found" and "wrong password" cases to prevent user-enumeration attacks.
* Inactive users are rejected *after* password verification so timing cannot
  be used to confirm whether an account exists.

This service intentionally knows nothing about FastAPI, HTTP status codes,
or JWT internals.  Those concerns belong to the route layer and JWTManager.
"""

import uuid
from datetime import UTC, datetime

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError
from sqlalchemy.exc import IntegrityError as SQLAlchemyIntegrityError
from sqlalchemy.orm import Session

from app.core.exceptions import (
    InactiveUserError,
    InvalidCredentialsError,
    UserAlreadyExistsError,
    UserNotFoundError,
)
from app.core.logger import get_logger
from app.database.models import User
from app.schemas.auth import LoginRequest, RegisterRequest, TokenResponse, UserResponse
from app.security.jwt_manager import JWTManager

logger = get_logger(__name__)

# Argon2id hasher with OWASP-recommended defaults.
# argon2-cffi's PasswordHasher defaults (Argon2id, time_cost=3, memory_cost=65536)
# match OWASP PHC profile 2 and are intentionally higher than the minimum.
_ph = PasswordHasher()


class AuthService:
    """
    Authentication and user-management service.

    Parameters
    ----------
    None — all state comes from the injected ``db`` session per method call.

    Methods are synchronous to match the existing service-layer convention.
    """

    def register(self, db: Session, request: RegisterRequest) -> UserResponse:
        """
        Register a new user account.

        1. Check for duplicate username (service-layer guard before DB attempt).
        2. Hash the password with Argon2id.
        3. Insert the user row.
        4. Return a safe ``UserResponse`` (no password hash).

        Parameters
        ----------
        db:
            Active SQLAlchemy session.
        request:
            Validated registration payload.

        Returns
        -------
        UserResponse
            Safe representation of the newly created user.
        Raises
        ------
        UserAlreadyExistsError
            If a user with the same username already exists.
        """
        existing = db.query(User).filter(User.username == request.username).first()
        if existing is not None:
            raise UserAlreadyExistsError(
                f"Username '{request.username}' is already taken.",
                detail="A user with that username already exists.",
            )

        password_hash = _ph.hash(request.password)

        user = User(
            id=str(uuid.uuid4()),
            username=request.username,
            password_hash=password_hash,
            is_active=True,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )

        try:
            db.add(user)
            db.commit()
            db.refresh(user)
        except SQLAlchemyIntegrityError:
            # Race condition: duplicate inserted between the guard and the INSERT.
            db.rollback()
            raise UserAlreadyExistsError(
                f"Username '{request.username}' is already taken.",
                detail="A user with that username already exists.",
            )

        logger.info("User registered | user_id=%s | username=%s", user.id, user.username)
        return UserResponse.model_validate(user)

    def login(self, db: Session, request: LoginRequest) -> TokenResponse:
        """
        Authenticate a user and return access + refresh tokens.

        Raises
        ------
        InvalidCredentialsError
            If the username is not found or the password is incorrect.
        InactiveUserError
            If the account is deactivated.
        """
        user = db.query(User).filter(User.username == request.username).first()

        # Verify password even when user is not found to prevent timing attacks.
        # A dummy hash is used so the Argon2id cost is always paid.
        _dummy_hash = (
            "$argon2id$v=19$m=65536,t=3,p=4"
            "$AAAAAAAAAAAAAAAAAAAAAA"
            "$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        )
        candidate_hash = user.password_hash if user is not None else _dummy_hash

        try:
            _ph.verify(candidate_hash, request.password)
            password_ok = True
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            password_ok = False

        if user is None or not password_ok:
            # Unified error — no hint about whether the username exists.
            raise InvalidCredentialsError(
                "Invalid username or password.",
                detail="Invalid username or password.",
            )

        if not user.is_active:
            raise InactiveUserError(
                f"Account '{user.username}' is deactivated.",
                detail="This account has been deactivated.",
            )

        access_token = JWTManager.create_access_token(user.id)
        refresh_token = JWTManager.create_refresh_token(user.id)

        logger.info("User logged in | user_id=%s | username=%s", user.id, user.username)
        return TokenResponse(access_token=access_token, refresh_token=refresh_token)

    def get_user_by_id(self, db: Session, user_id: str) -> User:
        """
        Load a user row by primary key.

        Raises
        ------
        UserNotFoundError
            If no user with that ID exists in the database.
        """
        user = db.get(User, user_id)
        if user is None:
            raise UserNotFoundError(
                f"User '{user_id}' not found.",
                detail="User account not found.",
            )
        return user

    def refresh(self, db: Session, refresh_token: str) -> TokenResponse:
        """
        Validate a refresh token and issue a new token pair.

        Raises
        ------
        ExpiredTokenError
            If the refresh token has expired.
        InvalidTokenError
            If the refresh token is malformed or has the wrong type.
        UserNotFoundError
            If the user referenced in the token no longer exists.
        InactiveUserError
            If the user account has been deactivated.
        """
        from app.core.exceptions import InactiveUserError
        payload = JWTManager.decode_refresh_token(refresh_token)
        user_id: str = payload["sub"]

        user = self.get_user_by_id(db, user_id)

        if not user.is_active:
            raise InactiveUserError(
                f"Account '{user.username}' is deactivated.",
                detail="This account has been deactivated.",
            )

        access_token = JWTManager.create_access_token(user.id)
        new_refresh_token = JWTManager.create_refresh_token(user.id)

        logger.info("Tokens refreshed | user_id=%s", user.id)
        return TokenResponse(access_token=access_token, refresh_token=new_refresh_token)
