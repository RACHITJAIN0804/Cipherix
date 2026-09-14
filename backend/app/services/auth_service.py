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

_ph = PasswordHasher()


class AuthService:
    def register(self, db: Session, request: RegisterRequest) -> UserResponse:
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
            db.rollback()
            raise UserAlreadyExistsError(
                f"Username '{request.username}' is already taken.",
                detail="A user with that username already exists.",
            )

        logger.info("User registered | user_id=%s | username=%s", user.id, user.username)
        return UserResponse.model_validate(user)

    def login(self, db: Session, request: LoginRequest) -> TokenResponse:
        user = db.query(User).filter(User.username == request.username).first()

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
        user = db.get(User, user_id)
        if user is None:
            raise UserNotFoundError(
                f"User '{user_id}' not found.",
                detail="User account not found.",
            )
        return user

    def refresh(self, db: Session, refresh_token: str) -> TokenResponse:
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
