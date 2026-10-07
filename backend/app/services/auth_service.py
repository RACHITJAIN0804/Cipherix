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

    def register_with_vault(
        self,
        db: Session,
        request: RegisterRequest,
        vault_base_dir,
    ):
        """Atomically register a new user, create their default vault, and
        generate a 16-word recovery seed.

        Returns a ``RegisterWithVaultResponse`` whose ``seed`` field contains
        the plaintext mnemonic exactly once.  The caller (route handler) must
        forward this to the frontend, which displays it once and then discards
        it from memory.  The plaintext seed is NEVER written to any database,
        log file, or persistent storage.
        """
        from pathlib import Path
        from app.schemas.auth import RegisterWithVaultResponse
        from app.schemas.vault import CreateVaultRequest
        from app.services.vault_service import VaultService
        from app.services.security_service import SecurityService
        from app.vault.vault_manager import VaultManager
        from app.vault.manifest import VaultManifest
        from app.database.models import Vault as VaultRecord

        existing = db.query(User).filter(User.username == request.username).first()
        if existing is not None:
            raise UserAlreadyExistsError(
                f"Username '{request.username}' is already taken.",
                detail="A user with that username already exists.",
            )

        password_hash = _ph.hash(request.password)
        user_id = str(uuid.uuid4())
        user = User(
            id=user_id,
            username=request.username,
            password_hash=password_hash,
            is_active=True,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )

        try:
            db.add(user)
            db.flush()
        except SQLAlchemyIntegrityError:
            db.rollback()
            raise UserAlreadyExistsError(
                f"Username '{request.username}' is already taken.",
                detail="A user with that username already exists.",
            )

        base_dir = Path(vault_base_dir)
        vault_mgr = VaultManager(vault_base_dir=base_dir)
        vault_svc = VaultService(manager=vault_mgr)
        vault_resp = vault_svc.create_vault(
            request=CreateVaultRequest(
                name=f"{request.username}'s Vault",
                password=request.password,
            ),
            user_id=user_id,
            db=db,
        )
        vault_id = vault_resp.vault_id

        vault_root = base_dir / vault_id
        manifest_path = vault_root / "manifest.json"
        m = VaultManifest.read(manifest_path)
        m.status = "unlocked"
        m.write(manifest_path)

        vr = db.get(VaultRecord, vault_id)
        if vr is not None:
            vr.status = "unlocked"

        sec_svc = SecurityService(vault_base_dir=base_dir)
        seed_resp = sec_svc.generate_recovery_seed(
            vault_id=vault_id,
            password=request.password,
            db=db,
        )

        m.status = "locked"
        m.write(manifest_path)
        if vr is not None:
            vr.status = "locked"

        db.commit()

        access_token = JWTManager.create_access_token(user_id)
        refresh_token = JWTManager.create_refresh_token(user_id)

        logger.info(
            "User registered with vault and recovery seed | user_id=%s | vault_id=%s",
            user_id,
            vault_id,
        )

        return RegisterWithVaultResponse(
            id=user_id,
            user_id=user_id,
            username=request.username,
            is_active=True,
            created_at=user.created_at,
            vault_id=vault_id,
            seed=seed_resp.seed,
            access_token=access_token,
            refresh_token=refresh_token,
        )

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
