"""
api/routes/auth.py
------------------
FastAPI route handlers for user authentication.

Pattern (consistent with existing route modules)
-------------------------------------------------
1. Extract and forward request data to :class:`~app.services.auth_service.AuthService`.
2. Map domain exceptions to HTTP status codes via ``_map_auth_exception``.
3. Return the appropriate response schema.

No business logic, no cryptography, and no database queries belong here.

Password handling
-----------------
Passwords are received as JSON body fields.  They are forwarded immediately
to the service layer and are never logged, stored in a route parameter,
or returned in any response body.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.dependencies import get_current_user
from app.core.config import settings
from app.core.exceptions import (
    AuthError,
    ExpiredTokenError,
    InactiveUserError,
    InvalidCredentialsError,
    InvalidRecoverySeedError,
    InvalidTokenError,
    RecoveryMetadataMissingError,
    TokenError,
    UnsupportedRecoveryVersionError,
    UserAlreadyExistsError,
    UserNotFoundError,
    VaultNotFoundError,
)
from app.core.logger import get_logger
from app.core.rate_limiter import limit_auth_requests
from app.database import get_db
from app.database.models import User
from app.schemas.auth import (
    LoginRequest,
    RecoverVaultRequest,
    RefreshRequest,
    RegisterRequest,
    TokenResponse,
    UserResponse,
)
from app.services.auth_service import AuthService
from app.services.security_service import SecurityService

logger = get_logger(__name__)

router = APIRouter(prefix="/auth", tags=["Authentication"])

_auth_service = AuthService()



def _map_auth_exception(exc: Exception) -> None:
    if isinstance(exc, UserAlreadyExistsError):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=exc.detail,
        ) from exc

    if isinstance(exc, InvalidCredentialsError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=exc.detail,
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    if isinstance(exc, InactiveUserError):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=exc.detail,
        ) from exc

    if isinstance(exc, (UserNotFoundError, VaultNotFoundError, RecoveryMetadataMissingError)):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=exc.detail,
        ) from exc

    if isinstance(exc, (InvalidRecoverySeedError, UnsupportedRecoveryVersionError)):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=exc.detail,
        ) from exc

    if isinstance(exc, ExpiredTokenError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=exc.detail,
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    if isinstance(exc, (InvalidTokenError, TokenError)):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=exc.detail,
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    if isinstance(exc, AuthError):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=exc.detail,
        ) from exc

    raise exc


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user account",
    dependencies=[Depends(limit_auth_requests)],
)
async def register(
    payload: RegisterRequest,
    db: Session = Depends(get_db),
) -> UserResponse:
    try:
        return _auth_service.register(db, payload)
    except Exception as exc:  # noqa: BLE001
        _map_auth_exception(exc)


@router.post(
    "/login",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    summary="Log in and obtain JWT tokens",
    dependencies=[Depends(limit_auth_requests)],
)
async def login(
    payload: LoginRequest,
    db: Session = Depends(get_db),
) -> TokenResponse:
    try:
        return _auth_service.login(db, payload)
    except Exception as exc:  # noqa: BLE001
        _map_auth_exception(exc)


@router.get(
    "/me",
    response_model=UserResponse,
    status_code=status.HTTP_200_OK,
    summary="Get the currently authenticated user",
)
async def me(
    current_user: User = Depends(get_current_user),
) -> UserResponse:
    return UserResponse.model_validate(current_user)


@router.post(
    "/refresh",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    summary="Refresh access token using a refresh token",
)
async def refresh(
    payload: RefreshRequest,
    db: Session = Depends(get_db),
) -> TokenResponse:
    try:
        return _auth_service.refresh(db, payload.refresh_token)
    except Exception as exc:  # noqa: BLE001
        _map_auth_exception(exc)


@router.post(
    "/recover",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    summary="Recover vault access using BIP-39 recovery seed",
    description=(
        "Recover access to a vault using a 24-word BIP-39 recovery seed and "
        "establish a new password.  Does not require an existing password or JWT."
    ),
    responses={
        200: {"description": "Recovery successful — new password established and tokens issued."},
        401: {"description": "Invalid user or unauthenticated."},
        403: {"description": "Account is deactivated."},
        404: {"description": "User or vault not found or recovery seed not configured."},
        422: {"description": "Invalid BIP-39 recovery seed format, checksum, or fingerprint mismatch."},
    },
)
async def recover(
    payload: RecoverVaultRequest,
    db: Session = Depends(get_db),
) -> TokenResponse:
    """
    ``POST /auth/recover`` — recover vault access and establish a new password.
    """
    try:
        sec_service = SecurityService(vault_base_dir=settings.VAULT_DIR)
        return sec_service.recover_vault(
            username=payload.username,
            seed=payload.seed,
            new_password=payload.new_password,
            db=db,
        )
    except Exception as exc:  # noqa: BLE001
        _map_auth_exception(exc)

