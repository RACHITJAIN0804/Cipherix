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

from app.core.exceptions import (
    AuthError,
    ExpiredTokenError,
    InactiveUserError,
    InvalidCredentialsError,
    InvalidTokenError,
    TokenError,
    UserAlreadyExistsError,
    UserNotFoundError,
)
from app.core.logger import get_logger
from app.database import get_db
from app.database.models import User
from app.api.dependencies import get_current_user
from app.schemas.auth import (
    LoginRequest,
    RefreshRequest,
    RegisterRequest,
    TokenResponse,
    UserResponse,
)
from app.services.auth_service import AuthService

logger = get_logger(__name__)

router = APIRouter(prefix="/auth", tags=["Authentication"])

_auth_service = AuthService()


# ---------------------------------------------------------------------------
# Exception mapper
# ---------------------------------------------------------------------------


def _map_auth_exception(exc: Exception) -> None:
    """
    Map a domain exception to the appropriate :class:`HTTPException`.

    Centralising the mapping here means every auth endpoint shares the same
    exception-to-status-code table without repeating it.

    Raises
    ------
    HTTPException
        Always.  Non-domain exceptions are re-raised so the global handler
        in ``main.py`` can log the full traceback.
    """
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

    if isinstance(exc, UserNotFoundError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=exc.detail,
            headers={"WWW-Authenticate": "Bearer"},
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


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user account",
    description=(
        "Create a new Cipherix user account.  The username must be unique "
        "(3–64 characters).  The password is hashed with Argon2id before "
        "storage and is never returned in any response."
    ),
    responses={
        201: {"description": "Account created successfully."},
        409: {"description": "Username already taken."},
        422: {"description": "Validation error (username too short, password too short, etc.)."},
    },
)
async def register(
    payload: RegisterRequest,
    db: Session = Depends(get_db),
) -> UserResponse:
    """
    ``POST /auth/register`` — create a new user account.

    Validates the username and password, hashes the password with Argon2id,
    and stores the user row.  Returns safe user information (no password hash).
    """
    try:
        return _auth_service.register(db, payload)
    except Exception as exc:  # noqa: BLE001
        _map_auth_exception(exc)


@router.post(
    "/login",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    summary="Log in and obtain JWT tokens",
    description=(
        "Authenticate with username and password.  Returns an access token "
        "(short-lived) and a refresh token (longer-lived).  Both are signed "
        "JWTs.  The password is never logged or returned."
    ),
    responses={
        200: {"description": "Login successful — tokens returned."},
        401: {"description": "Invalid username or password."},
        403: {"description": "Account is deactivated."},
    },
)
async def login(
    payload: LoginRequest,
    db: Session = Depends(get_db),
) -> TokenResponse:
    """
    ``POST /auth/login`` — authenticate and return tokens.

    Uses a constant-time Argon2id check for both existing and non-existing
    usernames to prevent timing-based user enumeration.
    """
    try:
        return _auth_service.login(db, payload)
    except Exception as exc:  # noqa: BLE001
        _map_auth_exception(exc)


@router.get(
    "/me",
    response_model=UserResponse,
    status_code=status.HTTP_200_OK,
    summary="Get the currently authenticated user",
    description=(
        "Returns the profile of the user identified by the Bearer JWT in "
        "the ``Authorization`` header.  No sensitive fields (password hash, "
        "keys, seeds) are included in the response."
    ),
    responses={
        200: {"description": "Authenticated user profile."},
        401: {"description": "Missing, expired, or invalid token."},
        403: {"description": "Account is deactivated."},
    },
)
async def me(
    current_user: User = Depends(get_current_user),
) -> UserResponse:
    """
    ``GET /auth/me`` — return the authenticated user's profile.

    This endpoint demonstrates and tests the ``get_current_user`` dependency.
    The dependency validates the Bearer token, loads the user from SQLite,
    and verifies the account is active before this handler is called.
    """
    return UserResponse.model_validate(current_user)


@router.post(
    "/refresh",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    summary="Refresh access token using a refresh token",
    description=(
        "Exchange a valid refresh token for a new access token and refresh "
        "token pair.  Refresh tokens have a longer lifetime than access tokens "
        "but cannot be used directly to access protected endpoints."
    ),
    responses={
        200: {"description": "New token pair issued."},
        401: {"description": "Refresh token is expired, invalid, or malformed."},
        403: {"description": "Account is deactivated."},
    },
)
async def refresh(
    payload: RefreshRequest,
    db: Session = Depends(get_db),
) -> TokenResponse:
    """
    ``POST /auth/refresh`` — exchange a refresh token for a new token pair.

    Validates the refresh token's signature, expiry, and type claim
    (``type="refresh"`` — an access token is never accepted here).
    """
    try:
        return _auth_service.refresh(db, payload.refresh_token)
    except Exception as exc:  # noqa: BLE001
        _map_auth_exception(exc)
