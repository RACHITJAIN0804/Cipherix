"""
security/jwt_manager.py
-----------------------
JWT creation and validation for Cipherix authentication.

Responsibilities
----------------
* Create signed access tokens (short-lived, ``type="access"``).
* Create signed refresh tokens (long-lived, ``type="refresh"``).
* Decode and validate any token, returning its claims.
* Enforce ``exp``, ``type``, and signature checks as separate concerns so
  routes can return precise error responses.

Design decisions
----------------
* **HS256 (HMAC-SHA256)**: sufficient for server-side JWTs where we control
  both signing and verification.  RS256 would only be needed for third-party
  token consumers.
* **Minimal claims**: only ``sub``, ``iat``, ``exp``, and ``type``.  No
  username, roles, or vault IDs in the token — those are looked up from the
  database on each request.
* **``type`` claim**: prevents a refresh token from being accepted as an
  access token or vice versa.  Access tokens have ``type="access"``;
  refresh tokens have ``type="refresh"``.
* **No token storage**: JWTs are stateless.  Revocation requires a separate
  milestone (token blocklist or short expiry + refresh rotation).
* **No sensitive data in claims**: passwords, Vault Keys, Master Keys, and
  recovery seeds are never placed in JWT payloads.

Configuration
-------------
All values come from :class:`~app.core.config.Settings`::

    jwt_secret_key              ← JWT_SECRET_KEY env var
    jwt_algorithm               ← JWT_ALGORITHM env var (default HS256)
    access_token_expire_minutes ← ACCESS_TOKEN_EXPIRE_MINUTES env var (default 30)
    refresh_token_expire_days   ← REFRESH_TOKEN_EXPIRE_DAYS env var (default 7)
"""

from datetime import UTC, datetime, timedelta
from typing import Any

import jwt

from app.core.config import settings
from app.core.exceptions import ExpiredTokenError, InvalidTokenError
from app.core.logger import get_logger

logger = get_logger(__name__)

# Token type claim values.
_ACCESS_TYPE: str = "access"
_REFRESH_TYPE: str = "refresh"


class JWTManager:
    """
    Stateless JWT factory and validator.

    All methods are class-level (no instance state) so the manager can be
    used as a singleton or instantiated per-request without overhead.

    Never place passwords, keys, or seeds in any JWT claim.
    """

    # ------------------------------------------------------------------
    # Token creation
    # ------------------------------------------------------------------

    @staticmethod
    def create_access_token(user_id: str) -> str:
        """
        Create a signed access token for the given user.

        Parameters
        ----------
        user_id:
            The user's UUID string — becomes the ``sub`` claim.

        Returns
        -------
        str
            Compact signed JWT (three Base64url-encoded segments).
        """
        now = datetime.now(UTC)
        expire = now + timedelta(minutes=settings.access_token_expire_minutes)
        claims: dict[str, Any] = {
            "sub": user_id,
            "iat": now,
            "exp": expire,
            "type": _ACCESS_TYPE,
        }
        token = jwt.encode(
            claims,
            settings.jwt_secret_key,
            algorithm=settings.jwt_algorithm,
        )
        logger.debug("Access token created | user_id=%s | exp=%s", user_id, expire)
        return token

    @staticmethod
    def create_refresh_token(user_id: str) -> str:
        """
        Create a signed refresh token for the given user.

        Refresh tokens are longer-lived than access tokens and carry
        ``type="refresh"`` so they cannot be accepted where access tokens
        are required.

        Parameters
        ----------
        user_id:
            The user's UUID string — becomes the ``sub`` claim.

        Returns
        -------
        str
            Compact signed JWT.
        """
        now = datetime.now(UTC)
        expire = now + timedelta(days=settings.refresh_token_expire_days)
        claims: dict[str, Any] = {
            "sub": user_id,
            "iat": now,
            "exp": expire,
            "type": _REFRESH_TYPE,
        }
        token = jwt.encode(
            claims,
            settings.jwt_secret_key,
            algorithm=settings.jwt_algorithm,
        )
        logger.debug("Refresh token created | user_id=%s | exp=%s", user_id, expire)
        return token

    # ------------------------------------------------------------------
    # Token validation
    # ------------------------------------------------------------------

    @staticmethod
    def decode_access_token(token: str) -> dict[str, Any]:
        """
        Decode and validate an access token.

        Validates:
        * Signature (HMAC-SHA256 with the configured secret).
        * Expiration (``exp`` claim).
        * Token type (must be ``"access"``).

        Parameters
        ----------
        token:
            Raw JWT string from the ``Authorization: Bearer <token>`` header.

        Returns
        -------
        dict[str, Any]
            Decoded and validated claims payload.

        Raises
        ------
        ExpiredTokenError
            If the token has passed its ``exp`` claim.
        InvalidTokenError
            If the signature is invalid, the token is malformed, claims are
            missing, or the ``type`` claim is not ``"access"``.
        """
        return JWTManager._decode(token, expected_type=_ACCESS_TYPE)

    @staticmethod
    def decode_refresh_token(token: str) -> dict[str, Any]:
        """
        Decode and validate a refresh token.

        Identical to :meth:`decode_access_token` but requires
        ``type="refresh"``.  A refresh token is **never** accepted where an
        access token is required, and vice versa.

        Parameters
        ----------
        token:
            Raw JWT string.

        Returns
        -------
        dict[str, Any]
            Decoded and validated claims payload.

        Raises
        ------
        ExpiredTokenError
            If the token has passed its ``exp`` claim.
        InvalidTokenError
            If the token is invalid or not of type ``"refresh"``.
        """
        return JWTManager._decode(token, expected_type=_REFRESH_TYPE)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _decode(token: str, expected_type: str) -> dict[str, Any]:
        """
        Decode a JWT and assert its type claim.

        Parameters
        ----------
        token:
            Raw JWT string.
        expected_type:
            One of ``"access"`` or ``"refresh"``.

        Returns
        -------
        dict[str, Any]
            Validated claims.

        Raises
        ------
        ExpiredTokenError
            Token has expired.
        InvalidTokenError
            Any other validation failure.
        """
        try:
            payload: dict[str, Any] = jwt.decode(
                token,
                settings.jwt_secret_key,
                algorithms=[settings.jwt_algorithm],
            )
        except jwt.ExpiredSignatureError as exc:
            logger.debug("JWT expired")
            raise ExpiredTokenError(
                "Token has expired.", detail="Token has expired."
            ) from exc
        except jwt.PyJWTError as exc:
            logger.debug("JWT invalid: %s", exc)
            raise InvalidTokenError(
                "Invalid token.", detail="Invalid or malformed token."
            ) from exc

        # Verify required claims exist.
        if "sub" not in payload:
            raise InvalidTokenError("Missing 'sub' claim.", detail="Invalid token claims.")
        if "type" not in payload:
            raise InvalidTokenError("Missing 'type' claim.", detail="Invalid token claims.")

        # Enforce type separation — a refresh token cannot be an access token.
        if payload["type"] != expected_type:
            raise InvalidTokenError(
                f"Expected token type '{expected_type}', got '{payload['type']}'.",
                detail="Invalid token type.",
            )

        return payload
