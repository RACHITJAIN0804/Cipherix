from datetime import UTC, datetime, timedelta
from typing import Any

import jwt

from app.core.config import settings
from app.core.exceptions import ExpiredTokenError, InvalidTokenError
from app.core.logger import get_logger

logger = get_logger(__name__)

_ACCESS_TYPE: str = "access"
_REFRESH_TYPE: str = "refresh"


class JWTManager:
    @staticmethod
    def create_access_token(user_id: str) -> str:
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

    @staticmethod
    def decode_access_token(token: str) -> dict[str, Any]:
        return JWTManager._decode(token, expected_type=_ACCESS_TYPE)

    @staticmethod
    def decode_refresh_token(token: str) -> dict[str, Any]:
        return JWTManager._decode(token, expected_type=_REFRESH_TYPE)

    @staticmethod
    def _decode(token: str, expected_type: str) -> dict[str, Any]:
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

        if "sub" not in payload:
            raise InvalidTokenError("Missing 'sub' claim.", detail="Invalid token claims.")
        if "type" not in payload:
            raise InvalidTokenError("Missing 'type' claim.", detail="Invalid token claims.")

        if payload["type"] != expected_type:
            raise InvalidTokenError(
                f"Expected token type '{expected_type}', got '{payload['type']}'.",
                detail="Invalid token type.",
            )

        return payload
