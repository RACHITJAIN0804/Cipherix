"""
schemas/auth.py
---------------
Pydantic request and response schemas for authentication endpoints.

Design decisions
----------------
* **No password in responses**: ``UserResponse`` and ``TokenResponse`` never
  include ``password_hash`` or any derivative of the password.
* **``model_config = ConfigDict(from_attributes=True)``**: allows building
  ``UserResponse`` directly from a :class:`~app.database.models.User` ORM row.
* **Validation on input**: ``RegisterRequest`` enforces minimum length and
  strips trailing whitespace on usernames.  Passwords are validated only for
  minimum length (strength rules belong in a separate milestone).
* **Refresh endpoint**: ``RefreshRequest`` accepts only the token string so
  the route can delegate all validation to :class:`~app.security.jwt_manager.JWTManager`.
"""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator



class RegisterRequest(BaseModel):
    """
    Request body for ``POST /auth/register``.

    Attributes
    ----------
    username:
        3–64 character login identifier.  Stripped of leading/trailing
        whitespace.  Must not be empty after stripping.
    password:
        Minimum 8 characters.  Never stored or returned.
    """

    username: str = Field(
        ...,
        min_length=3,
        max_length=64,
        description="Unique login identifier (3–64 characters).",
    )
    password: str = Field(
        ...,
        min_length=8,
        description="Account password (minimum 8 characters).",
    )

    @field_validator("username")
    @classmethod
    def username_strip(cls, v: str) -> str:
        stripped = v.strip()
        if not stripped:
            raise ValueError("Username must not be blank.")
        return stripped



class LoginRequest(BaseModel):
    """
    Request body for ``POST /auth/login``.

    Attributes
    ----------
    username:
        The user's login identifier.
    password:
        The user's password.  Never logged, never returned.
    """

    username: str = Field(..., description="Login identifier.")
    password: str = Field(..., description="Account password.")



class TokenResponse(BaseModel):
    """
    Response body for ``POST /auth/login`` and ``POST /auth/refresh``.

    Attributes
    ----------
    access_token:
        Short-lived JWT for authenticating API requests.
    refresh_token:
        Longer-lived JWT for obtaining new access tokens.
    token_type:
        Always ``"bearer"`` (OAuth2 convention).
    """

    access_token: str
    refresh_token: str
    token_type: str = "bearer"



class UserResponse(BaseModel):
    """
    Safe representation of a user account returned by ``GET /auth/me``.

    The ``password_hash`` field is **never** included.

    Attributes
    ----------
    id:
        UUID4 string — stable user identifier.
    username:
        Login identifier.
    is_active:
        Whether the account is active.
    created_at:
        UTC timestamp of account creation.
    """

    model_config = ConfigDict(from_attributes=True)

    id: str
    username: str
    is_active: bool
    created_at: datetime



class RefreshRequest(BaseModel):
    refresh_token: str = Field(..., description="Refresh JWT issued at login.")


class RecoverVaultRequest(BaseModel):
    """
    Request body for ``POST /auth/recover``.

    Attributes
    ----------
    username:
        Login identifier of the account to recover.
    seed:
        Space-separated 24-word BIP-39 recovery mnemonic.
    new_password:
        New password to establish for the vault.
    """

    username: str = Field(..., description="Login identifier.")
    seed: str = Field(..., min_length=20, description="24-word BIP-39 recovery seed.")
    new_password: str = Field(..., min_length=8, description="New vault password (minimum 8 characters).")

    @field_validator("username")
    @classmethod
    def username_strip(cls, v: str) -> str:
        stripped = v.strip()
        if not stripped:
            raise ValueError("Username must not be blank.")
        return stripped

