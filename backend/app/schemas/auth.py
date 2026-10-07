
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator


class RegisterRequest(BaseModel):

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


class RegisterWithVaultResponse(BaseModel):
    """Response returned exactly once at registration.

    ``seed`` is the plaintext 16-word recovery seed.  It exists in this
    response payload transiently — the frontend must display it once,
    prompt the user to confirm the backup, then discard it from memory.
    The backend never stores the plaintext seed.
    """

    id: str = Field(..., description="User ID (alias for user_id).")
    user_id: str
    username: str
    is_active: bool = True
    created_at: datetime
    vault_id: str
    seed: str = Field(
        ...,
        description=(
            "16-word BIP-39 recovery seed.  Shown once.  "
            "Write it down and store it securely."
        ),
    )
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class LoginRequest(BaseModel):

    username: str = Field(..., description="Login identifier.")
    password: str = Field(..., description="Account password.")


class TokenResponse(BaseModel):

    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class UserResponse(BaseModel):

    model_config = ConfigDict(from_attributes=True)

    id: str
    username: str
    is_active: bool
    created_at: datetime


class RefreshRequest(BaseModel):
    refresh_token: str = Field(..., description="Refresh JWT issued at login.")


class RecoverVaultRequest(BaseModel):

    username: str = Field(..., description="Login identifier.")
    seed: str = Field(..., min_length=20, description="16-word BIP-39 recovery seed.")
    new_password: str = Field(..., min_length=8, description="New vault password (minimum 8 characters).")

    @field_validator("username")
    @classmethod
    def username_strip(cls, v: str) -> str:
        stripped = v.strip()
        if not stripped:
            raise ValueError("Username must not be blank.")
        return stripped
