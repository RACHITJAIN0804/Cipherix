
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
    seed: str = Field(..., min_length=20, description="24-word BIP-39 recovery seed.")
    new_password: str = Field(..., min_length=8, description="New vault password (minimum 8 characters).")

    @field_validator("username")
    @classmethod
    def username_strip(cls, v: str) -> str:
        stripped = v.strip()
        if not stripped:
            raise ValueError("Username must not be blank.")
        return stripped

