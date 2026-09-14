
from datetime import datetime

from pydantic import BaseModel, Field, field_validator


class CreateVaultRequest(BaseModel):

    name: str = Field(
        ...,
        min_length=3,
        max_length=50,
        description="Human-readable vault name (3–50 characters after trimming).",
        examples=["My Private Notes", "Work Projects"],
    )
    password: str = Field(
        ...,
        min_length=8,
        description=(
            "Vault password used to derive the Master Key via Argon2id. "
            "Minimum 8 characters.  Never stored or logged."
        ),
    )

    @field_validator("name", mode="before")
    @classmethod
    def strip_whitespace(cls, value: str) -> str:
        if not isinstance(value, str):
            raise ValueError("name must be a string")
        stripped = value.strip()
        if not stripped:
            raise ValueError("name must not be empty or whitespace-only")
        return stripped


class _VaultBase(BaseModel):

    vault_id: str = Field(
        ...,
        description="UUID4 that uniquely identifies the vault.",
        examples=["3fa85f64-5717-4562-b3fc-2c963f66afa6"],
    )
    name: str = Field(
        ...,
        description="Human-readable vault name as stored.",
        examples=["My Private Notes"],
    )
    created_at: datetime = Field(
        ...,
        description="UTC timestamp of vault creation in ISO-8601 format.",
    )
    status: str = Field(
        ...,
        description="Current vault status.",
        examples=["locked"],
    )

    model_config = {"from_attributes": True}


class VaultResponse(_VaultBase):
    pass


class VaultSummary(_VaultBase):
    pass


class VaultStateResponse(BaseModel):

    vault_id: str = Field(
        ...,
        description="UUID4 that uniquely identifies the vault.",
        examples=["3fa85f64-5717-4562-b3fc-2c963f66afa6"],
    )
    status: str = Field(
        ...,
        description="Current vault status after the state transition.",
        examples=["locked", "unlocked"],
    )

    model_config = {"from_attributes": True}

