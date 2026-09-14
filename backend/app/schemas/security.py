
from pydantic import BaseModel, Field


class ChangePasswordRequest(BaseModel):

    old_password: str = Field(
        ...,
        min_length=8,
        description=(
            "Current vault password.  Used to re-derive the old Master Key "
            "and decrypt the Vault Key.  Never stored or logged."
        ),
    )
    new_password: str = Field(
        ...,
        min_length=8,
        description=(
            "New vault password.  Used to derive a new Master Key and "
            "re-wrap the Vault Key.  Never stored or logged."
        ),
    )


class ChangePasswordResponse(BaseModel):

    vault_id: str = Field(
        ...,
        description="UUID4 of the vault whose password was changed.",
        examples=["3fa85f64-5717-4562-b3fc-2c963f66afa6"],
    )
    changed_at: str = Field(
        ...,
        description="UTC ISO-8601 timestamp at which the re-wrap completed.",
        examples=["2026-08-06T08:00:00.000000+00:00"],
    )

    model_config = {"from_attributes": True}


class RecoverySeedResponse(BaseModel):

    vault_id: str = Field(
        ...,
        description="UUID4 of the vault for which the recovery seed was generated.",
        examples=["3fa85f64-5717-4562-b3fc-2c963f66afa6"],
    )
    seed: str = Field(
        ...,
        description=(
            "24-word BIP-39 recovery mnemonic.  Write this down and store it securely.  "
            "It will NOT be shown again."
        ),
    )
    algorithm: str = Field(
        ...,
        description="Mnemonic generation algorithm.",
        examples=["BIP39-24-SHA256"],
    )
    word_count: int = Field(
        ...,
        description="Number of words in the mnemonic.",
        examples=[24],
    )
    created_at: str = Field(
        ...,
        description="UTC ISO-8601 timestamp at which the seed was generated.",
    )

    model_config = {"from_attributes": True}


class VerifySeedRequest(BaseModel):

    seed: str = Field(
        ...,
        min_length=20,
        description=(
            "Space-separated 24-word BIP-39 mnemonic to validate against the "
            "vault's stored fingerprint.  Never stored or logged."
        ),
    )


class VerifySeedResponse(BaseModel):

    vault_id: str = Field(
        ...,
        description="UUID4 of the vault against which the seed was verified.",
    )
    valid: bool = Field(
        ...,
        description=(
            "``True`` if the seed is a valid BIP-39 mnemonic and its fingerprint "
            "matches the vault's stored fingerprint.  ``False`` otherwise."
        ),
    )

    model_config = {"from_attributes": True}
