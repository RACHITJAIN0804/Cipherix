"""
schemas/vault.py
----------------
Pydantic models that define the public contract for vault-related API
endpoints.

Separating schemas from domain objects (VaultManager, etc.) means:

* The API layer can evolve its wire format without touching business logic.
* Validation rules live in one place — not scattered across routes or
  services.
* Response models provide an explicit allow-list of fields that are safe
  to return to clients, preventing accidental data leakage.
"""

from datetime import datetime

from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Request
# ---------------------------------------------------------------------------


class CreateVaultRequest(BaseModel):
    """
    Validated payload for ``POST /vaults``.

    Pydantic trims leading/trailing whitespace via ``str.strip()`` in
    the validator *before* the length check runs, so a name of ``"  ab  "``
    is normalised to ``"ab"`` and then rejected for being too short.
    """

    name: str = Field(
        ...,
        min_length=3,
        max_length=50,
        description="Human-readable vault name (3–50 characters after trimming).",
        examples=["My Private Notes", "Work Projects"],
    )

    @field_validator("name", mode="before")
    @classmethod
    def strip_whitespace(cls, value: str) -> str:
        """
        Normalise the name before length constraints are evaluated.

        Stripping here (``mode="before"``) means Pydantic's built-in
        ``min_length`` / ``max_length`` checks operate on the *clean*
        string, not the raw user input.

        Raises
        ------
        ValueError
            If the value is not a string, or is empty after stripping.
        """
        if not isinstance(value, str):
            raise ValueError("name must be a string")
        stripped = value.strip()
        if not stripped:
            raise ValueError("name must not be empty or whitespace-only")
        return stripped


# ---------------------------------------------------------------------------
# Response
# ---------------------------------------------------------------------------


class VaultResponse(BaseModel):
    """
    Serialised vault data returned to the API consumer after successful
    creation.

    Only the fields that are safe and relevant for clients are exposed
    here.  Internal implementation details (filesystem paths, encryption
    keys, etc.) must never appear in this model.
    """

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


# ---------------------------------------------------------------------------
# List
# ---------------------------------------------------------------------------


class VaultSummary(BaseModel):
    """
    Compact vault representation used in ``GET /vaults`` list responses.

    Intentionally kept separate from :class:`VaultResponse` even though the
    fields are currently identical.  The two models serve different semantic
    roles:

    * :class:`VaultResponse` is a **creation receipt** — returned with 201
      after a vault is successfully scaffolded.
    * :class:`VaultSummary` is a **list item** — one entry in the array
      returned by the listing endpoint.

    Keeping them separate means adding a field to one (e.g. ``file_count``
    to ``VaultSummary``) never forces a change to the other.
    """

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
