"""
schemas/security.py
-------------------
Pydantic models for the public API contract of security operations.

Keeping security schemas separate from ``schemas/vault.py`` leaves room
for future additions: recovery seed responses, hardware key registration
requests, multi-device sync tokens, etc.

No cryptographic material — keys, salts, or hashes — ever appears in
these models.  Passwords are used ephemerally and discarded before any
response is constructed.
"""

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Request
# ---------------------------------------------------------------------------


class ChangePasswordRequest(BaseModel):
    """
    Validated payload for ``POST /vaults/{vault_id}/change-password``.

    Pydantic enforces minimum length before the request reaches the service
    layer.  The service layer performs additional cryptographic verification:
    ``old_password`` must successfully decrypt the Vault Key before
    ``new_password`` is used to re-wrap it.

    Neither password is ever logged, stored, or included in any response.
    """

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


# ---------------------------------------------------------------------------
# Response
# ---------------------------------------------------------------------------


class ChangePasswordResponse(BaseModel):
    """
    Minimal receipt returned by ``POST /vaults/{vault_id}/change-password``
    (HTTP 200).

    Contains no cryptographic material — only the vault identifier and the
    timestamp of the completed re-wrap operation.

    Extensibility
    -------------
    * **Recovery seed**: add ``recovery_seed_invalidated: bool`` to signal
      that a previously issued seed is now stale and must be regenerated.
    * **Hardware key**: add ``hardware_key_rewrap_required: bool`` to
      indicate that hardware-key-wrapped copies of the Vault Key need
      updating.
    * **Audit**: add ``event_id: str`` for correlation with an audit log.
    """

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
