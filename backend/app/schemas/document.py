"""
schemas/document.py
-------------------
Pydantic models that define the public API contract for document endpoints.

Keeping schemas separate from storage models means:

* The wire format (what the client sees) can evolve independently of how
  data is persisted on disk.
* Response models act as an explicit allow-list — only declared fields are
  ever sent to the caller.  Internal fields (filesystem paths, raw key
  material, etc.) can never accidentally leak.
* Validation rules live in one place, not scattered across routes or
  services.
"""

from datetime import datetime

from pydantic import BaseModel, Field



class _DocumentBase(BaseModel):
    """
    Fields common to every document response shape.

    A private base class keeps field definitions in a single place while
    allowing :class:`DocumentResponse` and any future detail/summary
    variants to diverge without breaking each other.
    """

    document_id: str = Field(
        ...,
        description="UUID4 that uniquely identifies the document within its vault.",
        examples=["550e8400-e29b-41d4-a716-446655440000"],
    )
    original_filename: str = Field(
        ...,
        description="The filename that was supplied at upload time.",
        examples=["report.pdf", "notes.txt"],
    )
    mime_type: str = Field(
        ...,
        description="MIME type inferred from the uploaded file's content-type header.",
        examples=["application/pdf", "text/plain"],
    )
    size: int = Field(
        ...,
        ge=0,
        description="Size of the *plaintext* file in bytes.",
        examples=[204800],
    )
    uploaded_at: datetime = Field(
        ...,
        description="UTC timestamp at which the document was uploaded and encrypted.",
    )
    encryption_version: str = Field(
        ...,
        description=(
            "Encryption scheme identifier stored alongside each document. "
            "Allows future migration when the encryption scheme changes."
        ),
        examples=["AES-256-GCM-v1"],
    )

    model_config = {"from_attributes": True}



class DocumentResponse(_DocumentBase):
    """
    Serialised document metadata returned after a successful upload
    (``POST /vaults/{vault_id}/documents`` — HTTP 201) or as a list item
    in ``GET /vaults/{vault_id}/documents`` (HTTP 200).

    Intentionally contains **no** encrypted data, no nonce, and no key
    material.  The encrypted binary blob is stored separately on disk and
    is never returned through this endpoint.
    """



class DocumentListResponse(BaseModel):
    """
    Envelope returned by ``GET /vaults/{vault_id}/documents``.

    Wrapping the list in an envelope (rather than returning a bare JSON
    array) keeps the response extensible — future pagination, total counts,
    or vault-level summaries can be added as top-level fields without
    changing the shape of the ``documents`` array.
    """

    vault_id: str = Field(
        ...,
        description="UUID4 of the vault whose document list is returned.",
    )
    count: int = Field(
        ...,
        ge=0,
        description="Total number of documents currently stored in the vault.",
    )
    documents: list[DocumentResponse] = Field(
        default_factory=list,
        description="Document metadata entries, sorted by upload time descending.",
    )



class VerifyIntegrityResponse(BaseModel):
    """
    Response returned by ``GET /vaults/{vault_id}/documents/{document_id}/verify``.

    A successful response indicates that the SHA-256 hash of the stored
    encrypted blob matches the hash recorded at upload time.  This means the
    ciphertext has not been modified or corrupted since it was written.

    The stored hash (``sha256_ciphertext``) is intentionally **not** included
    in the response to avoid giving attackers a reference value they could use
    to craft a replacement blob.

    Extensibility
    -------------
    * **Digital signature**: add a ``signature`` field containing an Ed25519
      signature of the hash so clients can verify it independently.
    * **Algorithm field**: add ``hash_algorithm: str = "sha256"`` for
      future algorithm agility.
    * **Blockchain anchor**: add ``blockchain_tx_id: str | None`` for an
      optional reference to an on-chain notarization record.
    * **Audit trail**: this response shape is the canonical record format for
      an append-only integrity audit log.
    """

    verified: bool = Field(
        ...,
        description=(
            "``true`` when the stored hash matches the recomputed hash. "
            "This field is always ``true`` in a 200 response — a mismatch "
            "raises an error rather than returning ``false``."
        ),
    )
    document_id: str = Field(
        ...,
        description="UUID4 of the document that was verified.",
        examples=["550e8400-e29b-41d4-a716-446655440000"],
    )
    checked_at: str = Field(
        ...,
        description="UTC ISO-8601 timestamp at which verification was performed.",
        examples=["2026-08-06T08:00:00.000000+00:00"],
    )

    model_config = {"from_attributes": True}
