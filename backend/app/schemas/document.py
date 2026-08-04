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


# ---------------------------------------------------------------------------
# Shared base (internal — not part of the public API surface)
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Single document response
# ---------------------------------------------------------------------------


class DocumentResponse(_DocumentBase):
    """
    Serialised document metadata returned after a successful upload
    (``POST /vaults/{vault_id}/documents`` — HTTP 201) or as a list item
    in ``GET /vaults/{vault_id}/documents`` (HTTP 200).

    Intentionally contains **no** encrypted data, no nonce, and no key
    material.  The encrypted binary blob is stored separately on disk and
    is never returned through this endpoint.
    """


# ---------------------------------------------------------------------------
# List response
# ---------------------------------------------------------------------------


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
