
from datetime import datetime

from pydantic import BaseModel, Field


class _DocumentBase(BaseModel):

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
    pass


class DocumentListResponse(BaseModel):

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


class DocumentChunkMetadata(BaseModel):
    chunk_id: str = Field(..., description="Deterministic SHA-256 hash identifier for the chunk.")
    document_id: str = Field(..., description="Parent document UUID4.")
    chunk_index: int = Field(..., ge=0, description="0-indexed position of chunk within document.")
    character_count: int = Field(..., ge=0, description="Character count of chunk text.")
    page_number: int | None = Field(default=None, description="Page number if extracted from paginated format (PDF).")
    text: str = Field(..., description="In-memory extracted chunk text.")


class DocumentProcessingResponse(BaseModel):
    document_id: str = Field(..., description="UUID4 of the processed document.")
    processing_status: str = Field(..., description="Processing status (e.g. 'processed').")
    chunk_count: int = Field(..., ge=0, description="Total number of chunks generated.")
    processed_at: datetime = Field(..., description="UTC timestamp of completion.")
    extraction_version: str = Field(default="1.0")
    chunking_version: str = Field(default="1.0")
    chunks: list[DocumentChunkMetadata] = Field(default_factory=list, description="In-memory list of generated chunks.")

    model_config = {"from_attributes": True}

