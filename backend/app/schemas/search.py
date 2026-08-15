"""
schemas/search.py
------------------
Pydantic schemas for vector-based semantic search API.
"""

from typing import Optional
from pydantic import BaseModel, Field


class SearchRequest(BaseModel):
    """Payload for initiating a vault-isolated semantic search query."""

    vault_id: str = Field(
        ...,
        description="UUID of the authorized target vault to search within.",
        json_schema_extra={"example": "123e4567-e89b-12d3-a456-426614174000"},
    )
    query: str = Field(
        ...,
        min_length=1,
        max_length=2000,
        description="Natural language search query text.",
        json_schema_extra={"example": "What are the main security requirements for encryption?"},
    )
    top_k: Optional[int] = Field(
        default=None,
        ge=1,
        le=50,
        description="Maximum number of relevant chunks to return (default is setting search_default_top_k).",
        json_schema_extra={"example": 5},
    )



class SearchResultItem(BaseModel):
    """Matching document text chunk with similarity score and metadata."""

    chunk_id: str = Field(..., description="Unique deterministic SHA-256 chunk identifier.")
    document_id: str = Field(..., description="UUID of the parent document.")
    vault_id: str = Field(..., description="UUID of the parent vault.")
    chunk_index: int = Field(..., description="0-indexed position of chunk within document.")
    character_count: int = Field(..., description="Character count of chunk text.")
    page_number: Optional[int] = Field(default=None, description="Page number if extracted from paginated file.")
    similarity_score: float = Field(..., description="Cosine similarity score between 0.0 and 1.0.")
    text: str = Field(..., description="Chunk text content.")
    original_filename: Optional[str] = Field(default=None, description="Original filename of source document.")


class SearchResponse(BaseModel):
    """Response containing ranked semantic search results for authorized vault."""

    vault_id: str = Field(..., description="UUID of the searched vault.")
    query: str = Field(..., description="Echoed search query string.")
    total_results: int = Field(..., description="Number of relevant matching chunks returned.")
    results: list[SearchResultItem] = Field(..., description="List of matching chunk search items.")
