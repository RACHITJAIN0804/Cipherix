"""
services/vector_store.py
-------------------------
Local persistent vector storage service using ChromaDB for Cipherix.

Enforces strict vault isolation by requiring vault_id filtering on all vector queries.
"""

from pathlib import Path
from typing import Any, Optional

import chromadb
from chromadb.config import Settings as ChromaSettings

from app.core.config import settings
from app.core.exceptions import DocumentProcessingError
from app.core.logger import get_logger
from app.services.document_processing.chunker import DocumentChunk

logger = get_logger(__name__)

# Module-level cache for ChromaDB client and collection
_client_instance: Optional[chromadb.PersistentClient] = None
_collection_instance = None
_COLLECTION_NAME = "cipherix_chunks"


def get_vector_store_client(db_dir: Path | None = None) -> chromadb.PersistentClient:
    """
    Get or initialize persistent ChromaDB client instance.
    """
    global _client_instance
    target_dir = db_dir or (settings.VECTOR_DB_DIR / settings.vector_db_dir_name)

    if _client_instance is not None:
        return _client_instance

    target_dir.mkdir(parents=True, exist_ok=True)
    logger.info("Initializing ChromaDB persistent client at %s", target_dir)

    _client_instance = chromadb.PersistentClient(
        path=str(target_dir),
        settings=ChromaSettings(
            anonymized_telemetry=False,
            allow_reset=True,
        ),
    )
    return _client_instance


def get_chunks_collection(db_dir: Path | None = None):
    """
    Get or create the ChromaDB collection for chunk embeddings.
    """
    global _collection_instance
    if _collection_instance is not None and db_dir is None:
        return _collection_instance

    client = get_vector_store_client(db_dir)
    collection = client.get_or_create_collection(
        name=_COLLECTION_NAME,
        metadata={"hnsw:space": "cosine"},
    )
    if db_dir is None:
        _collection_instance = collection
    return collection


class VectorStore:
    """
    Service wrapper around ChromaDB persistent vector storage for text chunks.
    """

    def __init__(self, db_dir: Path | None = None) -> None:
        self._db_dir = db_dir

    def _get_collection(self):
        return get_chunks_collection(self._db_dir)

    def add_chunks(
        self,
        chunks: list[DocumentChunk],
        embeddings: list[list[float]],
        vault_id: str,
        document_id: str,
        embedding_model: str | None = None,
    ) -> None:
        """
        Add or replace chunk vector embeddings for a document in ChromaDB.

        Parameters
        ----------
        chunks:
            List of DocumentChunk instances.
        embeddings:
            Corresponding embedding float vectors.
        vault_id:
            UUID of the target vault.
        document_id:
            UUID of the target document.
        embedding_model:
            Name of the embedding model used.
        """
        if not chunks or not embeddings:
            return

        if len(chunks) != len(embeddings):
            raise DocumentProcessingError("Mismatch between chunk count and embedding count.")

        try:
            collection = self._get_collection()

            ids: list[str] = []
            documents: list[str] = []
            metadatas: list[dict[str, Any]] = []
            vecs: list[list[float]] = []

            model_label = embedding_model or settings.embedding_model_name

            for chunk, emb in zip(chunks, embeddings):
                ids.append(chunk.chunk_id)
                documents.append(chunk.text)
                vecs.append(emb)
                metadatas.append(
                    {
                        "chunk_id": chunk.chunk_id,
                        "document_id": document_id,
                        "vault_id": vault_id,
                        "chunk_index": chunk.chunk_index,
                        "character_count": chunk.character_count,
                        "page_number": chunk.page_number if chunk.page_number is not None else -1,
                        "embedding_model": model_label,
                    }
                )

            # First remove existing vectors for this document to ensure clean re-indexing
            self.delete_document_vectors(document_id=document_id, vault_id=vault_id)

            collection.add(
                ids=ids,
                embeddings=vecs,
                documents=documents,
                metadatas=metadatas,
            )


            logger.info(
                "Added vector embeddings | vault_id=%s | document_id=%s | count=%d",
                vault_id,
                document_id,
                len(ids),
            )
        except Exception as exc:
            logger.error("Failed to insert vectors into ChromaDB | document_id=%s | error=%s", document_id, exc)
            raise DocumentProcessingError(
                f"Vector store insertion failed for document '{document_id}': {exc}",
                detail=str(exc),
            ) from exc

    def delete_document_vectors(self, document_id: str, vault_id: str | None = None) -> int:
        """
        Delete all vector embeddings belonging to a specific document.

        Returns deleted count estimation (or 0).
        """
        collection = self._get_collection()
        where_clause: dict[str, Any] = {"document_id": document_id}
        if vault_id:
            where_clause = {"$and": [{"document_id": document_id}, {"vault_id": vault_id}]}

        try:
            # Query existing to check if present
            existing = collection.get(where={"document_id": document_id})
            count = len(existing.get("ids", []))
            if count > 0:
                collection.delete(where={"document_id": document_id})
                logger.info("Deleted document vectors | document_id=%s | count=%d", document_id, count)
            return count
        except Exception as exc:
            logger.error("Failed deleting document vectors | document_id=%s | error=%s", document_id, exc)
            raise DocumentProcessingError(
                f"Vector store deletion failed for document '{document_id}': {exc}",
                detail=str(exc),
            ) from exc

    def delete_vault_vectors(self, vault_id: str) -> int:
        """
        Delete all vector embeddings belonging to a target vault.

        Returns deleted count estimation.
        """
        collection = self._get_collection()
        try:
            existing = collection.get(where={"vault_id": vault_id})
            count = len(existing.get("ids", []))
            if count > 0:
                collection.delete(where={"vault_id": vault_id})
                logger.info("Deleted vault vectors | vault_id=%s | count=%d", vault_id, count)
            return count
        except Exception as exc:
            logger.error("Failed deleting vault vectors | vault_id=%s | error=%s", vault_id, exc)
            raise DocumentProcessingError(
                f"Vector store deletion failed for vault '{vault_id}': {exc}",
                detail=str(exc),
            ) from exc

    def search_vault(
        self,
        query_embedding: list[float],
        vault_id: str,
        top_k: int = 5,
    ) -> list[dict[str, Any]]:
        """
        Execute semantic similarity search strictly filtered by vault_id.

        Parameters
        ----------
        query_embedding:
            Embedding vector for search query string.
        vault_id:
            Authorized vault UUID.
        top_k:
            Maximum number of nearest neighbor chunks to return.

        Returns
        -------
        list[dict[str, Any]]:
            Ranked list of matching result dictionaries containing chunk metadata,
            similarity score, and text.
        """
        if not vault_id:
            raise DocumentProcessingError("vault_id is required for vector search.")

        collection = self._get_collection()

        try:
            results = collection.query(
                query_embeddings=[query_embedding],
                n_results=top_k,
                where={"vault_id": vault_id},  # MANDATORY VAULT ISOLATION FILTER
                include=["documents", "metadatas", "distances"],
            )

            formatted_results: list[dict[str, Any]] = []

            if not results or not results.get("ids") or not results["ids"][0]:
                return []

            ids = results["ids"][0]
            documents = results["documents"][0] if results.get("documents") else []
            metadatas = results["metadatas"][0] if results.get("metadatas") else []
            distances = results["distances"][0] if results.get("distances") else []

            for cid, doc_text, meta, dist in zip(ids, documents, metadatas, distances):
                # Convert cosine distance to cosine similarity: sim = 1.0 - dist
                similarity = max(0.0, min(1.0, 1.0 - float(dist)))
                page_num = meta.get("page_number")
                if page_num == -1:
                    page_num = None

                formatted_results.append(
                    {
                        "chunk_id": cid,
                        "document_id": meta.get("document_id"),
                        "vault_id": meta.get("vault_id"),
                        "chunk_index": meta.get("chunk_index"),
                        "character_count": meta.get("character_count"),
                        "page_number": page_num,
                        "similarity_score": similarity,
                        "distance": float(dist),
                        "text": doc_text,
                    }
                )

            logger.info(
                "Executed vault vector search | vault_id=%s | top_k=%d | matches=%d",
                vault_id,
                top_k,
                len(formatted_results),
            )
            return formatted_results

        except Exception as exc:
            logger.error("Vector search query failed | vault_id=%s | error=%s", vault_id, exc)
            raise DocumentProcessingError(
                f"Vector search failed for vault '{vault_id}': {exc}",
                detail=str(exc),
            ) from exc
