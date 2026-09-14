
import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Iterator, Optional

from app.core.exceptions import DocumentNotFoundError, DocumentStorageError
from app.core.logger import get_logger

logger = get_logger(__name__)

_ENCRYPTED_DIR: str = "encrypted"
_METADATA_DIR: str = "metadata"
_BLOB_SUFFIX: str = ".bin"
_META_SUFFIX: str = ".json"


ENCRYPTION_VERSION: str = "AES-256-GCM-v1"


@dataclass
class DocumentMetadata:

    document_id: str
    original_filename: str
    mime_type: str
    size: int
    uploaded_at: str
    nonce: str
    encryption_version: str = field(default=ENCRYPTION_VERSION)
    sha256_ciphertext: Optional[str] = field(default=None)

    @classmethod
    def create(
        cls,
        document_id: str,
        original_filename: str,
        mime_type: str,
        size: int,
        nonce: str,
        sha256_ciphertext: str,
    ) -> "DocumentMetadata":
        return cls(
            document_id=document_id,
            original_filename=original_filename,
            mime_type=mime_type,
            size=size,
            nonce=nonce,
            sha256_ciphertext=sha256_ciphertext,
            uploaded_at=datetime.now(UTC).isoformat(),
        )

    def write(self, path: Path) -> None:
        path.write_text(json.dumps(asdict(self), indent=2), encoding="utf-8")

    @classmethod
    def read(cls, path: Path) -> "DocumentMetadata":
        raw: dict = json.loads(path.read_text(encoding="utf-8"))
        known_fields = {f.name for f in cls.__dataclass_fields__.values()}  # type: ignore[attr-defined]
        filtered = {k: v for k, v in raw.items() if k in known_fields}
        return cls(**filtered)


class DocumentManager:

    def __init__(self, vault_root: Path) -> None:
        self._vault_root: Path = vault_root
        self._encrypted_dir: Path = vault_root / _ENCRYPTED_DIR
        self._metadata_dir: Path = vault_root / _METADATA_DIR

    def write_blob(
        self,
        document_id: str,
        ciphertext: bytes,
        vault_id: str,
    ) -> Path:
        self._ensure_encrypted_dir(vault_id)
        blob_path = self._blob_path(document_id)

        logger.debug(
            "Writing encrypted blob | vault_id=%s | document_id=%s | bytes=%d",
            vault_id,
            document_id,
            len(ciphertext),
        )

        try:
            blob_path.write_bytes(ciphertext)
        except OSError as exc:
            raise DocumentStorageError(
                f"Failed to write encrypted blob for document '{document_id}' "
                f"in vault '{vault_id}': {exc}",
                detail=(
                    f"The encrypted file could not be written to disk. "
                    f"OS error: {exc.strerror}. Check filesystem permissions."
                ),
            ) from exc

        logger.info(
            "Encrypted blob written | vault_id=%s | document_id=%s | path=%s",
            vault_id,
            document_id,
            blob_path,
        )
        return blob_path

    def write_metadata(
        self,
        metadata: DocumentMetadata,
        vault_id: str,
    ) -> Path:
        self._ensure_metadata_dir(vault_id)
        meta_path = self._meta_path(metadata.document_id)

        logger.debug(
            "Writing document metadata | vault_id=%s | document_id=%s",
            vault_id,
            metadata.document_id,
        )

        try:
            metadata.write(meta_path)
        except OSError as exc:
            raise DocumentStorageError(
                f"Failed to write metadata for document '{metadata.document_id}' "
                f"in vault '{vault_id}': {exc}",
                detail=(
                    f"Document metadata could not be persisted. "
                    f"OS error: {exc.strerror}. Check filesystem permissions."
                ),
            ) from exc

        logger.info(
            "Document metadata written | vault_id=%s | document_id=%s | path=%s",
            vault_id,
            metadata.document_id,
            meta_path,
        )
        return meta_path

    def read_blob(self, document_id: str, vault_id: str) -> bytes:
        blob_path = self._blob_path(document_id)

        if not blob_path.is_file():
            raise DocumentNotFoundError(
                f"Encrypted blob not found for document '{document_id}' "
                f"in vault '{vault_id}'.",
                detail=(
                    f"No encrypted file exists at '{blob_path}'. "
                    "The document may have been deleted or never uploaded."
                ),
            )

        try:
            return blob_path.read_bytes()
        except OSError as exc:
            raise DocumentStorageError(
                f"Failed to read encrypted blob for document '{document_id}': {exc}",
                detail=f"OS error reading encrypted file: {exc.strerror}.",
            ) from exc

    def read_metadata(self, document_id: str, vault_id: str) -> DocumentMetadata:
        meta_path = self._meta_path(document_id)

        if not meta_path.is_file():
            raise DocumentNotFoundError(
                f"Metadata not found for document '{document_id}' "
                f"in vault '{vault_id}'.",
                detail=(
                    f"No metadata file exists at '{meta_path}'. "
                    "The document may have been deleted or never uploaded."
                ),
            )

        try:
            return DocumentMetadata.read(meta_path)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise DocumentStorageError(
                f"Failed to parse metadata for document '{document_id}': {exc}",
                detail=(
                    f"Document metadata at '{meta_path}' could not be parsed. "
                    "The file may be corrupt."
                ),
            ) from exc

    def list_metadata(self, vault_id: str) -> list[DocumentMetadata]:
        if not self._metadata_dir.is_dir():
            logger.debug(
                "metadata/ directory does not exist | vault_id=%s", vault_id
            )
            return []

        results: list[DocumentMetadata] = []

        for meta_path in self._iter_metadata_files():
            try:
                results.append(DocumentMetadata.read(meta_path))
            except (OSError, ValueError, KeyError, TypeError) as exc:
                logger.warning(
                    "Skipping unreadable metadata file | vault_id=%s | path=%s | error=%s",
                    vault_id,
                    meta_path,
                    exc,
                )

        results.sort(key=lambda m: m.uploaded_at, reverse=True)

        logger.debug(
            "Listed document metadata | vault_id=%s | count=%d",
            vault_id,
            len(results),
        )
        return results

    def delete_document(self, document_id: str, vault_id: str) -> None:
        blob_path = self._blob_path(document_id)
        meta_path = self._meta_path(document_id)

        blob_exists = blob_path.is_file()
        meta_exists = meta_path.is_file()

        if not blob_exists and not meta_exists:
            raise DocumentNotFoundError(
                f"Document '{document_id}' not found in vault '{vault_id}'.",
                detail=(
                    f"Neither an encrypted blob nor a metadata file exists for "
                    f"document '{document_id}'.  It may have been already deleted."
                ),
            )

        if blob_exists:
            try:
                blob_path.unlink()
                logger.info(
                    "Encrypted blob deleted | vault_id=%s | document_id=%s",
                    vault_id,
                    document_id,
                )
            except OSError as exc:
                raise DocumentStorageError(
                    f"Failed to delete encrypted blob for document '{document_id}': {exc}",
                    detail=f"OS error deleting encrypted file: {exc.strerror}.",
                ) from exc

        if meta_exists:
            try:
                meta_path.unlink()
                logger.info(
                    "Document metadata deleted | vault_id=%s | document_id=%s",
                    vault_id,
                    document_id,
                )
            except OSError as exc:
                raise DocumentStorageError(
                    f"Failed to delete metadata for document '{document_id}': {exc}",
                    detail=f"OS error deleting metadata file: {exc.strerror}.",
                ) from exc

    def _blob_path(self, document_id: str) -> Path:
        return self._encrypted_dir / f"{document_id}{_BLOB_SUFFIX}"

    def _meta_path(self, document_id: str) -> Path:
        return self._metadata_dir / f"{document_id}{_META_SUFFIX}"

    def _iter_metadata_files(self) -> Iterator[Path]:
        return self._metadata_dir.glob(f"*{_META_SUFFIX}")

    def _ensure_encrypted_dir(self, vault_id: str) -> None:
        if not self._encrypted_dir.is_dir():
            logger.warning(
                "encrypted/ directory missing, recreating | vault_id=%s", vault_id
            )
            self._encrypted_dir.mkdir(parents=True, exist_ok=True)

    def _ensure_metadata_dir(self, vault_id: str) -> None:
        if not self._metadata_dir.is_dir():
            logger.warning(
                "metadata/ directory missing, recreating | vault_id=%s", vault_id
            )
            self._metadata_dir.mkdir(parents=True, exist_ok=True)
