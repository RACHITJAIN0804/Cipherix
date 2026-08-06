"""
storage/document_manager.py
----------------------------
Filesystem manager for encrypted document blobs and their metadata.

:class:`DocumentManager` is the single authority for all I/O related to
documents inside a vault.  Its only job is to read, write, list, and delete
files on disk.  It knows nothing about HTTP, Pydantic, business rules, or
cryptography.

Directory layout
----------------
::

    vaults/
        <vault_id>/
            encrypted/          ← raw AES-256-GCM ciphertext blobs
            │   <doc_id>.bin
            metadata/           ← JSON metadata sidecar for each document
                <doc_id>.json

Design decisions
----------------
* **Separated storage** — encrypted blobs and metadata files are stored in
  different subdirectories.  This separation allows:

  - Metadata to be read (listed, searched, validated) without touching
    large binary blobs.
  - Independent access-control policies if the OS-level permissions model
    needs to differ between encrypted data and metadata.
  - Future streaming of blobs directly to an object store while keeping
    metadata local.

* **``.bin`` extension** — unambiguous indicator that the file is binary,
  opaque, and not human-readable.  Avoids OS associations that try to
  open the file with a viewer.

* **pathlib throughout** — all path composition uses
  :class:`~pathlib.Path` objects.  No string concatenation.

* **Typed exceptions** — all errors surface as
  :class:`~app.core.exceptions.DocumentStorageError` or
  :class:`~app.core.exceptions.DocumentNotFoundError`.

* **Atomic-ish writes** — blobs are written with ``write_bytes``, metadata
  with ``write_text``.  These are not truly atomic (no temp+rename), but
  are acceptable for this milestone.  A future hardening step can add
  write-to-temp-then-rename to guarantee crash safety.

Extensibility notes
-------------------
* **Chunked storage** — replace ``write_bytes`` with a streaming loop that
  writes fixed-size chunks.  The ``.bin`` format and the metadata schema
  remain unchanged.
* **Document versioning** — add a ``versions/`` subdirectory alongside
  ``encrypted/``; archive old blobs there on re-upload.
* **Integrity** — ``sha256_ciphertext`` is stored in the metadata JSON and
  verified on demand via the ``GET /verify`` endpoint.
* **Cloud backends** — swap the ``Path.write_bytes`` / ``Path.read_bytes``
  calls for SDK calls to S3, GCS, or Azure Blob.  The service layer does
  not change.
"""

import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Iterator, Optional

from app.core.exceptions import DocumentNotFoundError, DocumentStorageError
from app.core.logger import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_ENCRYPTED_DIR: str = "encrypted"
_METADATA_DIR: str = "metadata"
_BLOB_SUFFIX: str = ".bin"
_META_SUFFIX: str = ".json"

# Version tag written into every metadata file.
# Increment when the metadata schema changes in a backward-incompatible way.
ENCRYPTION_VERSION: str = "AES-256-GCM-v1"


# ---------------------------------------------------------------------------
# Metadata model
# ---------------------------------------------------------------------------


@dataclass
class DocumentMetadata:
    """
    In-memory representation of a document's ``<doc_id>.json`` sidecar.

    Using a ``@dataclass`` (rather than a plain dict) provides:

    * Type safety and IDE auto-complete.
    * A clear schema that can be diffed when fields change.
    * Trivial serialisation via :func:`dataclasses.asdict`.

    Attributes
    ----------
    document_id:
        UUID4 string that identifies the document.  Also the stem of both
        the ``.bin`` blob and this ``.json`` metadata file.
    original_filename:
        The filename supplied by the client at upload time (after
        validation/sanitisation).
    mime_type:
        Content-type header value provided by the client (or a safe
        default if the client did not supply one).
    size:
        Plaintext file size in bytes.  The encrypted blob will be slightly
        larger (by the 16-byte GCM authentication tag + 12-byte nonce
        stored in the blob header).
    uploaded_at:
        UTC ISO-8601 timestamp at which the document was accepted and
        encrypted.
    encryption_version:
        Identifies the encryption scheme used.  Allows future migrations
        to detect old-format blobs and re-encrypt them.
    nonce:
        Base64-encoded 12-byte AES-GCM nonce prepended to every blob.
        Stored here (not in the blob itself) so the decryption path can
        read the nonce without parsing the binary format.
    sha256_ciphertext:
        Lowercase hex SHA-256 digest of the **ciphertext** blob, computed
        immediately after AES-256-GCM encryption at upload time.  ``None``
        for documents uploaded before integrity verification was introduced.
        This field is the basis for the ``GET /verify`` endpoint and is
        the value that would be published to a blockchain anchor or
        digital-signature scheme.  Plaintext is never hashed.
    """

    document_id: str
    original_filename: str
    mime_type: str
    size: int
    uploaded_at: str
    nonce: str
    encryption_version: str = field(default=ENCRYPTION_VERSION)
    sha256_ciphertext: Optional[str] = field(default=None)

    # ------------------------------------------------------------------
    # Factory helpers
    # ------------------------------------------------------------------

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
        """
        Build a fresh :class:`DocumentMetadata` for a document being stored *now*.

        Parameters
        ----------
        document_id:
            The UUID4 string that identifies this document.
        original_filename:
            Sanitised filename from the upload.
        mime_type:
            MIME type from the upload (or ``"application/octet-stream"``
            when the client did not specify one).
        size:
            Plaintext byte length of the uploaded file.
        nonce:
            Base64-encoded 12-byte AES-GCM nonce used for this document.
        sha256_ciphertext:
            Lowercase hex SHA-256 digest of the ciphertext blob, computed
            immediately after AES-256-GCM encryption.
        """
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
        """
        Serialise and write this metadata object to ``path`` as JSON.

        Parameters
        ----------
        path:
            Absolute path to the target ``.json`` file.

        Raises
        ------
        OSError
            Propagated from :meth:`pathlib.Path.write_text` on I/O failure.
        """
        path.write_text(json.dumps(asdict(self), indent=2), encoding="utf-8")

    @classmethod
    def read(cls, path: Path) -> "DocumentMetadata":
        """
        Deserialise a ``.json`` file into a :class:`DocumentMetadata`.

        Unknown keys are silently dropped, allowing forward-compatible
        reads when older code reads a newer metadata schema.

        Parameters
        ----------
        path:
            Absolute path to the ``.json`` file.

        Returns
        -------
        DocumentMetadata

        Raises
        ------
        OSError
            If the file cannot be read.
        ValueError
            If the file contains invalid JSON or is missing required fields.
        """
        raw: dict = json.loads(path.read_text(encoding="utf-8"))
        known_fields = {f.name for f in cls.__dataclass_fields__.values()}  # type: ignore[attr-defined]
        filtered = {k: v for k, v in raw.items() if k in known_fields}
        return cls(**filtered)


# ---------------------------------------------------------------------------
# Manager
# ---------------------------------------------------------------------------


class DocumentManager:
    """
    Filesystem manager for a single vault's document store.

    Instantiated with the vault root directory and exposes methods to
    write, read, list, and delete document blobs and their metadata files.

    Parameters
    ----------
    vault_root:
        Absolute path to the vault's root directory
        (e.g. ``/data/vaults/<vault_id>/``).

    Notes
    -----
    :class:`DocumentManager` never creates the vault root itself —
    that is the responsibility of :class:`~app.vault.vault_manager.VaultManager`.
    It does, however, create the ``encrypted/`` and ``metadata/``
    subdirectories lazily if they are somehow absent (defensive guard only;
    they should already exist after vault creation).
    """

    def __init__(self, vault_root: Path) -> None:
        self._vault_root: Path = vault_root
        self._encrypted_dir: Path = vault_root / _ENCRYPTED_DIR
        self._metadata_dir: Path = vault_root / _METADATA_DIR

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def write_blob(
        self,
        document_id: str,
        ciphertext: bytes,
        vault_id: str,
    ) -> Path:
        """
        Write an encrypted blob to ``encrypted/<document_id>.bin``.

        Parameters
        ----------
        document_id:
            UUID4 string identifying the document.
        ciphertext:
            Raw AES-256-GCM ciphertext bytes (includes the 16-byte GCM tag).
        vault_id:
            Used only in log and error messages.

        Returns
        -------
        Path
            Absolute path of the written blob file.

        Raises
        ------
        DocumentStorageError
            If the blob cannot be written (permission denied, disk full, etc.).
        """
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
        """
        Serialise and write ``<document_id>.json`` to ``metadata/``.

        Parameters
        ----------
        metadata:
            Fully populated :class:`DocumentMetadata` instance.
        vault_id:
            Used only in log and error messages.

        Returns
        -------
        Path
            Absolute path of the written metadata file.

        Raises
        ------
        DocumentStorageError
            If the metadata file cannot be written.
        """
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

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def read_blob(self, document_id: str, vault_id: str) -> bytes:
        """
        Read and return the raw ciphertext from ``encrypted/<document_id>.bin``.

        Parameters
        ----------
        document_id:
            UUID4 string identifying the document.
        vault_id:
            Used only in log and error messages.

        Returns
        -------
        bytes
            Raw AES-256-GCM ciphertext bytes.

        Raises
        ------
        DocumentNotFoundError
            If the blob file does not exist.
        DocumentStorageError
            If the file exists but cannot be read.
        """
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
        """
        Deserialise and return ``metadata/<document_id>.json``.

        Parameters
        ----------
        document_id:
            UUID4 string identifying the document.
        vault_id:
            Used only in log and error messages.

        Returns
        -------
        DocumentMetadata

        Raises
        ------
        DocumentNotFoundError
            If the metadata file does not exist.
        DocumentStorageError
            If the file exists but cannot be read or parsed.
        """
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
        """
        Return metadata for all documents currently stored in the vault.

        Iterates over every ``.json`` file in ``metadata/`` and
        deserialises it.  Files that fail to parse are logged and skipped
        (best-effort listing — one corrupt sidecar must not hide all others).

        Results are sorted by ``uploaded_at`` in descending order (newest
        document first) to match the expected API ordering.

        Parameters
        ----------
        vault_id:
            Used only in log and error messages.

        Returns
        -------
        list[DocumentMetadata]
            Possibly empty list of document metadata entries.
        """
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

    # ------------------------------------------------------------------
    # Delete
    # ------------------------------------------------------------------

    def delete_document(self, document_id: str, vault_id: str) -> None:
        """
        Delete both the encrypted blob and the metadata sidecar for a document.

        This is a **best-effort two-phase delete**: the blob is removed
        first; if the blob delete succeeds but the metadata delete fails,
        the metadata file is left as an orphan and the error is raised.
        This is an acceptable trade-off for this milestone — a future
        hardening step can add a transaction-log approach.

        Parameters
        ----------
        document_id:
            UUID4 string identifying the document.
        vault_id:
            Used only in log and error messages.

        Raises
        ------
        DocumentNotFoundError
            If neither the blob nor the metadata file exist.
        DocumentStorageError
            If deletion of either file fails due to an OS error.
        """
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

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _blob_path(self, document_id: str) -> Path:
        """Return the absolute path for a document's encrypted blob."""
        return self._encrypted_dir / f"{document_id}{_BLOB_SUFFIX}"

    def _meta_path(self, document_id: str) -> Path:
        """Return the absolute path for a document's metadata sidecar."""
        return self._metadata_dir / f"{document_id}{_META_SUFFIX}"

    def _iter_metadata_files(self) -> Iterator[Path]:
        """Yield every ``.json`` file in the metadata directory."""
        return self._metadata_dir.glob(f"*{_META_SUFFIX}")

    def _ensure_encrypted_dir(self, vault_id: str) -> None:
        """
        Create ``encrypted/`` if it does not exist.

        This is a defensive guard — the directory should already exist after
        vault scaffolding.  Creating it here prevents an otherwise confusing
        ``FileNotFoundError`` if the directory was manually removed.
        """
        if not self._encrypted_dir.is_dir():
            logger.warning(
                "encrypted/ directory missing, recreating | vault_id=%s", vault_id
            )
            self._encrypted_dir.mkdir(parents=True, exist_ok=True)

    def _ensure_metadata_dir(self, vault_id: str) -> None:
        """
        Create ``metadata/`` if it does not exist.

        Same defensive rationale as :meth:`_ensure_encrypted_dir`.
        """
        if not self._metadata_dir.is_dir():
            logger.warning(
                "metadata/ directory missing, recreating | vault_id=%s", vault_id
            )
            self._metadata_dir.mkdir(parents=True, exist_ok=True)
