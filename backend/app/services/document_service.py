"""
services/document_service.py
-----------------------------
Business-logic layer for document upload, listing, deletion, download,
and integrity verification.

:class:`DocumentService` sits between the API route (HTTP concerns) and
the storage/cryptography layers.  Its responsibilities are:

1. **Validate** the vault state (exists, unlocked) and the upload (filename
   safe, file not empty) before doing any filesystem work.
2. **Orchestrate** the encryption pipeline: unwrap the Vault Key from
   ``key.json``, generate a nonce, encrypt the plaintext bytes, write the
   ciphertext blob, write the metadata sidecar.
3. **Orchestrate** decryption: read the ciphertext blob, read the metadata
   sidecar, unwrap the Vault Key, decrypt in memory — never writing plaintext
   to disk.
4. **Verify integrity**: read the encrypted blob, recompute its SHA-256 hash,
   compare against the stored hash.  No password or key material required.
5. **Compose** Pydantic response objects from storage dataclasses.
6. **Translate** domain exceptions into a form the route layer can act on.

This layer intentionally knows nothing about FastAPI, HTTP status codes,
or JSON serialisation.  Those concerns belong to the route.

Filename sanitisation policy
-----------------------------
* The filename must be non-empty after stripping whitespace.
* Path-traversal sequences are rejected outright.
* The sanitised name is stored in metadata; it is never used as a
  filesystem path (the UUID document_id is used instead).
"""

import hmac
import re
import uuid
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath

from app.core.exceptions import (
    CipherixError,
    CorruptedDocumentError,
    DocumentEncryptionError,
    DocumentNotFoundError,
    IntegrityVerificationError,
    InvalidUploadError,
    MissingIntegrityMetadataError,
    VaultLockedError,
    VaultNotFoundError,
)
from app.core.logger import get_logger
from app.schemas.document import (
    DocumentListResponse,
    DocumentResponse,
    VerifyIntegrityResponse,
)
from app.security.encryption import EncryptionManager
from app.security.key_manager import KeyManager
from app.security.password_manager import PasswordManager
from app.storage.document_manager import DocumentManager, DocumentMetadata
from app.vault.manifest import VaultManifest

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

_STATUS_UNLOCKED: str = "unlocked"
_DEFAULT_MIME: str = "application/octet-stream"
_MAX_FILENAME_LEN: int = 255
_FORBIDDEN_CHARS: re.Pattern = re.compile(r'[\x00<>:"/\\|?*]')


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------


class DocumentService:
    """
    Orchestrates document upload, listing, deletion, and download inside a vault.

    Parameters
    ----------
    vault_base_dir:
        Root directory under which all vault subdirectories live.
    """

    def __init__(self, vault_base_dir: Path) -> None:
        self._vault_base_dir: Path = vault_base_dir
        self._enc_mgr: EncryptionManager = EncryptionManager()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def upload_document(
        self,
        vault_id: str,
        password: str,
        filename: str,
        content_type: str | None,
        file_bytes: bytes,
    ) -> DocumentResponse:
        """
        Encrypt and store a document inside a vault.

        Flow
        ----
        1. Assert the vault exists and is unlocked.
        2. Validate and sanitise the filename.
        3. Assert the file is non-empty.
        4. Generate a UUID4 document ID.
        5. Unwrap the Vault Key from ``key.json`` using Argon2id + AES-GCM.
        6. Generate a 12-byte random nonce (OS CSPRNG).
        7. Encrypt the plaintext bytes with AES-256-GCM.
        8. Write the ciphertext blob to ``encrypted/<doc_id>.bin``.
        9. Write the metadata sidecar to ``metadata/<doc_id>.json``.
        10. Return the document metadata as a Pydantic response object.

        Parameters
        ----------
        vault_id:
            UUID4 identifying the target vault.
        password:
            The vault's unlock password (used to re-derive the Master Key
            and decrypt the Vault Key; never stored or logged).
        filename:
            Original filename from the upload (validated and sanitised here).
        content_type:
            MIME type from the ``Content-Type`` part header, or ``None``
            if absent (falls back to ``"application/octet-stream"``).
        file_bytes:
            Raw bytes of the uploaded file.

        Returns
        -------
        DocumentResponse
            Metadata of the newly encrypted and stored document.

        Raises
        ------
        VaultNotFoundError
            If the vault directory does not exist.
        VaultLockedError
            If the vault's status is not ``"unlocked"``.
        InvalidUploadError
            If the filename fails validation or the file is empty.
        DocumentEncryptionError
            If the Vault Key cannot be decrypted or AES-GCM encryption fails.
        DocumentStorageError
            If the ciphertext or metadata cannot be written to disk.
        """
        vault_root = self._assert_vault_unlocked(vault_id)
        safe_filename = self._validate_filename(filename)
        self._assert_file_not_empty(file_bytes, safe_filename)

        document_id = str(uuid.uuid4())
        mime_type = content_type or _DEFAULT_MIME

        logger.info(
            "Starting document upload | vault_id=%s | document_id=%s "
            "| filename=%s | size=%d | mime=%s",
            vault_id,
            document_id,
            safe_filename,
            len(file_bytes),
            mime_type,
        )

        # --- Step 5: Unwrap the Vault Key ---
        vault_key: bytes = self._unwrap_vault_key(vault_root, vault_id, password)

        try:
            nonce: bytes = self._enc_mgr.generate_nonce()
            ciphertext: bytes = self._enc_mgr.encrypt_bytes(
                plaintext=file_bytes,
                vault_key=vault_key,
                nonce=nonce,
            )
            nonce_b64: str = self._enc_mgr.encode_for_storage(nonce)
            sha256_ciphertext: str = self._enc_mgr.compute_sha256(ciphertext)

        except CipherixError:
            # Re-raise typed domain errors without wrapping.
            raise
        except Exception as exc:
            raise DocumentEncryptionError(
                f"Unexpected error encrypting document '{safe_filename}': {exc}",
                detail="An unexpected error occurred during document encryption.",
            ) from exc
        finally:
            # Release Vault Key bytes from local scope as soon as possible.
            try:
                del vault_key
            except NameError:
                pass

        # --- Steps 8 & 9: Persist ---
        doc_mgr = DocumentManager(vault_root)

        doc_mgr.write_blob(
            document_id=document_id,
            ciphertext=ciphertext,
            vault_id=vault_id,
        )

        metadata = DocumentMetadata.create(
            document_id=document_id,
            original_filename=safe_filename,
            mime_type=mime_type,
            size=len(file_bytes),
            nonce=nonce_b64,
            sha256_ciphertext=sha256_ciphertext,
        )

        doc_mgr.write_metadata(metadata=metadata, vault_id=vault_id)

        logger.info(
            "Document upload complete | vault_id=%s | document_id=%s | sha256=%s",
            vault_id,
            document_id,
            sha256_ciphertext[:16] + "...",
        )

        return self._metadata_to_response(metadata)

    def list_documents(self, vault_id: str) -> DocumentListResponse:
        """
        Return metadata for all documents stored in a vault.

        The vault must exist but need not be unlocked — listing metadata
        does not require decrypting any files.

        Parameters
        ----------
        vault_id:
            UUID4 identifying the target vault.

        Returns
        -------
        DocumentListResponse
            An envelope containing the vault_id, document count, and a
            list of document metadata entries sorted newest-first.

        Raises
        ------
        VaultNotFoundError
            If the vault directory does not exist.
        DocumentStorageError
            If the metadata directory is unreadable.
        """
        vault_root = self._assert_vault_exists(vault_id)

        doc_mgr = DocumentManager(vault_root)
        all_metadata = doc_mgr.list_metadata(vault_id)

        documents = [self._metadata_to_response(m) for m in all_metadata]

        logger.info(
            "Document listing | vault_id=%s | count=%d",
            vault_id,
            len(documents),
        )

        return DocumentListResponse(
            vault_id=vault_id,
            count=len(documents),
            documents=documents,
        )

    def delete_document(self, vault_id: str, document_id: str) -> None:
        """
        Delete a document's encrypted blob and metadata sidecar.

        The vault must exist but need not be unlocked — deletion does not
        require decrypting the file.

        Parameters
        ----------
        vault_id:
            UUID4 identifying the vault containing the document.
        document_id:
            UUID4 identifying the document to delete.

        Raises
        ------
        VaultNotFoundError
            If the vault directory does not exist.
        DocumentNotFoundError
            If neither the blob nor the metadata file exist for this document.
        DocumentStorageError
            If the OS cannot remove the file(s).
        """
        vault_root = self._assert_vault_exists(vault_id)

        doc_mgr = DocumentManager(vault_root)
        doc_mgr.delete_document(document_id=document_id, vault_id=vault_id)

        logger.info(
            "Document deleted | vault_id=%s | document_id=%s",
            vault_id,
            document_id,
        )

    def download_document(
        self,
        vault_id: str,
        document_id: str,
        password: str,
    ) -> tuple[bytes, DocumentMetadata]:
        """
        Decrypt and return a document's plaintext bytes and metadata.

        The decrypted content exists **only in memory** during this call.
        It is never written to any file or temp directory on disk.

        Flow
        ----
        1. Assert the vault exists and is unlocked.
        2. Read the metadata sidecar to get the stored nonce and MIME type.
        3. Assert the encrypted blob exists on disk.
        4. Unwrap the Vault Key (Argon2id + AES-GCM key-unwrap).
        5. Decrypt the blob in memory using the Vault Key and stored nonce.
        6. Return (plaintext_bytes, metadata).  Vault Key is cleared.

        Parameters
        ----------
        vault_id:
            UUID4 identifying the vault that contains the document.
        document_id:
            UUID4 identifying the document to download.
        password:
            The vault's unlock password used to re-derive the Master Key
            and decrypt the Vault Key.  Never stored or logged.

        Returns
        -------
        tuple[bytes, DocumentMetadata]
            ``(plaintext_bytes, metadata)`` where ``plaintext_bytes`` is the
            original file content and ``metadata`` carries the original
            filename and MIME type for building the HTTP response headers.

        Raises
        ------
        VaultNotFoundError
            If the vault directory does not exist.
        VaultLockedError
            If the vault's status is not ``"unlocked"``.
        DocumentNotFoundError
            If the encrypted blob or metadata sidecar does not exist.
        DocumentEncryptionError
            If the Vault Key cannot be decrypted (wrong password, corrupt
            ``key.json``, or corrupt ``password_meta.json``), or if AES-GCM
            authentication fails (tampered blob or mismatched nonce).
        DocumentStorageError
            If a file cannot be read due to an OS-level error.
        """
        vault_root = self._assert_vault_unlocked(vault_id)

        doc_mgr = DocumentManager(vault_root)

        # Read metadata first so we have the nonce before touching the blob.
        metadata: DocumentMetadata = doc_mgr.read_metadata(document_id, vault_id)
        ciphertext: bytes = doc_mgr.read_blob(document_id, vault_id)

        logger.info(
            "Starting document download | vault_id=%s | document_id=%s "
            "| filename=%s | ciphertext_bytes=%d",
            vault_id,
            document_id,
            metadata.original_filename,
            len(ciphertext),
        )

        vault_key: bytes = self._unwrap_vault_key(vault_root, vault_id, password)

        try:
            nonce: bytes = self._enc_mgr.decode_from_storage(metadata.nonce, "nonce")
            plaintext: bytes = self._enc_mgr.decrypt_bytes(
                ciphertext=ciphertext,
                vault_key=vault_key,
                nonce=nonce,
            )
        except CipherixError:
            raise
        except Exception as exc:
            raise DocumentEncryptionError(
                f"Unexpected error decrypting document '{document_id}': {exc}",
                detail="An unexpected error occurred during document decryption.",
            ) from exc
        finally:
            try:
                del vault_key
            except NameError:
                pass

        logger.info(
            "Document download complete | vault_id=%s | document_id=%s "
            "| plaintext_bytes=%d",
            vault_id,
            document_id,
            len(plaintext),
        )

        return plaintext, metadata

    def verify_document(
        self,
        vault_id: str,
        document_id: str,
    ) -> VerifyIntegrityResponse:
        """
        Verify the integrity of a stored encrypted document.

        Reads the encrypted blob from disk, recomputes its SHA-256 hash,
        and compares it against the hash recorded at upload time.  No password
        or Vault Key is required — this check operates entirely on ciphertext.

        Flow
        ----
        1. Assert the vault exists (need not be unlocked).
        2. Read the metadata sidecar; raise :class:`MissingIntegrityMetadataError`
           if ``sha256_ciphertext`` is absent (document predates this milestone).
        3. Read the encrypted blob; raise :class:`CorruptedDocumentError` if
           the file is missing or unreadable.
        4. Recompute ``sha256(ciphertext)`` via :class:`EncryptionManager`.
        5. Compare with stored hash using :func:`hmac.compare_digest` to
           prevent timing-oracle attacks.
        6. Raise :class:`IntegrityVerificationError` on mismatch.
        7. Return :class:`~app.schemas.document.VerifyIntegrityResponse`.

        Parameters
        ----------
        vault_id:
            UUID4 identifying the vault containing the document.
        document_id:
            UUID4 identifying the document to verify.

        Returns
        -------
        VerifyIntegrityResponse
            ``{"verified": True, "document_id": ..., "checked_at": ...}``

        Raises
        ------
        VaultNotFoundError
            If the vault directory does not exist.
        DocumentNotFoundError
            If the metadata sidecar does not exist.
        MissingIntegrityMetadataError
            If the metadata has no ``sha256_ciphertext`` field (document
            uploaded before this milestone).
        CorruptedDocumentError
            If the encrypted blob file is missing or cannot be read.
        IntegrityVerificationError
            If the recomputed hash does not match the stored hash.
        """
        vault_root = self._assert_vault_exists(vault_id)

        doc_mgr = DocumentManager(vault_root)

        metadata: DocumentMetadata = doc_mgr.read_metadata(document_id, vault_id)

        if not metadata.sha256_ciphertext:
            raise MissingIntegrityMetadataError(
                f"Document '{document_id}' has no integrity hash recorded.",
                detail=(
                    "This document was uploaded before integrity verification was "
                    "introduced.  Re-upload the document to generate a baseline hash."
                ),
            )

        try:
            ciphertext: bytes = doc_mgr.read_blob(document_id, vault_id)
        except DocumentNotFoundError as exc:
            raise CorruptedDocumentError(
                f"Encrypted blob missing for document '{document_id}' "
                f"in vault '{vault_id}' during integrity check.",
                detail=(
                    "The metadata sidecar exists but the encrypted blob file does not. "
                    "The document may have been partially deleted or is corrupt."
                ),
            ) from exc
        except Exception as exc:
            raise CorruptedDocumentError(
                f"Cannot read encrypted blob for document '{document_id}': {exc}",
                detail=f"OS error reading encrypted blob: {exc}",
            ) from exc

        computed_hash: str = self._enc_mgr.compute_sha256(ciphertext)
        stored_hash: str = metadata.sha256_ciphertext

        logger.debug(
            "Integrity check | vault_id=%s | document_id=%s | stored=%s | computed=%s",
            vault_id,
            document_id,
            stored_hash[:16] + "...",
            computed_hash[:16] + "...",
        )

        if not hmac.compare_digest(computed_hash, stored_hash):
            logger.warning(
                "Integrity check FAILED | vault_id=%s | document_id=%s",
                vault_id,
                document_id,
            )
            raise IntegrityVerificationError(
                f"Integrity check failed for document '{document_id}' "
                f"in vault '{vault_id}': hash mismatch.",
                detail=(
                    "The SHA-256 hash of the stored encrypted document does not match "
                    "the hash recorded at upload time.  The document may have been "
                    "tampered with or corrupted after upload."
                ),
            )

        checked_at = datetime.now(UTC).isoformat()

        logger.info(
            "Integrity check PASSED | vault_id=%s | document_id=%s | checked_at=%s",
            vault_id,
            document_id,
            checked_at,
        )

        return VerifyIntegrityResponse(
            verified=True,
            document_id=document_id,
            checked_at=checked_at,
        )

    # ------------------------------------------------------------------
    # Private: vault state helpers
    # ------------------------------------------------------------------

    def _vault_root(self, vault_id: str) -> Path:
        """Return the vault root directory path for a given vault_id."""
        return self._vault_base_dir / vault_id

    def _assert_vault_exists(self, vault_id: str) -> Path:
        """
        Assert that the vault root directory exists on disk.

        Returns the vault root Path on success.

        Raises
        ------
        VaultNotFoundError
            If the directory does not exist.
        """
        root = self._vault_root(vault_id)
        if not root.is_dir():
            raise VaultNotFoundError(
                f"Vault '{vault_id}' does not exist.",
                detail=f"No vault directory found for vault_id '{vault_id}'.",
            )
        return root

    def _assert_vault_unlocked(self, vault_id: str) -> Path:
        """
        Assert that the vault exists **and** is in the ``unlocked`` state.

        Reads ``manifest.json`` to check the current status.

        Returns the vault root Path on success.

        Raises
        ------
        VaultNotFoundError
            If the vault directory or manifest does not exist.
        VaultLockedError
            If the vault's status is not ``"unlocked"``.
        """
        root = self._assert_vault_exists(vault_id)

        manifest_path = root / "manifest.json"
        try:
            manifest = VaultManifest.read(manifest_path)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise VaultNotFoundError(
                f"Cannot read manifest for vault '{vault_id}': {exc}",
                detail=(
                    f"Vault '{vault_id}' exists on disk but its manifest.json "
                    "could not be read.  The vault may be corrupt."
                ),
            ) from exc

        if manifest.status != _STATUS_UNLOCKED:
            raise VaultLockedError(
                f"Vault '{vault_id}' is locked.  Unlock the vault before "
                "uploading documents.",
                detail=(
                    f"Vault '{vault_id}' has status '{manifest.status}'.  "
                    "Document operations require the vault to be unlocked."
                ),
            )

        return root

    # ------------------------------------------------------------------
    # Private: vault key unwrapping
    # ------------------------------------------------------------------

    def _unwrap_vault_key(
        self,
        vault_root: Path,
        vault_id: str,
        password: str,
    ) -> bytes:
        """
        Re-derive the Master Key and use it to decrypt the Vault Key.

        Steps
        -----
        1. Read ``password_meta.json`` to get the stored salt.
        2. Derive the Master Key from (password, salt) via Argon2id.
        3. Read ``key.json`` to get the encrypted Vault Key and nonce.
        4. Decrypt the Vault Key with AES-256-GCM.

        The Master Key is discarded in the ``finally`` block.

        Parameters
        ----------
        vault_root:
            Absolute path to the vault root directory.
        vault_id:
            Used only in log and error messages.
        password:
            The vault's password (never stored or logged).

        Returns
        -------
        bytes
            Raw 32-byte Vault Key plaintext.

        Raises
        ------
        DocumentEncryptionError
            If the salt, key metadata, or decryption fails.
        """
        master_key: bytes | None = None

        try:
            pwd_mgr = PasswordManager(vault_root)
            salt_hex, _kdf_params = pwd_mgr.read_metadata(vault_id)
            master_key = pwd_mgr.derive_master_key(password, salt_hex)

            key_mgr = KeyManager(vault_root)
            key_meta: KeyMetadata = key_mgr.read(vault_id)

            ct_bytes = self._enc_mgr.decode_from_storage(
                key_meta.encrypted_vault_key, "encrypted_vault_key"
            )
            nonce_bytes = self._enc_mgr.decode_from_storage(
                key_meta.nonce, "nonce"
            )

            vault_key = self._enc_mgr.decrypt_vault_key(
                ciphertext=ct_bytes,
                master_key=master_key,
                nonce=nonce_bytes,
            )

            logger.debug(
                "Vault Key unwrapped successfully | vault_id=%s", vault_id
            )

            return vault_key

        except CipherixError:
            raise
        except Exception as exc:
            raise DocumentEncryptionError(
                f"Failed to unwrap Vault Key for vault '{vault_id}': {exc}",
                detail=(
                    "The Vault Key could not be decrypted.  This may be caused "
                    "by an incorrect password, corrupt key.json, or corrupt "
                    "password_meta.json."
                ),
            ) from exc
        finally:
            try:
                del master_key
            except NameError:
                pass

    # ------------------------------------------------------------------
    # Private: validation
    # ------------------------------------------------------------------

    @staticmethod
    def _validate_filename(filename: str) -> str:
        """
        Validate and return a sanitised version of the uploaded filename.

        Rules
        -----
        * Must be a non-empty string after stripping whitespace.
        * Length must not exceed :data:`_MAX_FILENAME_LEN` characters.
        * Must not contain forbidden characters (null bytes, ``<>:"/\\|?*``).
        * Must not be or contain path-traversal sequences (``..``,
          absolute paths starting with ``/`` or ``\\``).
        * The *name component only* (``PurePosixPath(name).name``) is used
          so that ``foo/bar.pdf`` is stored as ``bar.pdf`` rather than
          rejected outright.

        Parameters
        ----------
        filename:
            Raw filename as received from the client.

        Returns
        -------
        str
            The sanitised filename (name component only, whitespace stripped).

        Raises
        ------
        InvalidUploadError
            If the filename fails any of the above rules.
        """
        if not isinstance(filename, str) or not filename.strip():
            raise InvalidUploadError(
                "Filename is missing or empty.",
                detail=(
                    "The uploaded file must include a non-empty filename. "
                    "Provide a filename via the Content-Disposition header."
                ),
            )

        # Extract only the name component to strip any client-supplied path.
        name = PurePosixPath(filename.strip()).name

        if not name:
            raise InvalidUploadError(
                f"Filename '{filename}' resolved to an empty name after path extraction.",
                detail=(
                    "The supplied filename resolved to an empty string after "
                    "extracting the name component.  Provide a simple filename "
                    "without leading slashes or trailing separators."
                ),
            )

        if len(name) > _MAX_FILENAME_LEN:
            raise InvalidUploadError(
                f"Filename exceeds the maximum allowed length of {_MAX_FILENAME_LEN} characters.",
                detail=(
                    f"The filename '{name[:40]}...' is {len(name)} characters "
                    f"long.  The maximum allowed length is {_MAX_FILENAME_LEN}."
                ),
            )

        if _FORBIDDEN_CHARS.search(name):
            raise InvalidUploadError(
                f"Filename '{name}' contains forbidden characters.",
                detail=(
                    "The filename contains one or more characters that are not "
                    r"permitted: null byte, < > : \" / \ | ? *"
                ),
            )

        if name.startswith(".") and name == "." or name == "..":
            raise InvalidUploadError(
                "Filename must not be '.' or '..'.",
                detail="Path-traversal filenames are not accepted.",
            )

        return name

    @staticmethod
    def _assert_file_not_empty(file_bytes: bytes, filename: str) -> None:
        """
        Raise :class:`InvalidUploadError` if the file has zero bytes.

        Parameters
        ----------
        file_bytes:
            The raw bytes of the uploaded file.
        filename:
            Sanitised filename used only in the error message.

        Raises
        ------
        InvalidUploadError
            If ``file_bytes`` is empty.
        """
        if not file_bytes:
            raise InvalidUploadError(
                f"Uploaded file '{filename}' is empty (zero bytes).",
                detail=(
                    "The uploaded file contains no data.  "
                    "Empty files cannot be encrypted and stored."
                ),
            )

    # ------------------------------------------------------------------
    # Private: response mapping
    # ------------------------------------------------------------------

    @staticmethod
    def _metadata_to_response(metadata: DocumentMetadata) -> DocumentResponse:
        """
        Convert a storage-layer :class:`~app.storage.document_manager.DocumentMetadata`
        into a Pydantic :class:`~app.schemas.document.DocumentResponse`.

        The ``nonce`` field is intentionally **not** included in the response —
        it is an internal encryption detail that must never be sent to clients.
        The ``uploaded_at`` string is parsed into a :class:`~datetime.datetime`
        so the Pydantic model can serialise it consistently.
        """
        return DocumentResponse(
            document_id=metadata.document_id,
            original_filename=metadata.original_filename,
            mime_type=metadata.mime_type,
            size=metadata.size,
            uploaded_at=datetime.fromisoformat(metadata.uploaded_at),
            encryption_version=metadata.encryption_version,
        )
