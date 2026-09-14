
import hmac
import re
import uuid
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.exceptions import (
    CipherixError,
    CorruptedDocumentError,
    DocumentEncryptionError,
    DocumentNotFoundError,
    DocumentStorageError,
    IntegrityVerificationError,
    InvalidUploadError,
    MissingIntegrityMetadataError,
    VaultLockedError,
    VaultNotFoundError,
)
from app.core.logger import get_logger
from app.database.models import Document as DocumentRecord
from app.schemas.document import (
    DocumentListResponse,
    DocumentResponse,
    VerifyIntegrityResponse,
)
from app.security.encryption import EncryptionManager
from app.security.key_manager import KeyManager
from app.security.password_manager import PasswordManager
from app.services.vector_store import VectorStore
from app.storage.document_manager import DocumentManager, DocumentMetadata
from app.vault.manifest import VaultManifest


logger = get_logger(__name__)

_STATUS_UNLOCKED: str = "unlocked"
_DEFAULT_MIME: str = "application/octet-stream"
_MAX_FILENAME_LEN: int = 255
_FORBIDDEN_CHARS: re.Pattern = re.compile(r'[\x00<>:"/\\|?*]')


class DocumentService:

    def __init__(self, vault_base_dir: Path) -> None:
        self._vault_base_dir: Path = vault_base_dir
        self._enc_mgr: EncryptionManager = EncryptionManager()

    def upload_document(
        self,
        vault_id: str,
        password: str,
        filename: str,
        content_type: str | None,
        file_bytes: bytes,
        db: Session | None = None,
    ) -> DocumentResponse:
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
            raise
        except Exception as exc:
            raise DocumentEncryptionError(
                f"Unexpected error encrypting document '{safe_filename}': {exc}",
                detail="An unexpected error occurred during document encryption.",
            ) from exc
        finally:
            try:
                del vault_key
            except NameError:
                pass

        doc_mgr = DocumentManager(vault_root)

        blob_path = doc_mgr.write_blob(
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

        meta_path = doc_mgr.write_metadata(metadata=metadata, vault_id=vault_id)

        if db is not None:


            encrypted_rel_path = f"encrypted/{document_id}.bin"
            try:
                self._insert_document_record(
                    db=db,
                    document_id=document_id,
                    vault_id=vault_id,
                    original_filename=safe_filename,
                    mime_type=mime_type,
                    size=len(file_bytes),
                    encrypted_path=encrypted_rel_path,
                    integrity_hash=sha256_ciphertext,
                    encryption_version=metadata.encryption_version,
                )
            except SQLAlchemyError as exc:


                db.rollback()
                logger.error(
                    "DB insert failed after document written to disk — "
                    "rolling back filesystem | vault_id=%s | document_id=%s | error=%s",
                    vault_id,
                    document_id,
                    exc,
                )
                for cleanup_path in (blob_path, meta_path):
                    try:
                        if cleanup_path.is_file():
                            cleanup_path.unlink()
                    except OSError as fs_exc:
                        logger.error(
                            "Filesystem cleanup FAILED | path=%s | error=%s",
                            cleanup_path,
                            fs_exc,
                        )
                raise DocumentStorageError(
                    f"Failed to persist document '{document_id}' to the database: {exc}",
                    detail=(
                        "The document was encrypted and written to disk but could not "
                        "be recorded in the database.  The filesystem files have been "
                        "removed.  Please retry the upload."
                    ),
                ) from exc

        logger.info(
            "Document upload complete | vault_id=%s | document_id=%s | sha256=%s",
            vault_id,
            document_id,
            sha256_ciphertext[:16] + "...",
        )

        return self._metadata_to_response(metadata)

    def list_documents(
        self, vault_id: str, db: Session | None = None
    ) -> DocumentListResponse:
        vault_root = self._assert_vault_exists(vault_id)

        if db is not None:
            from app.database.models import Document as DocumentRecord
            db_docs = (
                db.query(DocumentRecord)
                .filter(DocumentRecord.vault_id == vault_id)
                .order_by(DocumentRecord.created_at.desc())
                .all()
            )
            documents = [
                DocumentResponse(
                    document_id=rec.id,
                    original_filename=rec.original_filename,
                    mime_type=rec.mime_type,
                    size=rec.size,
                    uploaded_at=rec.created_at,
                    encryption_version=rec.encryption_version,
                )
                for rec in db_docs
            ]
            logger.info(
                "Document listing (SQLite) | vault_id=%s | count=%d",
                vault_id,
                len(documents),
            )
            return DocumentListResponse(
                vault_id=vault_id,
                count=len(documents),
                documents=documents,
            )

        doc_mgr = DocumentManager(vault_root)
        all_metadata = doc_mgr.list_metadata(vault_id)

        documents = [self._metadata_to_response(m) for m in all_metadata]

        logger.info(
            "Document listing (filesystem) | vault_id=%s | count=%d",
            vault_id,
            len(documents),
        )

        return DocumentListResponse(
            vault_id=vault_id,
            count=len(documents),
            documents=documents,
        )

    def delete_document(
        self,
        vault_id: str,
        document_id: str,
        db: Session | None = None,
    ) -> None:
        vault_root = self._assert_vault_exists(vault_id)

        if db is not None:
            try:
                record = db.get(DocumentRecord, document_id)
                if record is not None:
                    db.delete(record)
                    db.commit()
                    logger.debug(
                        "Document DB record deleted | vault_id=%s | document_id=%s",
                        vault_id,
                        document_id,
                    )
                else:
                    logger.warning(
                        "Document DB record not found during delete "
                        "| vault_id=%s | document_id=%s",
                        vault_id,
                        document_id,
                    )
            except SQLAlchemyError as exc:
                db.rollback()
                logger.error(
                    "DB deletion failed | vault_id=%s | document_id=%s | error=%s",
                    vault_id,
                    document_id,
                    exc,
                )
                raise DocumentStorageError(
                    f"Failed to delete document '{document_id}' DB record: {exc}",
                    detail=(
                        "The document database record could not be removed.  "
                        "The encrypted file has NOT been deleted to maintain consistency."
                    ),
                ) from exc

        doc_mgr = DocumentManager(vault_root)
        doc_mgr.delete_document(document_id=document_id, vault_id=vault_id)

        try:
            vector_store = VectorStore()
            vector_store.delete_document_vectors(document_id=document_id, vault_id=vault_id)
        except Exception as v_exc:
            logger.warning(
                "Failed to delete document vectors during document deletion | document_id=%s | error=%s",
                document_id,
                v_exc,
            )

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
        db: Session | None = None,
    ) -> tuple[bytes, DocumentMetadata]:
        vault_root = self._assert_vault_unlocked(vault_id)

        doc_mgr = DocumentManager(vault_root)

        if db is not None:
            from app.database.models import Document as DocumentRecord

            db_record = db.get(DocumentRecord, document_id)
            if db_record is None or db_record.vault_id != vault_id:
                raise DocumentNotFoundError(
                    f"Document '{document_id}' not found in vault '{vault_id}'.",
                    detail=(
                        f"No document record found for document_id '{document_id}' "
                        f"in vault '{vault_id}'."
                    ),
                )
            metadata = doc_mgr.read_metadata(document_id, vault_id)
        else:
            metadata = doc_mgr.read_metadata(document_id, vault_id)

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
        db: Session | None = None,
    ) -> VerifyIntegrityResponse:
        vault_root = self._assert_vault_exists(vault_id)

        doc_mgr = DocumentManager(vault_root)

        if db is not None:
            from app.database.models import Document as DocumentRecord

            db_record = db.get(DocumentRecord, document_id)
            if db_record is None or db_record.vault_id != vault_id:
                raise DocumentNotFoundError(
                    f"Document '{document_id}' not found in vault '{vault_id}'.",
                    detail=(
                        f"No document record found for document_id '{document_id}' "
                        f"in vault '{vault_id}'."
                    ),
                )
            stored_hash: str | None = db_record.integrity_hash
            if not stored_hash:
                raise MissingIntegrityMetadataError(
                    f"Document '{document_id}' has no integrity hash in SQLite.",
                    detail=(
                        "This document was uploaded before integrity verification was "
                        "introduced.  Re-upload the document to generate a baseline hash."
                    ),
                )
        else:
            metadata: DocumentMetadata = doc_mgr.read_metadata(document_id, vault_id)
            if not metadata.sha256_ciphertext:
                raise MissingIntegrityMetadataError(
                    f"Document '{document_id}' has no integrity hash recorded.",
                    detail=(
                        "This document was uploaded before integrity verification was "
                        "introduced.  Re-upload the document to generate a baseline hash."
                    ),
                )
            stored_hash = metadata.sha256_ciphertext

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

    @staticmethod
    def _insert_document_record(
        db: Session,
        document_id: str,
        vault_id: str,
        original_filename: str,
        mime_type: str,
        size: int,
        encrypted_path: str,
        integrity_hash: str | None,
        encryption_version: str,
    ) -> None:
        now = datetime.now(UTC)
        record = DocumentRecord(
            id=document_id,
            vault_id=vault_id,
            original_filename=original_filename,
            mime_type=mime_type,
            size=size,
            encrypted_path=encrypted_path,
            integrity_hash=integrity_hash,
            encryption_version=encryption_version,
            created_at=now,
            updated_at=now,
        )
        db.add(record)
        db.commit()

        logger.info(
            "Document DB record inserted | vault_id=%s | document_id=%s",
            vault_id,
            document_id,
        )

    def _vault_root(self, vault_id: str) -> Path:
        return self._vault_base_dir / vault_id

    def _assert_vault_exists(self, vault_id: str) -> Path:
        root = self._vault_root(vault_id)
        if not root.is_dir():
            raise VaultNotFoundError(
                f"Vault '{vault_id}' does not exist.",
                detail=f"No vault directory found for vault_id '{vault_id}'.",
            )
        return root

    def _assert_vault_unlocked(self, vault_id: str) -> Path:
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

    def _unwrap_vault_key(
        self,
        vault_root: Path,
        vault_id: str,
        password: str,
    ) -> bytes:
        master_key: bytes | None = None

        try:
            pwd_mgr = PasswordManager(vault_root)
            salt_hex, _kdf_params = pwd_mgr.read_metadata(vault_id)
            master_key = pwd_mgr.derive_master_key(password, salt_hex)

            key_mgr = KeyManager(vault_root)
            key_meta = key_mgr.read(vault_id)

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

    @staticmethod
    def _validate_filename(filename: str) -> str:
        if not isinstance(filename, str) or not filename.strip():
            raise InvalidUploadError(
                "Filename is missing or empty.",
                detail=(
                    "The uploaded file must include a non-empty filename. "
                    "Provide a filename via the Content-Disposition header."
                ),
            )


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
        if not file_bytes:
            raise InvalidUploadError(
                f"Uploaded file '{filename}' is empty (zero bytes).",
                detail=(
                    "The uploaded file contains no data.  "
                    "Empty files cannot be encrypted and stored."
                ),
            )

    @staticmethod
    def _metadata_to_response(metadata: DocumentMetadata) -> DocumentResponse:
        return DocumentResponse(
            document_id=metadata.document_id,
            original_filename=metadata.original_filename,
            mime_type=metadata.mime_type,
            size=metadata.size,
            uploaded_at=datetime.fromisoformat(metadata.uploaded_at),
            encryption_version=metadata.encryption_version,
        )
