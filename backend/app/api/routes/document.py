"""
api/routes/document.py
----------------------
FastAPI route handlers for encrypted document operations.

Each handler follows the same pattern:

1. Extract and forward request data to :class:`~app.services.document_service.DocumentService`.
2. Map domain exceptions to HTTP status codes.
3. Return the appropriate response or stream.

No business logic, no filesystem code, and no cryptography belongs here.

Dependency wiring
-----------------
``_get_document_service()`` constructs :class:`~app.services.document_service.DocumentService`
on every request using ``settings.VAULT_DIR``.  Tests can override this
dependency with ``app.dependency_overrides``.

Password handling
-----------------
The vault password is supplied as an HTTP header (``X-Vault-Password``) on
every request that requires decryption.  It is never logged, never stored
in a route parameter, and is discarded by the service layer immediately after
the Vault Key is unwrapped.
"""

from fastapi import APIRouter, Depends, File, Header, HTTPException, UploadFile, status
from fastapi.responses import Response, StreamingResponse
from sqlalchemy.orm import Session

from app.api.dependencies import get_current_user, get_db, get_user_vault
from app.core.config import settings
from app.core.exceptions import (
    CipherixError,
    CorruptedDocumentError,
    DocumentEncryptionError,
    DocumentExtractionError,
    DocumentNotFoundError,
    DocumentProcessingError,
    DocumentStorageError,
    EmptyDocumentError,
    IntegrityError,
    IntegrityVerificationError,
    InvalidUploadError,
    MissingIntegrityMetadataError,
    UnsupportedFileTypeError,
    VaultAccessDeniedError,
    VaultLockedError,
    VaultNotFoundError,
)
from app.core.logger import get_logger
from app.database.models import User, Vault

from app.schemas.document import (
    DocumentListResponse,
    DocumentProcessingResponse,
    DocumentResponse,
    VerifyIntegrityResponse,
)
from app.services.document_processing.pipeline import DocumentProcessingPipeline
from app.services.document_service import DocumentService

logger = get_logger(__name__)

router = APIRouter(
    prefix="/vaults",
    tags=["Documents"],
)



def _get_document_service() -> DocumentService:
    return DocumentService(vault_base_dir=settings.VAULT_DIR)



def _map_document_exception(exc: Exception) -> None:
    if isinstance(exc, VaultNotFoundError):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=exc.detail) from exc

    if isinstance(exc, VaultLockedError):
        raise HTTPException(status_code=status.HTTP_423_LOCKED, detail=exc.detail) from exc

    if isinstance(exc, DocumentNotFoundError):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=exc.detail) from exc

    if isinstance(exc, (InvalidUploadError, UnsupportedFileTypeError, EmptyDocumentError, DocumentExtractionError)):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=exc.detail
        ) from exc

    if isinstance(exc, IntegrityError):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=exc.detail) from exc

    if isinstance(exc, DocumentProcessingError):
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=exc.detail) from exc


    if isinstance(exc, CorruptedDocumentError):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=exc.detail
        ) from exc

    if isinstance(exc, (DocumentEncryptionError, DocumentStorageError)):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=exc.detail
        ) from exc

    if isinstance(exc, CipherixError):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=exc.detail
        ) from exc

    raise exc



@router.post(
    "/{vault_id}/documents",
    response_model=DocumentResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Upload and encrypt a document",
    description=(
        "Encrypt and store a file inside the vault identified by ``vault_id``. "
        "The vault must be unlocked.  The file is encrypted with AES-256-GCM "
        "using a per-document nonce.  Only ciphertext is written to disk; "
        "the plaintext is discarded immediately after encryption."
    ),
    responses={
        201: {"description": "Document encrypted and stored."},
        401: {"description": "Missing, expired, or invalid JWT token."},
        404: {"description": "Vault not found or not owned."},
        422: {"description": "Invalid filename or empty file."},
        423: {"description": "Vault is locked."},
        500: {"description": "Encryption or storage failure."},
    },
)
async def upload_document(
    vault_id: str,
    vault: Vault = Depends(get_user_vault),
    file: UploadFile = File(..., description="File to encrypt and store."),
    x_vault_password: str = Header(
        ...,
        alias="X-Vault-Password",
        description="Vault unlock password used to derive the Master Key.",
    ),
    service: DocumentService = Depends(_get_document_service),
    db: Session = Depends(get_db),
) -> DocumentResponse:
    """
    ``POST /vaults/{vault_id}/documents`` — encrypt and store a document.
    """
    try:
        file_bytes = await file.read()
        response = service.upload_document(
            vault_id=vault.id,
            password=x_vault_password,
            filename=file.filename or "",
            content_type=file.content_type,
            file_bytes=file_bytes,
            db=db,
        )
        logger.info(
            "POST /vaults/%s/documents succeeded | document_id=%s",
            vault.id,
            response.document_id,
        )
        return response
    except Exception as exc:  # noqa: BLE001
        _map_document_exception(exc)


@router.get(
    "/{vault_id}/documents/{document_id}/verify",
    response_model=VerifyIntegrityResponse,
    status_code=status.HTTP_200_OK,
    summary="Verify encrypted document integrity",
    description=(
        "Recompute the SHA-256 hash of the stored encrypted blob and compare "
        "it against the hash recorded at upload time.  No password is required."
    ),
    responses={
        200: {"description": "Integrity verified — hash matches."},
        401: {"description": "Missing, expired, or invalid JWT token."},
        404: {"description": "Vault or document not found."},
        409: {"description": "Hash mismatch or missing integrity metadata."},
        500: {"description": "Blob unreadable or storage failure."},
    },
)
async def verify_document_integrity(
    vault_id: str,
    document_id: str,
    vault: Vault = Depends(get_user_vault),
    service: DocumentService = Depends(_get_document_service),
    db: Session = Depends(get_db),
) -> VerifyIntegrityResponse:
    """
    ``GET /vaults/{vault_id}/documents/{document_id}/verify`` — integrity check.
    """
    try:
        result = service.verify_document(
            vault_id=vault.id,
            document_id=document_id,
            db=db,
        )
        logger.info(
            "GET /vaults/%s/documents/%s/verify PASSED",
            vault.id,
            document_id,
        )
        return result
    except Exception as exc:  # noqa: BLE001
        _map_document_exception(exc)


@router.get(
    "/{vault_id}/documents",
    response_model=DocumentListResponse,
    status_code=status.HTTP_200_OK,
    summary="List documents in a vault",
    description=(
        "Return metadata for every document stored in the vault."
    ),
    responses={
        200: {"description": "List of document metadata entries."},
        401: {"description": "Missing, expired, or invalid JWT token."},
        404: {"description": "Vault not found or not owned."},
        500: {"description": "Metadata storage error."},
    },
)
async def list_documents(
    vault_id: str,
    vault: Vault = Depends(get_user_vault),
    service: DocumentService = Depends(_get_document_service),
    db: Session = Depends(get_db),
) -> DocumentListResponse:
    """``GET /vaults/{vault_id}/documents`` — list document metadata."""
    try:
        result = service.list_documents(vault.id, db=db)
        logger.info(
            "GET /vaults/%s/documents succeeded | count=%d",
            vault.id,
            result.count,
        )
        return result
    except Exception as exc:  # noqa: BLE001
        _map_document_exception(exc)


@router.get(
    "/{vault_id}/documents/{document_id}",
    status_code=status.HTTP_200_OK,
    summary="Download and decrypt a document",
    description=(
        "Decrypt and stream the original file for the document identified by "
        "``document_id`` inside ``vault_id``.  The vault must be unlocked."
    ),
    responses={
        200: {"description": "Decrypted file content as an octet stream."},
        401: {"description": "Missing, expired, or invalid JWT token."},
        404: {"description": "Vault or document not found."},
        423: {"description": "Vault is locked."},
        500: {"description": "Decryption or storage failure."},
    },
    response_class=StreamingResponse,
)
async def download_document(
    vault_id: str,
    document_id: str,
    vault: Vault = Depends(get_user_vault),
    x_vault_password: str = Header(
        ...,
        alias="X-Vault-Password",
        description="Vault unlock password used to derive the Master Key.",
    ),
    service: DocumentService = Depends(_get_document_service),
    db: Session = Depends(get_db),
) -> StreamingResponse:
    """
    ``GET /vaults/{vault_id}/documents/{document_id}`` — decrypt and download.
    """
    try:
        plaintext, metadata = service.download_document(
            vault_id=vault.id,
            document_id=document_id,
            password=x_vault_password,
            db=db,
        )
        logger.info(
            "GET /vaults/%s/documents/%s succeeded | filename=%s | bytes=%d",
            vault.id,
            document_id,
            metadata.original_filename,
            len(plaintext),
        )
        return StreamingResponse(
            content=iter([plaintext]),
            media_type=metadata.mime_type,
            headers={
                "Content-Disposition": (
                    f'attachment; filename="{metadata.original_filename}"'
                ),
                "Content-Length": str(len(plaintext)),
            },
        )
    except Exception as exc:  # noqa: BLE001
        _map_document_exception(exc)


@router.delete(
    "/{vault_id}/documents/{document_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete an encrypted document",
    description=(
        "Permanently delete the encrypted blob and metadata sidecar for the "
        "document identified by ``document_id`` inside ``vault_id``."
    ),
    responses={
        204: {"description": "Document deleted."},
        401: {"description": "Missing, expired, or invalid JWT token."},
        404: {"description": "Vault or document not found."},
        500: {"description": "Filesystem deletion error."},
    },
)
async def delete_document(
    vault_id: str,
    document_id: str,
    vault: Vault = Depends(get_user_vault),
    service: DocumentService = Depends(_get_document_service),
    db: Session = Depends(get_db),
) -> Response:
    """``DELETE /vaults/{vault_id}/documents/{document_id}`` — delete a document."""
    try:
        service.delete_document(vault_id=vault.id, document_id=document_id, db=db)
        logger.info(
            "DELETE /vaults/%s/documents/%s succeeded",
            vault.id,
            document_id,
        )
        return Response(status_code=status.HTTP_204_NO_CONTENT)
    except Exception as exc:  # noqa: BLE001
        _map_document_exception(exc)


@router.post(
    "/{vault_id}/documents/{document_id}/process",
    response_model=DocumentProcessingResponse,
    status_code=status.HTTP_200_OK,
    summary="Process an encrypted document for RAG chunking",
    description=(
        "Decrypts an encrypted document in memory, verifies integrity, "
        "extracts text (TXT, PDF, DOCX), cleans text, and generates deterministic "
        "chunks ready for downstream RAG embeddings. Does NOT permanently persist "
        "decrypted text or plaintext chunks."
    ),
    responses={
        200: {"description": "Document processed successfully into chunks."},
        401: {"description": "Missing, expired, or invalid JWT or wrong password."},
        403: {"description": "User does not own the vault."},
        404: {"description": "Vault or document not found."},
        409: {"description": "Document integrity check failed."},
        422: {"description": "Unsupported file format, empty document, or extraction error."},
    },
)
async def process_document(
    vault_id: str,
    document_id: str,
    x_vault_password: str = Header(
        ...,
        alias="X-Vault-Password",
        description="Password required to decrypt the vault key.",
    ),
    vault: Vault = Depends(get_user_vault),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> DocumentProcessingResponse:
    """``POST /vaults/{vault_id}/documents/{document_id}/process`` — process a document for RAG."""
    try:
        pipeline = DocumentProcessingPipeline(vault_base_dir=settings.VAULT_DIR)
        return pipeline.process_document(
            vault_id=vault.id,
            document_id=document_id,
            user_id=current_user.id,
            password=x_vault_password,
            db=db,
        )
    except Exception as exc:  # noqa: BLE001
        _map_document_exception(exc)


