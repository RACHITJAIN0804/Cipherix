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

from app.core.config import settings
from app.core.exceptions import (
    CipherixError,
    DocumentEncryptionError,
    DocumentNotFoundError,
    DocumentStorageError,
    InvalidUploadError,
    VaultLockedError,
    VaultNotFoundError,
)
from app.core.logger import get_logger
from app.schemas.document import DocumentListResponse, DocumentResponse
from app.services.document_service import DocumentService

logger = get_logger(__name__)

router = APIRouter(
    prefix="/vaults",
    tags=["Documents"],
)


# ---------------------------------------------------------------------------
# Dependency
# ---------------------------------------------------------------------------


def _get_document_service() -> DocumentService:
    """
    FastAPI dependency that wires together the DocumentService.

    Constructing the service here (rather than at module import time) means:

    * Each request gets a fresh service instance with no shared mutable state.
    * Tests can override this dependency with ``app.dependency_overrides``.
    * ``settings.VAULT_DIR`` is read at request time.
    """
    return DocumentService(vault_base_dir=settings.VAULT_DIR)


# ---------------------------------------------------------------------------
# Exception mapper
# ---------------------------------------------------------------------------


def _map_document_exception(exc: Exception, vault_id: str) -> None:
    """
    Map a domain exception to the appropriate :class:`HTTPException`.

    Centralising the mapping here means every document endpoint shares
    the same exception-to-status-code table without repeating it.

    Raises
    ------
    HTTPException
        Always.  Re-raises non-domain exceptions unmodified so the global
        handler in ``main.py`` can log the full traceback.
    """
    if isinstance(exc, VaultNotFoundError):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=exc.detail) from exc

    if isinstance(exc, VaultLockedError):
        raise HTTPException(status_code=status.HTTP_423_LOCKED, detail=exc.detail) from exc

    if isinstance(exc, DocumentNotFoundError):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=exc.detail) from exc

    if isinstance(exc, InvalidUploadError):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=exc.detail
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


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


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
        404: {"description": "Vault not found."},
        422: {"description": "Invalid filename or empty file."},
        423: {"description": "Vault is locked."},
        500: {"description": "Encryption or storage failure."},
    },
)
async def upload_document(
    vault_id: str,
    file: UploadFile = File(..., description="File to encrypt and store."),
    x_vault_password: str = Header(
        ...,
        alias="X-Vault-Password",
        description="Vault unlock password used to derive the Master Key.",
    ),
    service: DocumentService = Depends(_get_document_service),
) -> DocumentResponse:
    """
    ``POST /vaults/{vault_id}/documents`` — encrypt and store a document.

    Reads the entire file into memory, delegates encryption and storage to
    :class:`~app.services.document_service.DocumentService`, and returns
    the document metadata.  The password is forwarded to the service and is
    never stored or logged by this handler.
    """
    try:
        file_bytes = await file.read()
        response = service.upload_document(
            vault_id=vault_id,
            password=x_vault_password,
            filename=file.filename or "",
            content_type=file.content_type,
            file_bytes=file_bytes,
        )
        logger.info(
            "POST /vaults/%s/documents succeeded | document_id=%s",
            vault_id,
            response.document_id,
        )
        return response
    except Exception as exc:  # noqa: BLE001
        _map_document_exception(exc, vault_id)


@router.get(
    "/{vault_id}/documents",
    response_model=DocumentListResponse,
    status_code=status.HTTP_200_OK,
    summary="List documents in a vault",
    description=(
        "Return metadata for every document stored in the vault.  "
        "The vault need not be unlocked — listing reads only metadata files, "
        "not encrypted blobs.  No decryption is performed."
    ),
    responses={
        200: {"description": "List of document metadata entries."},
        404: {"description": "Vault not found."},
        500: {"description": "Metadata storage error."},
    },
)
async def list_documents(
    vault_id: str,
    service: DocumentService = Depends(_get_document_service),
) -> DocumentListResponse:
    """``GET /vaults/{vault_id}/documents`` — list document metadata."""
    try:
        result = service.list_documents(vault_id)
        logger.info(
            "GET /vaults/%s/documents succeeded | count=%d",
            vault_id,
            result.count,
        )
        return result
    except Exception as exc:  # noqa: BLE001
        _map_document_exception(exc, vault_id)


@router.get(
    "/{vault_id}/documents/{document_id}",
    status_code=status.HTTP_200_OK,
    summary="Download and decrypt a document",
    description=(
        "Decrypt and stream the original file for the document identified by "
        "``document_id`` inside ``vault_id``.  The vault must be unlocked.  "
        "The password is used to derive the Master Key, which unwraps the "
        "Vault Key, which decrypts the document.  Plaintext is never written "
        "to disk — it lives only in memory for the duration of this request."
    ),
    responses={
        200: {"description": "Decrypted file content as an octet stream."},
        404: {"description": "Vault or document not found."},
        423: {"description": "Vault is locked."},
        500: {"description": "Decryption or storage failure."},
    },
    response_class=StreamingResponse,
)
async def download_document(
    vault_id: str,
    document_id: str,
    x_vault_password: str = Header(
        ...,
        alias="X-Vault-Password",
        description="Vault unlock password used to derive the Master Key.",
    ),
    service: DocumentService = Depends(_get_document_service),
) -> StreamingResponse:
    """
    ``GET /vaults/{vault_id}/documents/{document_id}`` — decrypt and download.

    Delegates decryption to
    :meth:`~app.services.document_service.DocumentService.download_document`,
    which returns ``(plaintext_bytes, metadata)``.  The plaintext is wrapped in
    a :class:`~fastapi.responses.StreamingResponse` so it streams directly to
    the client without being buffered a second time.

    ``Content-Disposition: attachment`` causes browsers to save the file
    rather than trying to display it, preserving the original filename.
    """
    try:
        plaintext, metadata = service.download_document(
            vault_id=vault_id,
            document_id=document_id,
            password=x_vault_password,
        )
        logger.info(
            "GET /vaults/%s/documents/%s succeeded | filename=%s | bytes=%d",
            vault_id,
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
        _map_document_exception(exc, vault_id)


@router.delete(
    "/{vault_id}/documents/{document_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete an encrypted document",
    description=(
        "Permanently delete the encrypted blob and metadata sidecar for the "
        "document identified by ``document_id`` inside ``vault_id``.  "
        "The vault need not be unlocked.  This action is **irreversible**."
    ),
    responses={
        204: {"description": "Document deleted."},
        404: {"description": "Vault or document not found."},
        500: {"description": "Filesystem deletion error."},
    },
)
async def delete_document(
    vault_id: str,
    document_id: str,
    service: DocumentService = Depends(_get_document_service),
) -> Response:
    """``DELETE /vaults/{vault_id}/documents/{document_id}`` — delete a document."""
    try:
        service.delete_document(vault_id=vault_id, document_id=document_id)
        logger.info(
            "DELETE /vaults/%s/documents/%s succeeded",
            vault_id,
            document_id,
        )
        return Response(status_code=status.HTTP_204_NO_CONTENT)
    except Exception as exc:  # noqa: BLE001
        _map_document_exception(exc, vault_id)
