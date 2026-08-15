"""
api/routes/rag.py
-----------------
FastAPI router for the Cipherix RAG (Retrieval-Augmented Generation) endpoint.

POST /api/v1/rag/query — Vault-isolated question answering via local LLM.

Security
--------
* JWT authentication is required (get_current_user dependency).
* Vault ownership is re-verified inside RAGService (defense in depth).
* Cross-vault access is prevented at the ChromaDB filter level.
* LLM backend errors are mapped to safe HTTP responses — no internal
  details are leaked to the client.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.dependencies import get_current_user
from app.core.exceptions import (
    CipherixError,
    DocumentProcessingError,
    LLMGenerationError,
    LLMTimeoutError,
    LLMUnavailableError,
    RAGEmptyQueryError,
    RAGNoContextError,
    VaultAccessDeniedError,
    VaultNotFoundError,
)
from app.core.logger import get_logger
from app.database.database import get_db
from app.database.models import User
from app.schemas.rag import RAGRequest, RAGResponse
from app.services.rag_service import RAGService

logger = get_logger(__name__)

router = APIRouter(tags=["rag"])

_NO_CONTEXT_ANSWER = (
    "The information you requested was not found in your vault documents."
)


def _get_rag_service() -> RAGService:
    return RAGService()


@router.post(
    "/query",
    response_model=RAGResponse,
    status_code=status.HTTP_200_OK,
    summary="RAG query — ask a question about your vault documents",
    description=(
        "Retrieval-Augmented Generation: embeds the query, searches the authorized vault, "
        "builds grounded context, and generates a locally-computed answer via Ollama. "
        "All processing is performed on-device; no data is sent to external services."
    ),
    responses={
        200: {"description": "Grounded answer with source citations returned successfully."},
        400: {"description": "Invalid query parameters or vault_id format."},
        401: {"description": "Missing, expired, or invalid JWT token."},
        403: {"description": "Access denied: user does not own the requested vault."},
        404: {"description": "Requested vault not found."},
        422: {"description": "Query is empty or request payload is invalid."},
        500: {"description": "Embedding, vector search, or LLM generation failure."},
        503: {"description": "Local LLM service (Ollama) is unavailable or timed out."},
    },
)
async def rag_query(
    request: RAGRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    rag_service: RAGService = Depends(_get_rag_service),
) -> RAGResponse:
    """
    ``POST /api/v1/rag/query`` — vault-isolated RAG question answering.

    Requires a valid Bearer JWT.  The authenticated user must own the
    specified vault.  All retrieval and generation is local — no external
    APIs are called.
    """
    try:
        return rag_service.query(
            request=request,
            user_id=current_user.id,
            db=db,
        )

    except RAGEmptyQueryError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=exc.detail,
        ) from exc

    except RAGNoContextError:
        # Not an error — vault simply has no relevant content for this query.
        # Return a 200 with a canned answer rather than a 404/422.
        logger.info(
            "RAG: no relevant context found | user_id=%s | vault_id=%s",
            current_user.id,
            request.vault_id,
        )
        return RAGResponse(
            vault_id=request.vault_id,
            query=request.query,
            answer=_NO_CONTEXT_ANSWER,
            sources=[],
            total_chunks_used=0,
            llm_model="n/a",
        )

    except VaultAccessDeniedError as exc:
        logger.warning(
            "RAG access denied | user_id=%s | vault_id=%s",
            current_user.id,
            request.vault_id,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=exc.detail,
        ) from exc

    except VaultNotFoundError as exc:
        logger.warning(
            "RAG vault not found | user_id=%s | vault_id=%s",
            current_user.id,
            request.vault_id,
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=exc.detail,
        ) from exc

    except (LLMUnavailableError, LLMTimeoutError) as exc:
        logger.error(
            "RAG LLM unavailable/timeout | user_id=%s | vault_id=%s | error=%s",
            current_user.id,
            request.vault_id,
            type(exc).__name__,
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=exc.detail,
        ) from exc

    except LLMGenerationError as exc:
        logger.error(
            "RAG LLM generation error | user_id=%s | vault_id=%s",
            current_user.id,
            request.vault_id,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=exc.detail,
        ) from exc

    except DocumentProcessingError as exc:
        logger.error(
            "RAG embedding/vector error | user_id=%s | vault_id=%s | detail=%s",
            current_user.id,
            request.vault_id,
            exc.detail,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=exc.detail,
        ) from exc

    except CipherixError as exc:
        logger.error(
            "Unexpected domain error during RAG query | user_id=%s | vault_id=%s",
            current_user.id,
            request.vault_id,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=exc.detail,
        ) from exc
