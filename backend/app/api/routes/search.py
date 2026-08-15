"""
api/routes/search.py
--------------------
FastAPI router for semantic similarity search over encrypted document vaults.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.dependencies import get_current_user
from app.core.exceptions import (
    CipherixError,
    DocumentProcessingError,
    VaultAccessDeniedError,
    VaultNotFoundError,
    VaultValidationError,
)
from app.core.logger import get_logger
from app.core.rate_limiter import limit_expensive_requests
from app.database.database import get_db
from app.database.models import User
from app.schemas.search import SearchRequest, SearchResponse
from app.services.search_service import SearchService

logger = get_logger(__name__)

router = APIRouter(tags=["search"])


def _get_search_service() -> SearchService:
    return SearchService()


@router.post(
    "",
    response_model=SearchResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(limit_expensive_requests)],
    summary="Semantic vector search inside an authorized vault",
    description=(
        "Execute natural language vector similarity search over text chunks "
        "belonging exclusively to an authorized vault owned by the authenticated user."
    ),
    responses={
        200: {"description": "Ranked matching text chunks returned successfully."},
        400: {"description": "Invalid query parameters or vault_id format."},
        401: {"description": "Missing, expired, or invalid JWT token."},
        403: {"description": "Access denied: user does not own the requested vault."},
        404: {"description": "Requested vault not found."},
        500: {"description": "Vector database or embedding service error."},
    },
)
async def search_vault(
    request: SearchRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    search_service: SearchService = Depends(_get_search_service),
) -> SearchResponse:
    """
    ``POST /api/v1/search`` — vault-isolated semantic vector search.
    """
    try:
        response = search_service.search(
            request=request,
            user_id=current_user.id,
            db=db,
        )
        return response

    except VaultAccessDeniedError as exc:
        logger.warning(
            "Semantic search access denied | user_id=%s | vault_id=%s",
            current_user.id,
            request.vault_id,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=exc.detail,
        ) from exc

    except VaultNotFoundError as exc:
        logger.warning(
            "Semantic search vault not found | user_id=%s | vault_id=%s",
            current_user.id,
            request.vault_id,
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=exc.detail,
        ) from exc

    except (VaultValidationError, ValueError) as exc:
        logger.warning("Semantic search request validation failed | detail=%s", exc)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    except DocumentProcessingError as exc:
        logger.error("Semantic search failed | vault_id=%s | detail=%s", request.vault_id, exc.detail)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=exc.detail,
        ) from exc

    except CipherixError as exc:
        logger.error("Unexpected domain error during semantic search | %s", exc.detail)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=exc.detail,
        ) from exc
