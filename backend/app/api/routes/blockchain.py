"""
api/routes/blockchain.py
------------------------
FastAPI routes for document integrity blockchain anchoring and verification.

Endpoints:
* POST /api/v1/blockchain/anchor — Anchor a document's SHA-256 integrity hash.
* POST /api/v1/blockchain/verify — Recalculate hash and verify against DB & blockchain.
* GET  /api/v1/blockchain/anchor/{document_id} — Retrieve anchor metadata.
"""

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.api.dependencies import get_current_user, get_db
from app.core.exceptions import (
    AnchorNotFoundError,
    BlockchainError,
    BlockchainUnavailableError,
    DocumentNotFoundError,
    MissingIntegrityMetadataError,
    VaultNotFoundError,
)
from app.core.logger import get_logger
from app.core.rate_limiter import limit_expensive_requests
from app.database.models import User
from app.schemas.blockchain import (
    AnchorRequest,
    AnchorResponse,
    VerifyAnchorRequest,
    VerifyAnchorResponse,
)
from app.services.blockchain.blockchain_service import BlockchainService

logger = get_logger(__name__)

router = APIRouter(prefix="/blockchain", tags=["Blockchain Integrity"])

_blockchain_service = BlockchainService()


@router.post("/anchor", response_model=AnchorResponse, dependencies=[Depends(limit_expensive_requests)])
def anchor_document_hash(
    payload: AnchorRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> AnchorResponse:
    """
    Anchor document's SHA-256 integrity hash on the blockchain.
    """
    try:
        return _blockchain_service.anchor_document(
            db=db,
            user_id=current_user.id,
            vault_id=payload.vault_id,
            document_id=payload.document_id,
        )
    except (VaultNotFoundError, DocumentNotFoundError) as err:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(err),
        )
    except (MissingIntegrityMetadataError, BlockchainUnavailableError) as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(err),
        )
    except BlockchainError as err:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(err),
        )


@router.post("/verify", response_model=VerifyAnchorResponse)
def verify_document_anchor(
    payload: VerifyAnchorRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> VerifyAnchorResponse:
    """
    Verify document integrity against stored database hash and blockchain anchor.
    """
    try:
        return _blockchain_service.verify_document_anchor(
            db=db,
            user_id=current_user.id,
            vault_id=payload.vault_id,
            document_id=payload.document_id,
        )
    except (VaultNotFoundError, DocumentNotFoundError) as err:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(err),
        )
    except BlockchainError as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(err),
        )


@router.get("/anchor/{document_id}", response_model=AnchorResponse)
def get_document_anchor(
    document_id: str,
    vault_id: str = Query(..., description="Vault UUID containing the document."),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> AnchorResponse:
    """
    Retrieve blockchain anchor metadata for a document.
    """
    try:
        return _blockchain_service.get_document_anchor(
            db=db,
            user_id=current_user.id,
            vault_id=vault_id,
            document_id=document_id,
        )
    except (VaultNotFoundError, DocumentNotFoundError, AnchorNotFoundError) as err:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(err),
        )
    except BlockchainError as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(err),
        )
