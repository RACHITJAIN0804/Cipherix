"""
api/routes/computer_access.py
------------------------------
FastAPI routes for safe controlled local-computer access system.

Endpoints:
* POST /api/v1/computer-access/toggle      — Enable/disable computer access toggle.
* GET  /api/v1/computer-access/status      — Query computer access state for user.
* POST /api/v1/computer-access/action      — Propose or execute a registered safe action.
* POST /api/v1/computer-access/approve     — User approval for a pending write action.
* GET  /api/v1/computer-access/audit-logs  — List non-sensitive computer access audit logs.
"""

from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.dependencies import get_current_user, get_db
from app.core.exceptions import (
    ActionExecutionError,
    ActionNotAllowedError,
    ApprovalRequiredError,
    AuthError,
    ComputerAccessDisabledError,
    PathGuardError,
)
from app.core.logger import get_logger
from app.database.models import ComputerAccessAuditLog, User, Vault
from app.schemas.computer_access import (
    AccessStatusResponse,
    ActionRequest,
    ActionResponse,
    ApproveActionRequest,
    AuditLogResponse,
    ToggleAccessRequest,
)
from app.services.computer_access.executor import ComputerAccessExecutor
from app.services.computer_access.permission_service import PermissionService

logger = get_logger(__name__)

router = APIRouter(prefix="/computer-access", tags=["Computer Access"])

_permission_service = PermissionService()
_executor = ComputerAccessExecutor(permission_service=_permission_service)


@router.get("/status", response_model=AccessStatusResponse)
def get_computer_access_status(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> AccessStatusResponse:
    """
    Get current computer access toggle status for authenticated user.
    """
    enabled = _permission_service.is_computer_access_enabled(db, current_user.id)
    path_guard = _executor.get_user_path_guard(current_user.id)
    return AccessStatusResponse(
        enabled=enabled,
        workspace_root=str(path_guard.get_workspace_root()),
    )


@router.post("/toggle", response_model=AccessStatusResponse)
def toggle_computer_access(
    payload: ToggleAccessRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> AccessStatusResponse:
    """
    Enable or disable computer access for the authenticated user.
    """
    new_state = _permission_service.set_computer_access_enabled(
        db, current_user.id, payload.enabled
    )
    path_guard = _executor.get_user_path_guard(current_user.id)
    return AccessStatusResponse(
        enabled=new_state,
        workspace_root=str(path_guard.get_workspace_root()),
    )


@router.post("/action", response_model=ActionResponse)
def execute_computer_action(
    payload: ActionRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ActionResponse:
    """
    Execute or propose a safe registered computer action.
    """
    # If vault_id is supplied, verify vault ownership
    if payload.vault_id:
        vault = db.get(Vault, payload.vault_id)
        if vault is None or (vault.user_id is not None and vault.user_id != current_user.id):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Vault '{payload.vault_id}' not found.",
            )

    try:
        response = _executor.execute_action(db, current_user.id, payload)
        return response
    except ComputerAccessDisabledError as err:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(err),
        )
    except ActionNotAllowedError as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(err),
        )
    except PathGuardError as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(err),
        )
    except ActionExecutionError as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(err),
        )


@router.post("/approve")
def approve_computer_action(
    payload: ApproveActionRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Explicitly approve a pending write action.
    """
    try:
        approval = _permission_service.approve_request(
            db, payload.approval_id, current_user.id
        )
        return {
            "status": approval.status,
            "approval_id": approval.id,
            "action": approval.action,
        }
    except AuthError as err:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(err),
        )


@router.get("/audit-logs", response_model=List[AuditLogResponse])
def get_audit_logs(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> List[AuditLogResponse]:
    """
    Retrieve computer access audit log entries for the authenticated user.
    """
    stmt = (
        select(ComputerAccessAuditLog)
        .where(ComputerAccessAuditLog.user_id == current_user.id)
        .order_by(ComputerAccessAuditLog.created_at.desc())
    )
    logs = db.scalars(stmt).all()
    return [AuditLogResponse.model_validate(log) for log in logs]
