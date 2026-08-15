"""
services/computer_access/executor.py
------------------------------------
Main execution coordinator for safe local-computer access system.

Integrates authentication, server-side permission checks, ActionRegistry allowed-list
dispatching, PathGuard filesystem sandboxing, explicit user approvals, and privacy-preserving audit logging.
"""

import json
import uuid
from pathlib import Path
from typing import Any, Dict, Optional

from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.exceptions import (
    ActionExecutionError,
    ActionNotAllowedError,
    ApprovalRequiredError,
    ComputerAccessDisabledError,
    PathGuardError,
)
from app.core.logger import get_logger
from app.database.models import ComputerAccessAuditLog
from app.schemas.computer_access import (
    ActionRequest,
    ActionResponse,
    CopyFileParams,
    CreateDirectoryParams,
    CreateTextFileParams,
    ListDirectoryParams,
    MoveFileParams,
    ReadTextFileParams,
    WriteTextFileParams,
)
from app.services.computer_access.action_registry import ActionDefinition, ActionRegistry
from app.services.computer_access.actions import filesystem as fs_actions
from app.services.computer_access.path_guard import PathGuard
from app.services.computer_access.permission_service import PermissionService

logger = get_logger(__name__)


class ComputerAccessExecutor:
    """
    Coordinator executing only registered, safe, sandboxed computer access actions.
    """

    def __init__(
        self,
        registry: Optional[ActionRegistry] = None,
        permission_service: Optional[PermissionService] = None,
    ) -> None:
        self.registry: ActionRegistry = registry or ActionRegistry()
        self.permission_service: PermissionService = (
            permission_service or PermissionService()
        )

    def get_user_path_guard(self, user_id: str) -> PathGuard:
        """
        Get PathGuard initialized with per-user workspace directory for isolation.
        """
        workspace = settings.COMPUTER_ACCESS_WORKSPACE_DIR / user_id
        return PathGuard(workspace)

    def _create_audit_log(
        self,
        db: Session,
        user_id: str,
        vault_id: Optional[str],
        action: str,
        relative_path: Optional[str],
        result_status: str,
        approval_status: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Write non-sensitive audit event to SQLite database and structured logger.
        """
        try:
            # Filter sensitive fields from details before serialization
            safe_details = {}
            if details:
                for k, v in details.items():
                    if k in ("content", "password", "key", "seed", "token", "jwt"):
                        continue
                    safe_details[k] = v

            details_json = json.dumps(safe_details) if safe_details else None

            log_entry = ComputerAccessAuditLog(
                id=str(uuid.uuid4()),
                user_id=user_id,
                vault_id=vault_id,
                action=action,
                relative_path=relative_path,
                result_status=result_status,
                approval_status=approval_status,
                details_json=details_json,
            )
            db.add(log_entry)
            db.commit()
            logger.info(
                "AuditLog: user=%s action=%s path=%s result=%s approval=%s",
                user_id,
                action,
                relative_path,
                result_status,
                approval_status,
            )
        except Exception as err:
            logger.error("Failed to write computer access audit log: %s", err)

    def execute_action(
        self, db: Session, user_id: str, request: ActionRequest
    ) -> ActionResponse:
        """
        Main execution flow:
        1. Check computer-access permission toggle.
        2. Lookup action in ActionRegistry.
        3. Validate parameters schema.
        4. Validate path sandboxing via PathGuard.
        5. Check user approval requirement.
        6. Dispatch to registered handler.
        7. Audit log event.
        """
        # 1. Permission check
        if not self.permission_service.is_computer_access_enabled(db, user_id):
            self._create_audit_log(
                db=db,
                user_id=user_id,
                vault_id=request.vault_id,
                action=request.action,
                relative_path=request.parameters.get("path"),
                result_status="rejected",
                approval_status="denied",
                details={"reason": "Computer access disabled"},
            )
            raise ComputerAccessDisabledError(
                "Computer access is currently disabled for your account."
            )

        # 2. Action Registry Lookup
        action_def: ActionDefinition = self.registry.get_action(request.action)

        # 3. Validate Parameters
        validated_params = self.registry.validate_parameters(
            request.action, request.parameters
        )

        # 4. Path Guard Sandboxing
        path_guard = self.get_user_path_guard(user_id)
        path_param = getattr(validated_params, "path", getattr(validated_params, "src_path", None))

        # 5. User Approval Check
        approval_status = "not_required"
        if action_def.requires_approval:
            # Check if explicit user approval is granted or approval_id is provided and valid
            is_approved = False

            if request.approved:
                is_approved = True
                approval_status = "approved"
            elif request.approval_id:
                if self.permission_service.is_approval_valid(
                    db, request.approval_id, user_id, request.action
                ):
                    is_approved = True
                    approval_status = "approved"

            if not is_approved:
                # Create approval request
                approval_req = self.permission_service.create_approval_request(
                    db=db,
                    user_id=user_id,
                    action=request.action,
                    parameters=request.parameters,
                )
                self._create_audit_log(
                    db=db,
                    user_id=user_id,
                    vault_id=request.vault_id,
                    action=request.action,
                    relative_path=path_param,
                    result_status="rejected",
                    approval_status="pending",
                    details={"approval_id": approval_req.id},
                )
                return ActionResponse(
                    success=False,
                    action=request.action,
                    status="approval_required",
                    requires_approval=True,
                    approval_id=approval_req.id,
                    error=f"Explicit user approval is required to execute write action '{request.action}'.",
                )

        # 6. Execute registered safe action
        try:
            result_data: Dict[str, Any] = {}
            if request.action == "list_directory":
                result_data = fs_actions.execute_list_directory(
                    path_guard, validated_params  # type: ignore[arg-type]
                )
            elif request.action == "read_text_file":
                result_data = fs_actions.execute_read_text_file(
                    path_guard, validated_params  # type: ignore[arg-type]
                )
            elif request.action == "create_directory":
                result_data = fs_actions.execute_create_directory(
                    path_guard, validated_params  # type: ignore[arg-type]
                )
            elif request.action == "create_text_file":
                result_data = fs_actions.execute_create_text_file(
                    path_guard, validated_params  # type: ignore[arg-type]
                )
            elif request.action == "write_text_file":
                result_data = fs_actions.execute_write_text_file(
                    path_guard, validated_params  # type: ignore[arg-type]
                )
            elif request.action == "copy_file":
                result_data = fs_actions.execute_copy_file(
                    path_guard, validated_params  # type: ignore[arg-type]
                )
            elif request.action == "move_file":
                result_data = fs_actions.execute_move_file(
                    path_guard, validated_params  # type: ignore[arg-type]
                )
            else:
                raise ActionNotAllowedError(f"Handler for action '{request.action}' not implemented.")

            # 7. Audit log success
            self._create_audit_log(
                db=db,
                user_id=user_id,
                vault_id=request.vault_id,
                action=request.action,
                relative_path=path_param,
                result_status="success",
                approval_status=approval_status,
                details=result_data,
            )

            return ActionResponse(
                success=True,
                action=request.action,
                status="executed",
                requires_approval=action_def.requires_approval,
                result=result_data,
            )

        except (PathGuardError, ActionExecutionError) as err:
            self._create_audit_log(
                db=db,
                user_id=user_id,
                vault_id=request.vault_id,
                action=request.action,
                relative_path=path_param,
                result_status="failure",
                approval_status=approval_status,
                details={"error": str(err)},
            )
            raise
