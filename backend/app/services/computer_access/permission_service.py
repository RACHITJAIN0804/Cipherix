"""
services/computer_access/permission_service.py
------------------------------------------------
Permission service managing computer-access permission toggles and user approval requests.
"""

import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import Optional

from sqlalchemy.orm import Session

from app.core.exceptions import (
    ApprovalRequiredError,
    AuthError,
    ComputerAccessDisabledError,
)
from app.core.logger import get_logger
from app.database.models import ComputerAccessApproval, UserComputerAccess

logger = get_logger(__name__)


class PermissionService:
    """
    Manages server-side computer access toggles and explicit user action approvals.
    """

    def is_computer_access_enabled(self, db: Session, user_id: str) -> bool:
        """
        Check if computer access is enabled for the specified user.
        Defaults to False (DISABLED).
        """
        record = db.get(UserComputerAccess, user_id)
        if record is None:
            return False
        return bool(record.enabled)

    def set_computer_access_enabled(
        self, db: Session, user_id: str, enabled: bool
    ) -> bool:
        """
        Enable or disable computer access for the specified user.
        """
        record = db.get(UserComputerAccess, user_id)
        if record is None:
            record = UserComputerAccess(user_id=user_id, enabled=enabled)
            db.add(record)
        else:
            record.enabled = enabled
            record.updated_at = datetime.now(UTC)
        db.commit()
        db.refresh(record)
        logger.info(
            "Computer access toggle updated for user %s: enabled=%s", user_id, enabled
        )
        return record.enabled

    def create_approval_request(
        self,
        db: Session,
        user_id: str,
        action: str,
        parameters: dict,
        expires_in_minutes: int = 15,
    ) -> ComputerAccessApproval:
        """
        Create a new pending approval request for a write action.
        """
        approval_id = str(uuid.uuid4())
        # Sanitise parameters for approval storage (exclude full text content if large)
        safe_params = {k: v for k, v in parameters.items()}
        if "content" in safe_params and isinstance(safe_params["content"], str) and len(safe_params["content"]) > 100:
            safe_params["content"] = f"[{len(safe_params['content'])} characters content]"

        expires_at = datetime.now(UTC) + timedelta(minutes=expires_in_minutes)

        approval = ComputerAccessApproval(
            id=approval_id,
            user_id=user_id,
            action=action,
            parameters_json=json.dumps(safe_params),
            status="pending",
            expires_at=expires_at,
        )
        db.add(approval)
        db.commit()
        db.refresh(approval)
        logger.info("Created action approval request %s for user %s, action %s", approval_id, user_id, action)
        return approval

    def approve_request(
        self, db: Session, approval_id: str, user_id: str
    ) -> ComputerAccessApproval:
        """
        Approve a pending approval request.

        Raises
        ------
        AuthError
            If approval does not exist or belongs to another user.
        """
        approval = db.get(ComputerAccessApproval, approval_id)
        if approval is None:
            raise AuthError(f"Approval request '{approval_id}' not found.")
        if approval.user_id != user_id:
            logger.warning(
                "User %s attempted to approve approval request %s belonging to user %s",
                user_id,
                approval_id,
                approval.user_id,
            )
            raise AuthError("Unauthorized: cannot approve an action belonging to another user.")

        if approval.status != "pending":
            logger.info("Approval request %s is already status: %s", approval_id, approval.status)

        approval.status = "approved"
        approval.updated_at = datetime.now(UTC)
        db.commit()
        db.refresh(approval)
        logger.info("User %s approved action request %s (%s)", user_id, approval_id, approval.action)
        return approval

    def is_approval_valid(
        self, db: Session, approval_id: str, user_id: str, action: str
    ) -> bool:
        """
        Verify if an approval request is valid, approved, owned by user_id, and matches the action.
        """
        approval = db.get(ComputerAccessApproval, approval_id)
        if approval is None:
            return False
        if approval.user_id != user_id or approval.action != action:
            return False
        return approval.status == "approved"
