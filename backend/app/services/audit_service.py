"""
app/services/audit_service.py
------------------------------
Centralized Audit Logging Service using ComputerAccessAuditLog model.
Records secure audit trail events for authentication, vault operations,
computer access, and blockchain hash anchoring/verifications.
"""

import json
import uuid
from datetime import UTC, datetime
from typing import Any, Dict, Optional

from sqlalchemy.orm import Session

from app.core.logger import get_logger
from app.database.models import ComputerAccessAuditLog

logger = get_logger(__name__)

# Standard Audit Event Types for Blockchain
EVENT_BLOCKCHAIN_ANCHOR_SUCCESS = "blockchain_anchor_success"
EVENT_BLOCKCHAIN_ANCHOR_FAILURE = "blockchain_anchor_failure"
EVENT_BLOCKCHAIN_VERIFY_REQUEST = "blockchain_verify_request"
EVENT_BLOCKCHAIN_VERIFY_SUCCESS = "blockchain_verify_success"
EVENT_BLOCKCHAIN_VERIFY_MISMATCH = "blockchain_verify_mismatch"
EVENT_BLOCKCHAIN_VERIFY_UNAVAILABLE = "blockchain_verify_unavailable"
EVENT_BLOCKCHAIN_VERIFY_MISSING_RECORD = "blockchain_verify_missing_record"


class AuditService:
    """Centralized Audit Logging Service using ComputerAccessAuditLog."""

    @staticmethod
    def log_event(
        db: Session,
        user_id: str,
        action: str,
        vault_id: Optional[str] = None,
        document_id: Optional[str] = None,
        result_status: str = "SUCCESS",
        approval_status: str = "AUTOMATIC",
        details: Optional[Dict[str, Any]] = None,
    ) -> Optional[ComputerAccessAuditLog]:
        try:
            safe_details = {}
            if details:
                for k, v in details.items():
                    # Sanitize: NEVER log keys, seed phrases, passwords, or plaintext content
                    if k.lower() in ("content", "password", "key", "seed", "token", "jwt", "plaintext", "vault_key", "master_key"):
                        continue
                    safe_details[k] = v

            details_json = json.dumps(safe_details) if safe_details else None

            log_entry = ComputerAccessAuditLog(
                id=str(uuid.uuid4()),
                user_id=user_id,
                vault_id=vault_id,
                action=action,
                relative_path=document_id,
                result_status=result_status,
                approval_status=approval_status,
                details_json=details_json,
                created_at=datetime.now(UTC),
            )

            try:
                nested = db.begin_nested()
                db.add(log_entry)
                nested.commit()
            except Exception:
                db.add(log_entry)
                db.flush()

            return log_entry
        except Exception as exc:
            logger.warning("Audit logging failed for action '%s': %s", action, exc)
            return None
