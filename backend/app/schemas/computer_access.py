"""
schemas/computer_access.py
---------------------------
Pydantic validation schemas for computer access request/response data models.
"""

from datetime import datetime
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field, ConfigDict


class ToggleAccessRequest(BaseModel):
    """Request payload to enable or disable computer access for the authenticated user."""

    enabled: bool = Field(
        ..., description="True to enable computer access, False to disable."
    )


class AccessStatusResponse(BaseModel):
    """Response containing computer access state for the authenticated user."""

    enabled: bool = Field(..., description="Whether computer access is currently enabled.")
    workspace_root: str = Field(..., description="Canonical path of the user's workspace directory.")


class ListDirectoryParams(BaseModel):
    """Parameters for list_directory action."""

    model_config = ConfigDict(extra="forbid")
    path: str = Field(default="", description="Relative path to directory within workspace.")


class ReadTextFileParams(BaseModel):
    """Parameters for read_text_file action."""

    model_config = ConfigDict(extra="forbid")
    path: str = Field(..., description="Relative path to text file within workspace.")


class CreateDirectoryParams(BaseModel):
    """Parameters for create_directory action."""

    model_config = ConfigDict(extra="forbid")
    path: str = Field(..., description="Relative path of directory to create within workspace.")


class CreateTextFileParams(BaseModel):
    """Parameters for create_text_file action."""

    model_config = ConfigDict(extra="forbid")
    path: str = Field(..., description="Relative path of text file to create within workspace.")
    content: str = Field(default="", description="Initial text content for file.")


class WriteTextFileParams(BaseModel):
    """Parameters for write_text_file action."""

    model_config = ConfigDict(extra="forbid")
    path: str = Field(..., description="Relative path of text file to write within workspace.")
    content: str = Field(..., description="Text content to write to file.")


class CopyFileParams(BaseModel):
    """Parameters for copy_file action."""

    model_config = ConfigDict(extra="forbid")
    src_path: str = Field(..., description="Relative path of source file within workspace.")
    dst_path: str = Field(..., description="Relative path of destination file within workspace.")


class MoveFileParams(BaseModel):
    """Parameters for move_file action."""

    model_config = ConfigDict(extra="forbid")
    src_path: str = Field(..., description="Relative path of source file within workspace.")
    dst_path: str = Field(..., description="Relative path of destination file within workspace.")


class ActionRequest(BaseModel):
    """Structured action proposal / request from user or LLM."""

    action: str = Field(..., description="Name of registered action (e.g. read_text_file).")
    parameters: Dict[str, Any] = Field(
        default_factory=dict, description="Action parameters dictionary."
    )
    approved: bool = Field(
        default=False, description="Flag indicating user explicit approval."
    )
    approval_id: Optional[str] = Field(
        default=None, description="Optional pending approval ID."
    )
    vault_id: Optional[str] = Field(
        default=None, description="Optional vault ID scope."
    )


class ActionResponse(BaseModel):
    """Structured action execution or approval challenge response."""

    success: bool = Field(..., description="Whether the request succeeded.")
    action: str = Field(..., description="Name of action processed.")
    status: str = Field(..., description="Status ('executed', 'approval_required', 'rejected', 'failed').")
    requires_approval: bool = Field(default=False, description="Whether explicit approval is required.")
    approval_id: Optional[str] = Field(default=None, description="Pending approval ID if approval required.")
    result: Optional[Any] = Field(default=None, description="Action execution result output.")
    error: Optional[str] = Field(default=None, description="Error message if failed or rejected.")


class ApproveActionRequest(BaseModel):
    """Payload to approve a pending write action by approval ID."""

    approval_id: str = Field(..., description="UUID of pending action approval request.")


class AuditLogResponse(BaseModel):
    """Computer access audit log entry response."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    user_id: str
    vault_id: Optional[str] = None
    action: str
    relative_path: Optional[str] = None
    result_status: str
    approval_status: str
    details_json: Optional[str] = None
    created_at: datetime
