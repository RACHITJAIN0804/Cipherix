
from datetime import datetime
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field, ConfigDict


class ToggleAccessRequest(BaseModel):

    enabled: bool = Field(
        ..., description="True to enable computer access, False to disable."
    )


class AccessStatusResponse(BaseModel):

    enabled: bool = Field(..., description="Whether computer access is currently enabled.")
    workspace_root: str = Field(..., description="Canonical path of the user's workspace directory.")


class ListDirectoryParams(BaseModel):

    model_config = ConfigDict(extra="forbid")
    path: str = Field(default="", description="Relative path to directory within workspace.")


class ReadTextFileParams(BaseModel):

    model_config = ConfigDict(extra="forbid")
    path: str = Field(..., description="Relative path to text file within workspace.")


class CreateDirectoryParams(BaseModel):

    model_config = ConfigDict(extra="forbid")
    path: str = Field(..., description="Relative path of directory to create within workspace.")


class CreateTextFileParams(BaseModel):

    model_config = ConfigDict(extra="forbid")
    path: str = Field(..., description="Relative path of text file to create within workspace.")
    content: str = Field(default="", description="Initial text content for file.")


class WriteTextFileParams(BaseModel):

    model_config = ConfigDict(extra="forbid")
    path: str = Field(..., description="Relative path of text file to write within workspace.")
    content: str = Field(..., description="Text content to write to file.")


class CopyFileParams(BaseModel):

    model_config = ConfigDict(extra="forbid")
    src_path: str = Field(..., description="Relative path of source file within workspace.")
    dst_path: str = Field(..., description="Relative path of destination file within workspace.")


class MoveFileParams(BaseModel):

    model_config = ConfigDict(extra="forbid")
    src_path: str = Field(..., description="Relative path of source file within workspace.")
    dst_path: str = Field(..., description="Relative path of destination file within workspace.")


class ActionRequest(BaseModel):

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

    success: bool = Field(..., description="Whether the request succeeded.")
    action: str = Field(..., description="Name of action processed.")
    status: str = Field(..., description="Status ('executed', 'approval_required', 'rejected', 'failed').")
    requires_approval: bool = Field(default=False, description="Whether explicit approval is required.")
    approval_id: Optional[str] = Field(default=None, description="Pending approval ID if approval required.")
    result: Optional[Any] = Field(default=None, description="Action execution result output.")
    error: Optional[str] = Field(default=None, description="Error message if failed or rejected.")


class ApproveActionRequest(BaseModel):

    approval_id: str = Field(..., description="UUID of pending action approval request.")


class AuditLogResponse(BaseModel):

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
