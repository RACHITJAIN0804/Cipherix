"""
services/computer_access/actions/filesystem.py
------------------------------------------------
Safe filesystem action executors.

All operations execute strictly through PathGuard validation to guarantee
path sandboxing within CIPHERIX_WORKSPACE.
"""

import shutil
from pathlib import Path
from typing import Any, Dict

from app.core.exceptions import ActionExecutionError
from app.core.logger import get_logger
from app.schemas.computer_access import (
    CopyFileParams,
    CreateDirectoryParams,
    CreateTextFileParams,
    ListDirectoryParams,
    MoveFileParams,
    ReadTextFileParams,
    WriteTextFileParams,
)
from app.services.computer_access.path_guard import PathGuard

logger = get_logger(__name__)


def _get_relative_str(path: Path, root: Path) -> str:
    try:
        rel = path.relative_to(root)
        return str(rel).replace("\\", "/")
    except ValueError:
        return str(path).replace("\\", "/")


def execute_list_directory(path_guard: PathGuard, params: ListDirectoryParams) -> Dict[str, Any]:
    """Execute list_directory safe action."""
    target_path = path_guard.validate_and_resolve(params.path)
    if not target_path.exists():
        raise ActionExecutionError(f"Directory '{params.path}' does not exist.")
    if not target_path.is_dir():
        raise ActionExecutionError(f"Path '{params.path}' is not a directory.")

    entries = []
    root = path_guard.get_workspace_root()
    try:
        for child in target_path.iterdir():
            entries.append(
                {
                    "name": child.name,
                    "type": "directory" if child.is_dir() else "file",
                    "size": child.stat().st_size if child.is_file() else 0,
                    "path": _get_relative_str(child, root),
                }
            )
    except Exception as err:
        raise ActionExecutionError(f"Failed to list directory '{params.path}': {err}") from err

    return {
        "path": _get_relative_str(target_path, root),
        "entries": entries,
        "count": len(entries),
    }


def execute_read_text_file(path_guard: PathGuard, params: ReadTextFileParams) -> Dict[str, Any]:
    """Execute read_text_file safe action."""
    target_path = path_guard.validate_and_resolve(params.path)
    if not target_path.exists():
        raise ActionExecutionError(f"File '{params.path}' does not exist.")
    if not target_path.is_file():
        raise ActionExecutionError(f"Path '{params.path}' is not a file.")

    root = path_guard.get_workspace_root()
    try:
        content = target_path.read_text(encoding="utf-8")
        return {
            "path": _get_relative_str(target_path, root),
            "content": content,
            "size": len(content),
        }
    except UnicodeDecodeError as err:
        raise ActionExecutionError(f"File '{params.path}' is not a readable text file (binary file): {err}") from err
    except Exception as err:
        raise ActionExecutionError(f"Failed to read file '{params.path}': {err}") from err


def execute_create_directory(path_guard: PathGuard, params: CreateDirectoryParams) -> Dict[str, Any]:
    """Execute create_directory safe action."""
    target_path = path_guard.validate_and_resolve(params.path)
    root = path_guard.get_workspace_root()
    try:
        target_path.mkdir(parents=True, exist_ok=True)
        return {
            "path": _get_relative_str(target_path, root),
            "status": "created",
        }
    except Exception as err:
        raise ActionExecutionError(f"Failed to create directory '{params.path}': {err}") from err


def execute_create_text_file(path_guard: PathGuard, params: CreateTextFileParams) -> Dict[str, Any]:
    """Execute create_text_file safe action."""
    target_path = path_guard.validate_and_resolve(params.path)
    root = path_guard.get_workspace_root()
    try:
        target_path.parent.mkdir(parents=True, exist_ok=True)
        target_path.write_text(params.content, encoding="utf-8")
        return {
            "path": _get_relative_str(target_path, root),
            "status": "created",
            "size": len(params.content),
        }
    except Exception as err:
        raise ActionExecutionError(f"Failed to create text file '{params.path}': {err}") from err


def execute_write_text_file(path_guard: PathGuard, params: WriteTextFileParams) -> Dict[str, Any]:
    """Execute write_text_file safe action."""
    target_path = path_guard.validate_and_resolve(params.path)
    root = path_guard.get_workspace_root()
    try:
        target_path.parent.mkdir(parents=True, exist_ok=True)
        target_path.write_text(params.content, encoding="utf-8")
        return {
            "path": _get_relative_str(target_path, root),
            "status": "written",
            "size": len(params.content),
        }
    except Exception as err:
        raise ActionExecutionError(f"Failed to write text file '{params.path}': {err}") from err


def execute_copy_file(path_guard: PathGuard, params: CopyFileParams) -> Dict[str, Any]:
    """Execute copy_file safe action."""
    src_path = path_guard.validate_and_resolve(params.src_path)
    dst_path = path_guard.validate_and_resolve(params.dst_path)

    if not src_path.exists():
        raise ActionExecutionError(f"Source file '{params.src_path}' does not exist.")
    if not src_path.is_file():
        raise ActionExecutionError(f"Source '{params.src_path}' is not a file.")

    root = path_guard.get_workspace_root()
    try:
        dst_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src_path, dst_path)
        return {
            "src_path": _get_relative_str(src_path, root),
            "dst_path": _get_relative_str(dst_path, root),
            "status": "copied",
        }
    except Exception as err:
        raise ActionExecutionError(f"Failed to copy file from '{params.src_path}' to '{params.dst_path}': {err}") from err


def execute_move_file(path_guard: PathGuard, params: MoveFileParams) -> Dict[str, Any]:
    """Execute move_file safe action."""
    src_path = path_guard.validate_and_resolve(params.src_path)
    dst_path = path_guard.validate_and_resolve(params.dst_path)

    if not src_path.exists():
        raise ActionExecutionError(f"Source path '{params.src_path}' does not exist.")

    root = path_guard.get_workspace_root()
    try:
        dst_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(src_path, dst_path)
        return {
            "src_path": _get_relative_str(src_path, root),
            "dst_path": _get_relative_str(dst_path, root),
            "status": "moved",
        }
    except Exception as err:
        raise ActionExecutionError(f"Failed to move path from '{params.src_path}' to '{params.dst_path}': {err}") from err
