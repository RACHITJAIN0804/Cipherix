
import os
from pathlib import Path

from app.core.exceptions import PathGuardError
from app.core.logger import get_logger

logger = get_logger(__name__)


class PathGuard:

    def __init__(self, workspace_root: Path) -> None:
        self.workspace_root: Path = workspace_root.resolve()
        self.workspace_root.mkdir(parents=True, exist_ok=True)

    def get_workspace_root(self) -> Path:
        return self.workspace_root

    def validate_and_resolve(self, path_str: str) -> Path:
        if path_str is None:
            raise PathGuardError("Path parameter cannot be None.")

        cleaned = str(path_str).strip()


        if cleaned.startswith("\\\\") or cleaned.startswith("//"):
            logger.warning("PathGuard blocked UNC path: %s", cleaned)
            raise PathGuardError(f"UNC path '{cleaned}' is strictly prohibited.")


        if len(cleaned) >= 2 and cleaned[1] == ":" and cleaned[0].isalpha():

            resolved_abs = Path(cleaned).resolve()
            try:
                if resolved_abs.is_relative_to(self.workspace_root):
                    return resolved_abs
            except (ValueError, Exception):
                pass
            logger.warning("PathGuard blocked drive specification: %s", cleaned)
            raise PathGuardError(f"Absolute drive path '{cleaned}' is prohibited outside workspace.")


        normalized_str = cleaned.replace("\\", "/")
        parts = [p for p in normalized_str.split("/") if p]
        if ".." in parts:
            logger.warning("PathGuard blocked path containing parent directory traversal: %s", cleaned)
            raise PathGuardError(f"Path traversal sequence '..' in '{cleaned}' is strictly prohibited.")


        candidate = (self.workspace_root / cleaned)

        try:
            resolved = candidate.resolve()
        except Exception as err:
            logger.warning("PathGuard failed to resolve path '%s': %s", cleaned, err)
            raise PathGuardError(f"Failed to resolve path '{cleaned}': {err}") from err


        try:
            is_inside = resolved.is_relative_to(self.workspace_root)
        except AttributeError:

            try:
                resolved.relative_to(self.workspace_root)
                is_inside = True
            except ValueError:
                is_inside = False

        if not is_inside:
            logger.warning("PathGuard blocked path escape outside root: %s -> %s", cleaned, resolved)
            raise PathGuardError(f"Path '{cleaned}' resolves outside allowed workspace root.")


        check_path = resolved if resolved.exists() else resolved.parent
        if check_path.exists():
            try:
                real_path = Path(os.path.realpath(check_path))
                if not real_path.is_relative_to(self.workspace_root):
                    logger.warning("PathGuard blocked symlink escape: %s -> %s", cleaned, real_path)
                    raise PathGuardError(f"Symlink target for '{cleaned}' escapes workspace root.")
            except Exception as err:
                raise PathGuardError(f"Failed symlink validation for '{cleaned}': {err}") from err

        return resolved
