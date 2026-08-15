"""
services/computer_access/action_registry.py
--------------------------------------------
Action registry for safe local-computer access system.

Defines a fixed allowlist of safe computer actions.
Disallows arbitrary shell execution, process spawning, Python code execution,
and administrative system calls.
"""

from dataclasses import dataclass
from typing import Dict, Type

from pydantic import BaseModel, ValidationError

from app.core.exceptions import ActionNotAllowedError
from app.schemas.computer_access import (
    CopyFileParams,
    CreateDirectoryParams,
    CreateTextFileParams,
    ListDirectoryParams,
    MoveFileParams,
    ReadTextFileParams,
    WriteTextFileParams,
)


@dataclass(frozen=True)
class ActionDefinition:
    """Metadata definition for a registered safe computer action."""

    name: str
    description: str
    risk_level: str  # "READ" or "WRITE"
    requires_approval: bool
    params_schema: Type[BaseModel]


class ActionRegistry:
    """
    Registry enforcing fixed allowlist of allowed safe actions.
    """

    def __init__(self) -> None:
        self._actions: Dict[str, ActionDefinition] = {}
        self._register_default_actions()

    def _register_default_actions(self) -> None:
        """Register the 7 safe filesystem actions."""
        self.register_action(
            ActionDefinition(
                name="list_directory",
                description="List contents of a directory within the Cipherix workspace.",
                risk_level="READ",
                requires_approval=False,
                params_schema=ListDirectoryParams,
            )
        )
        self.register_action(
            ActionDefinition(
                name="read_text_file",
                description="Read contents of a text file within the Cipherix workspace.",
                risk_level="READ",
                requires_approval=False,
                params_schema=ReadTextFileParams,
            )
        )
        self.register_action(
            ActionDefinition(
                name="create_directory",
                description="Create a directory within the Cipherix workspace.",
                risk_level="WRITE",
                requires_approval=True,
                params_schema=CreateDirectoryParams,
            )
        )
        self.register_action(
            ActionDefinition(
                name="create_text_file",
                description="Create a new text file within the Cipherix workspace.",
                risk_level="WRITE",
                requires_approval=True,
                params_schema=CreateTextFileParams,
            )
        )
        self.register_action(
            ActionDefinition(
                name="write_text_file",
                description="Write or overwrite content in a text file within the Cipherix workspace.",
                risk_level="WRITE",
                requires_approval=True,
                params_schema=WriteTextFileParams,
            )
        )
        self.register_action(
            ActionDefinition(
                name="copy_file",
                description="Copy a file within the Cipherix workspace.",
                risk_level="WRITE",
                requires_approval=True,
                params_schema=CopyFileParams,
            )
        )
        self.register_action(
            ActionDefinition(
                name="move_file",
                description="Move or rename a file within the Cipherix workspace.",
                risk_level="WRITE",
                requires_approval=True,
                params_schema=MoveFileParams,
            )
        )

    def register_action(self, action: ActionDefinition) -> None:
        """Register an action in the allowlist."""
        self._actions[action.name] = action

    def get_action(self, action_name: str) -> ActionDefinition:
        """
        Lookup action metadata by name.

        Raises
        ------
        ActionNotAllowedError
            If action is not in the registered allowlist.
        """
        if not action_name or action_name not in self._actions:
            raise ActionNotAllowedError(
                f"Action '{action_name}' is not allowed or not registered."
            )
        return self._actions[action_name]

    def validate_parameters(self, action_name: str, parameters: dict) -> BaseModel:
        """
        Validate input parameters against the Pydantic schema for the action.
        """
        action_def = self.get_action(action_name)
        try:
            return action_def.params_schema.model_validate(parameters or {})
        except ValidationError as err:
            raise ActionNotAllowedError(
                f"Invalid parameters for action '{action_name}': {err}"
            ) from err

    def is_action_allowed(self, action_name: str) -> bool:
        """Check if action is registered."""
        return action_name in self._actions

    def list_actions(self) -> list[ActionDefinition]:
        """Return list of all registered actions."""
        return list(self._actions.values())
