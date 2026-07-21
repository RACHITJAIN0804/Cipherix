"""
services/vault_service.py
-------------------------
Business-logic layer for vault operations.

:class:`VaultService` sits between the API route (HTTP concerns) and
:class:`~app.vault.vault_manager.VaultManager` (filesystem concerns).
Its responsibilities are:

1. **Validate** the incoming request beyond what Pydantic can express
   (e.g. business rules that depend on runtime state).
2. **Orchestrate** domain objects — generate the vault ID, build the
   manifest, call the manager, compose the response.
3. **Translate** domain exceptions into a form the route layer can act on.

This layer intentionally knows nothing about FastAPI, HTTP status codes,
or JSON serialisation.  Those concerns belong to the route.

Dependency injection
--------------------
The service receives a :class:`~app.vault.vault_manager.VaultManager`
via its constructor, which makes it straightforward to swap in a fake
manager during unit testing.
"""

import uuid
from datetime import UTC, datetime

from app.core.exceptions import VaultCreationError, VaultManifestError, VaultValidationError
from app.core.logger import get_logger
from app.schemas.vault import CreateVaultRequest, VaultResponse, VaultSummary
from app.vault.manifest import VaultManifest
from app.vault.vault_manager import VaultManager

logger = get_logger(__name__)


class VaultService:
    """
    Orchestrates vault creation and listing.

    Parameters
    ----------
    manager:
        A :class:`~app.vault.vault_manager.VaultManager` instance that
        will perform the actual filesystem operations.
    """

    def __init__(self, manager: VaultManager) -> None:
        self._manager: VaultManager = manager

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def create_vault(self, request: CreateVaultRequest) -> VaultResponse:
        """
        Create a new vault and return its serialised representation.

        Flow
        ----
        1. Run additional business-rule validation on the request.
        2. Generate a collision-free UUID4 vault identifier.
        3. Build a :class:`~app.vault.manifest.VaultManifest`.
        4. Delegate filesystem scaffolding to :class:`~app.vault.vault_manager.VaultManager`.
        5. Compose and return a :class:`~app.schemas.vault.VaultResponse`.

        Parameters
        ----------
        request:
            A Pydantic-validated :class:`~app.schemas.vault.CreateVaultRequest`.

        Returns
        -------
        VaultResponse
            Metadata of the newly created vault.

        Raises
        ------
        VaultValidationError
            If the request violates a business rule not captured by Pydantic.
        VaultCreationError
            If the filesystem scaffolding fails.
        """
        self._validate(request)

        vault_id: str = str(uuid.uuid4())
        logger.info("Initiating vault creation | name=%r | id=%s", request.name, vault_id)

        manifest = VaultManifest.create(vault_id=vault_id, name=request.name)

        self._manager.create(vault_id=vault_id, manifest=manifest)

        logger.info("Vault created successfully | id=%s | name=%r", vault_id, request.name)

        return VaultResponse(
            vault_id=vault_id,
            name=manifest.name,
            created_at=datetime.fromisoformat(manifest.created_at),
            status=manifest.status,
        )

    def list_vaults(self) -> list[VaultSummary]:
        """
        Return a summary of every valid vault, sorted newest-first.

        Flow
        ----
        1. Delegate discovery to :meth:`~app.vault.vault_manager.VaultManager.list_vaults`.
        2. For each returned manifest, convert to :class:`~app.schemas.vault.VaultSummary`.
        3. Skip any vault whose manifest is corrupt (log a warning, continue).
        4. Sort by ``created_at`` descending (newest first).

        Returns
        -------
        list[VaultSummary]
            Zero or more vault summaries, newest first.  Returns an empty
            list when no vaults exist — never raises in that case.
        """
        raw_manifests = self._manager.list_vaults()

        summaries: list[VaultSummary] = []
        for manifest in raw_manifests:
            try:
                summaries.append(
                    VaultSummary(
                        vault_id=manifest.vault_id,
                        name=manifest.name,
                        created_at=datetime.fromisoformat(manifest.created_at),
                        status=manifest.status,
                    )
                )
            except (ValueError, TypeError) as exc:
                # A VaultManifest read succeeded but contained an
                # unparseable created_at or other field.  Treat as corrupt.
                logger.warning(
                    "Skipping vault with invalid manifest data | "
                    "vault_id=%s | error=%s",
                    getattr(manifest, "vault_id", "<unknown>"),
                    exc,
                )

        summaries.sort(
            key=lambda s: s.created_at,
            reverse=True,
        )

        logger.info("Listing vaults | count=%d", len(summaries))
        return summaries

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _validate(self, request: CreateVaultRequest) -> None:
        """
        Enforce business rules that Pydantic alone cannot express.

        Pydantic handles structural validation (types, lengths, patterns).
        This method handles *semantic* validation that may depend on
        application-level rules or future runtime state (e.g. "a vault
        with this name already exists for this user").

        Raises
        ------
        VaultValidationError
            On any business-rule violation.
        """
        # Belt-and-suspenders guard: Pydantic already strips whitespace,
        # but we re-check here so the service layer is correct in isolation.
        if not request.name or not request.name.strip():
            raise VaultValidationError(
                "Vault name must not be empty.",
                detail="Provide a non-empty name between 3 and 50 characters.",
            )
