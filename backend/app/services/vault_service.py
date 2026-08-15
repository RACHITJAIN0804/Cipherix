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
3. **Persist** application metadata in SQLite via the injected session.
4. **Translate** domain exceptions into a form the route layer can act on.

Filesystem / SQLite separation
--------------------------------
The filesystem (VaultManager) is the authoritative source of truth for
vault structure and cryptographic files.  SQLite stores application
metadata that enables future search, reporting, and cross-vault queries
without scanning the filesystem.

Transaction safety
------------------
Vault creation:
    1. Filesystem scaffolding (VaultManager.create).
    2. DB INSERT (Vault + SecurityMetadata).
    3. DB COMMIT.
    → On DB commit failure: shutil.rmtree(vault_root) to leave no orphan.

Vault deletion:
    1. Filesystem deletion (VaultManager.delete_vault).
    2. DB DELETE of the Vault row (CASCADE removes Documents + SecurityMetadata).
    3. DB COMMIT.
    → On DB failure: log the orphaned DB record; the filesystem is already clean.

This layer intentionally knows nothing about FastAPI, HTTP status codes,
or JSON serialisation.  Those concerns belong to the route.

Dependency injection
--------------------
The service receives a :class:`~app.vault.vault_manager.VaultManager`
via its constructor and an optional :class:`~sqlalchemy.orm.Session` per
method call.  Passing ``db=None`` disables DB persistence (useful in tests
that focus on filesystem behaviour only).
"""

import shutil
import uuid
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.exceptions import (
    VaultCreationError,
    VaultError,
    VaultStateError,
    VaultValidationError,
)
from app.core.logger import get_logger
from app.database.models import SecurityMetadata as SecurityMetadataRecord
from app.database.models import Vault as VaultRecord
from app.schemas.vault import (
    CreateVaultRequest,
    VaultResponse,
    VaultStateResponse,
    VaultSummary,
)
from app.vault.manifest import VaultManifest
from app.vault.vault_manager import VaultManager

logger = get_logger(__name__)

_STATUS_LOCKED: str = "locked"
_STATUS_UNLOCKED: str = "unlocked"


class VaultService:
    """
    Orchestrates vault creation, listing, deletion, and state transitions.

    Parameters
    ----------
    manager:
        A :class:`~app.vault.vault_manager.VaultManager` instance that
        will perform the actual filesystem operations.
    """

    def __init__(self, manager: VaultManager) -> None:
        self._manager: VaultManager = manager

    def create_vault(
        self,
        request: CreateVaultRequest,
        user_id: str | None = None,
        db: Session | None = None,
    ) -> VaultResponse:
        """
        Create a new vault, persist metadata to SQLite, and return its
        serialised representation.

        Flow
        ----
        1. Run additional business-rule validation on the request.
        2. Generate a collision-free UUID4 vault identifier.
        3. Build a :class:`~app.vault.manifest.VaultManifest`.
        4. Delegate filesystem scaffolding to
           :class:`~app.vault.vault_manager.VaultManager`.
        5. If ``db`` is provided: INSERT Vault + SecurityMetadata rows.
           Associate the Vault row with ``user_id`` if supplied.
           On DB failure, remove the newly created filesystem tree.
        6. Compose and return a :class:`~app.schemas.vault.VaultResponse`.

        Parameters
        ----------
        request:
            A Pydantic-validated :class:`~app.schemas.vault.CreateVaultRequest`.
        user_id:
            Optional UUID4 string of the authenticated owner.
        db:
            SQLAlchemy session.  When provided, a Vault record and a
            SecurityMetadata record are inserted and committed.  When
            ``None``, DB persistence is skipped (e.g. in filesystem-only tests).

        Returns
        -------
        VaultResponse
            Metadata of the newly created vault.

        Raises
        ------
        VaultValidationError
            If the request violates a business rule not captured by Pydantic.
        VaultCreationError
            If the filesystem scaffolding or DB insert fails.
        """
        self._validate(request)

        vault_id: str = str(uuid.uuid4())
        logger.info(
            "Initiating vault creation | name=%r | id=%s | user_id=%s",
            request.name,
            vault_id,
            user_id,
        )

        manifest = VaultManifest.create(vault_id=vault_id, name=request.name)

        vault_root: Path = self._manager.create(
            vault_id=vault_id, manifest=manifest, password=request.password
        )

        if db is not None:
            try:
                self._insert_vault_records(
                    db=db,
                    vault_id=vault_id,
                    name=request.name,
                    vault_root=vault_root,
                    user_id=user_id,
                )
            except SQLAlchemyError as exc:
                # DB commit failed after filesystem creation succeeded.
                # Roll back the DB transaction first, then clean up the filesystem
                # tree to avoid leaving an orphaned vault on disk.
                db.rollback()
                logger.error(
                    "DB insert failed after vault created on disk — "
                    "rolling back filesystem | vault_id=%s | error=%s",
                    vault_id,
                    exc,
                )
                try:
                    shutil.rmtree(vault_root)
                    logger.info(
                        "Filesystem cleanup successful | vault_id=%s", vault_id
                    )
                except OSError as fs_exc:
                    logger.error(
                        "Filesystem cleanup FAILED after DB rollback "
                        "| vault_id=%s | error=%s",
                        vault_id,
                        fs_exc,
                    )
                raise VaultCreationError(
                    f"Failed to persist vault '{vault_id}' to the database: {exc}",
                    detail=(
                        "The vault was created on the filesystem but could not be "
                        "recorded in the database.  The vault directory has been "
                        "removed to keep the system consistent.  Please retry."
                    ),
                ) from exc

        logger.info("Vault created successfully | id=%s | name=%r", vault_id, request.name)

        return VaultResponse(
            vault_id=vault_id,
            name=manifest.name,
            created_at=datetime.fromisoformat(manifest.created_at),
            status=manifest.status,
        )

    def delete_vault(self, vault_id: str, db: Session | None = None) -> None:
        """
        Permanently delete an existing vault and all of its contents.

        Flow
        ----
        1. Validate that ``vault_id`` is a well-formed UUID4 string.
        2. Delegate filesystem removal to
           :meth:`~app.vault.vault_manager.VaultManager.delete_vault`.
        3. If ``db`` is provided: DELETE the Vault row (CASCADE removes
           all Document and SecurityMetadata rows).
        4. Log success or re-raise a typed domain exception on failure.

        Parameters
        ----------
        vault_id:
            The UUID4 string that identifies the vault to delete.
        db:
            SQLAlchemy session.  When provided, the Vault DB record is
            deleted and committed after filesystem deletion.

        Raises
        ------
        VaultValidationError
            If ``vault_id`` is not a valid UUID string.
        VaultNotFoundError
            If no vault with that ID exists on disk.
        VaultManifestError
            If the vault directory has no ``manifest.json`` (corrupt vault).
        VaultDeletionError
            If the OS prevents removing the directory tree.
        """
        self._validate_vault_id(vault_id)

        logger.info("Initiating vault deletion | vault_id=%s", vault_id)

        try:
            self._manager.delete_vault(vault_id)
        except VaultError:
            logger.warning("Vault deletion did not complete | vault_id=%s", vault_id)
            raise

        if db is not None:
            try:
                record = db.get(VaultRecord, vault_id)
                if record is not None:
                    db.delete(record)
                    db.commit()
                    logger.debug(
                        "Vault DB record deleted | vault_id=%s", vault_id
                    )
                else:
                    logger.warning(
                        "Vault deleted from filesystem but no DB record found "
                        "| vault_id=%s",
                        vault_id,
                    )
            except SQLAlchemyError as exc:
                db.rollback()
                logger.error(
                    "Failed to delete vault DB record after filesystem deletion "
                    "| vault_id=%s | error=%s",
                    vault_id,
                    exc,
                )

        logger.info("Vault deleted successfully | vault_id=%s", vault_id)

    def list_vaults(
        self,
        user_id: str | None = None,
        db: Session | None = None,
    ) -> list[VaultSummary]:
        """
        Return a summary of every valid vault belonging to user_id, sorted newest-first.

        Parameters
        ----------
        user_id:
            Optional user ID filter. When supplied alongside db, only vaults
            belonging to this user are returned.
        db:
            Optional SQLAlchemy session.

        Returns
        -------
        list[VaultSummary]
            Zero or more vault summaries, newest first.  Returns an empty
            list when no vaults exist — never raises in that case.
        """
        raw_manifests = self._manager.list_vaults()

        allowed_vault_ids: set[str] | None = None
        if db is not None and user_id is not None:
            user_records = db.query(VaultRecord.id).filter(VaultRecord.user_id == user_id).all()
            allowed_vault_ids = {r.id for r in user_records}

        summaries: list[VaultSummary] = []
        for manifest in raw_manifests:
            if allowed_vault_ids is not None and manifest.vault_id not in allowed_vault_ids:
                continue
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

        logger.info("Listing vaults | count=%d | user_id=%s", len(summaries), user_id)
        return summaries

    def lock_vault(
        self, vault_id: str, db: Session | None = None
    ) -> VaultStateResponse:
        """
        Transition a vault to the locked state.

        Delegates to :meth:`_transition_vault_state`.  Raises
        :class:`VaultStateError` if the vault is already locked.

        Parameters
        ----------
        vault_id:
            UUID4 string that identifies the vault to lock.
        db:
            SQLAlchemy session.  When provided, the Vault DB record's
            ``status`` and ``updated_at`` columns are updated after the
            filesystem manifest is written.

        Returns
        -------
        VaultStateResponse
            Confirmation that the vault is now ``"locked"``.

        Raises
        ------
        VaultValidationError
            If ``vault_id`` is not a valid UUID.
        VaultNotFoundError
            If no vault with that ID exists on disk.
        VaultManifestError
            If ``manifest.json`` is absent, unreadable, or cannot be written.
        VaultStateError
            If the vault is already locked.
        """
        return self._transition_vault_state(
            vault_id,
            target_status=_STATUS_LOCKED,
            current_label="locked",
            db=db,
        )

    def unlock_vault(
        self, vault_id: str, db: Session | None = None
    ) -> VaultStateResponse:
        """
        Transition a vault to the unlocked state.

        Delegates to :meth:`_transition_vault_state`.  Raises
        :class:`VaultStateError` if the vault is already unlocked.

        Parameters
        ----------
        vault_id:
            UUID4 string that identifies the vault to unlock.
        db:
            SQLAlchemy session.  When provided, the Vault DB record's
            ``status`` and ``updated_at`` columns are updated after the
            filesystem manifest is written.

        Returns
        -------
        VaultStateResponse
            Confirmation that the vault is now ``"unlocked"``.

        Raises
        ------
        VaultValidationError
            If ``vault_id`` is not a valid UUID.
        VaultNotFoundError
            If no vault with that ID exists on disk.
        VaultManifestError
            If ``manifest.json`` is absent, unreadable, or cannot be written.
        VaultStateError
            If the vault is already unlocked.
        """
        return self._transition_vault_state(
            vault_id,
            target_status=_STATUS_UNLOCKED,
            current_label="unlocked",
            db=db,
        )

    def _insert_vault_records(
        self,
        db: Session,
        vault_id: str,
        name: str,
        vault_root: Path,
        user_id: str | None = None,
    ) -> None:
        """
        Read the key + password metadata files that VaultManager just wrote
        and insert the corresponding Vault + SecurityMetadata DB rows in a
        single atomic transaction.

        This method must be called AFTER VaultManager.create() has
        successfully written all JSON files to disk.  It reads those files
        to populate the SecurityMetadata columns, ensuring the DB record
        mirrors the on-disk state.

        Parameters
        ----------
        db:
            An open SQLAlchemy session (not yet committed).
        vault_id:
            UUID4 string identifying the new vault.
        name:
            Human-readable vault name from the create request.
        vault_root:
            Absolute path to the vault root directory on disk.
        user_id:
            Optional owner user ID string.

        Raises
        ------
        SQLAlchemyError
            Propagated from the ORM add/commit on any DB error.
        """
        import json

        from app.security.kdf_params import KdfParams

        now = datetime.now(UTC)

        key_json_path = vault_root / "key.json"
        key_data: dict = json.loads(key_json_path.read_text(encoding="utf-8"))

        pwd_meta_path = vault_root / "password_meta.json"
        pwd_data: dict = json.loads(pwd_meta_path.read_text(encoding="utf-8"))
        kdf_params = KdfParams.from_dict(pwd_data.get("kdf", {}))
        salt_hex: str = pwd_data.get("salt", "")

        vault_record = VaultRecord(
            id=vault_id,
            name=name,
            status="locked",
            security_version="1.0",
            user_id=user_id,
            created_at=now,
            updated_at=now,
        )
        db.add(vault_record)

        # encrypted_vault_key stores CIPHERTEXT — never plaintext.
        # salt and nonce are not secret; they are required for future
        # Master Key re-derivation and AES-GCM decryption respectively.
        security_record = SecurityMetadataRecord(
            vault_id=vault_id,
            key_version=key_data.get("key_version", "1"),
            encryption_algorithm=key_data.get("algorithm", "AES-256-GCM"),
            encrypted_vault_key=key_data.get("encrypted_vault_key", ""),
            nonce=key_data.get("nonce", ""),
            salt=salt_hex,
            argon2_time_cost=kdf_params.time_cost,
            argon2_memory_cost=kdf_params.memory_cost,
            argon2_parallelism=kdf_params.parallelism,
            argon2_hash_len=kdf_params.hash_len,
            recovery_version=None,
            seed_fingerprint=None,
            created_at=now,
            updated_at=now,
        )
        db.add(security_record)

        db.commit()

        logger.info(
            "Vault + SecurityMetadata DB records inserted | vault_id=%s",
            vault_id,
        )

    def _transition_vault_state(
        self,
        vault_id: str,
        target_status: str,
        current_label: str,
        db: Session | None = None,
    ) -> VaultStateResponse:
        """
        Core implementation shared by :meth:`lock_vault` and :meth:`unlock_vault`.

        Flow
        ----
        1. Validate ``vault_id`` is a well-formed UUID.
        2. Read the current manifest from disk.
        3. Guard against a no-op: raise :class:`VaultStateError` if the
           vault is already in ``target_status``.
        4. Delegate the status write to
           :meth:`~app.vault.vault_manager.VaultManager.update_vault_status`.
        5. If ``db`` is provided: update the Vault DB row's ``status`` and
           ``updated_at``.  A DB failure is logged but does not roll back the
           filesystem change — the manifest on disk is authoritative.
        6. Log the operation and return a :class:`VaultStateResponse`.

        Parameters
        ----------
        vault_id:
            UUID4 string that identifies the vault.
        target_status:
            The status string to transition to (``"locked"`` or ``"unlocked"``).
        current_label:
            Human-readable label for the target state, used in error messages
            and log output (e.g. ``"locked"``, ``"unlocked"``).
        db:
            Optional SQLAlchemy session.  When provided, syncs the Vault row.

        Returns
        -------
        VaultStateResponse
            Confirmation of the new vault state.

        Raises
        ------
        VaultValidationError
            If ``vault_id`` is not a valid UUID.
        VaultNotFoundError
            If no vault with that ID exists on disk.
        VaultManifestError
            If ``manifest.json`` is absent, unreadable, or cannot be written.
        VaultStateError
            If the vault is already in ``target_status``.
        """
        self._validate_vault_id(vault_id)
        logger.info(
            "Initiating vault %s | vault_id=%s", current_label, vault_id
        )

        manifest = self._manager.read_manifest(vault_id)

        if manifest.status == target_status:
            logger.warning(
                "State transition rejected: vault already %s | vault_id=%s",
                current_label,
                vault_id,
            )
            raise VaultStateError(
                f"Vault '{vault_id}' is already {current_label}.",
                detail=(
                    f"Vault '{vault_id}' is already in the '{target_status}' state. "
                    "No change was made."
                ),
            )

        self._manager.update_vault_status(vault_id, target_status)
        logger.info(
            "Vault %s successfully | vault_id=%s", current_label, vault_id
        )

        # Sync the Vault DB row status.  A DB failure here is non-fatal:
        # the filesystem manifest is the authoritative state; a stale DB
        # record will be reconciled on the next operation.
        if db is not None:
            try:
                vault_record = db.get(VaultRecord, vault_id)
                if vault_record is not None:
                    vault_record.status = target_status
                    vault_record.updated_at = datetime.now(UTC)
                    db.commit()
                    logger.debug(
                        "Vault DB status synced | vault_id=%s | status=%s",
                        vault_id,
                        target_status,
                    )
                else:
                    logger.warning(
                        "Vault DB record not found during status sync "
                        "| vault_id=%s",
                        vault_id,
                    )
            except SQLAlchemyError as exc:
                db.rollback()
                logger.warning(
                    "Failed to sync Vault DB status — disk manifest is current; "
                    "DB record is stale | vault_id=%s | error=%s",
                    vault_id,
                    exc,
                )

        return VaultStateResponse(vault_id=vault_id, status=target_status)

    def _validate(self, request: CreateVaultRequest) -> None:
        """
        Enforce business rules that Pydantic alone cannot express.

        Raises
        ------
        VaultValidationError
            On any business-rule violation.
        """
        if not request.name or not request.name.strip():
            raise VaultValidationError(
                "Vault name must not be empty.",
                detail="Provide a non-empty name between 3 and 50 characters.",
            )

    def _validate_vault_id(self, vault_id: str) -> None:
        """
        Ensure ``vault_id`` is a valid UUID string before touching the filesystem.

        Raises
        ------
        VaultValidationError
            If ``vault_id`` cannot be parsed as a UUID.
        """
        try:
            uuid.UUID(vault_id)
        except ValueError as exc:
            raise VaultValidationError(
                f"Invalid vault ID: '{vault_id}'",
                detail=f"'{vault_id}' is not a valid UUID. Provide a UUID4 vault identifier.",
            ) from exc
