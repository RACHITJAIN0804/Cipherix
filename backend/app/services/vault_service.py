
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
from app.services.vector_store import VectorStore
from app.vault.manifest import VaultManifest
from app.vault.vault_manager import VaultManager

logger = get_logger(__name__)


_STATUS_LOCKED: str = "locked"
_STATUS_UNLOCKED: str = "unlocked"


class VaultService:

    def __init__(self, manager: VaultManager) -> None:
        self._manager: VaultManager = manager

    def create_vault(
        self,
        request: CreateVaultRequest,
        user_id: str | None = None,
        db: Session | None = None,
    ) -> VaultResponse:
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
        self._validate_vault_id(vault_id)

        logger.info("Initiating vault deletion | vault_id=%s", vault_id)

        try:
            self._manager.delete_vault(vault_id)
        except VaultError:
            logger.warning("Vault deletion did not complete | vault_id=%s", vault_id)
            raise

        try:
            vector_store = VectorStore()
            vector_store.delete_vault_vectors(vault_id)
        except Exception as v_exc:
            logger.warning(
                "Failed to delete vault vectors during vault deletion | vault_id=%s | error=%s",
                vault_id,
                v_exc,
            )


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
        return self._transition_vault_state(
            vault_id,
            target_status=_STATUS_LOCKED,
            current_label="locked",
            db=db,
        )

    def unlock_vault(
        self, vault_id: str, db: Session | None = None
    ) -> VaultStateResponse:
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
        if not request.name or not request.name.strip():
            raise VaultValidationError(
                "Vault name must not be empty.",
                detail="Provide a non-empty name between 3 and 50 characters.",
            )

    def _validate_vault_id(self, vault_id: str) -> None:
        try:
            uuid.UUID(vault_id)
        except ValueError as exc:
            raise VaultValidationError(
                f"Invalid vault ID: '{vault_id}'",
                detail=f"'{vault_id}' is not a valid UUID. Provide a UUID4 vault identifier.",
            ) from exc
