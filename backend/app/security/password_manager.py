
import json
import secrets
from pathlib import Path
from typing import Any

from argon2.low_level import Type, hash_secret_raw

from app.core.exceptions import (
    InvalidKdfParamsError,
    InvalidPasswordError,
    MissingSaltError,
)
from app.core.logger import get_logger
from app.security.kdf_params import SALT_BYTES, KdfParams

logger = get_logger(__name__)

_PASSWORD_META_FILENAME: str = "password_meta.json"


_SCHEMA_VERSION: str = "1"


class PasswordManager:

    def __init__(
        self,
        vault_root: Path,
        params: KdfParams | None = None,
    ) -> None:
        self._vault_root: Path = vault_root
        self._meta_path: Path = vault_root / _PASSWORD_META_FILENAME
        self._params: KdfParams = params if params is not None else KdfParams.default()

    def generate_salt(self) -> str:
        salt_hex: str = secrets.token_hex(SALT_BYTES)
        logger.debug(
            "Salt generated for vault at '%s' (bytes=%d, encoding=hex)",
            self._vault_root,
            SALT_BYTES,
        )
        return salt_hex

    def derive_master_key(self, password: str, salt_hex: str) -> bytes:
        if not isinstance(password, str) or not password.strip():
            raise InvalidPasswordError(
                "Password must not be empty.",
                detail=(
                    "A non-empty password is required for Master Key "
                    "derivation.  An empty or whitespace-only password "
                    "produces a zero-entropy secret and is rejected."
                ),
            )

        self._validate_params(self._params)
        salt_bytes: bytes = self._decode_salt(salt_hex)

        logger.debug(
            "Deriving Master Key (algorithm=%s, version=%d, time_cost=%d, "
            "memory_cost=%d, parallelism=%d, hash_len=%d)",
            self._params.algorithm,
            self._params.version,
            self._params.time_cost,
            self._params.memory_cost,
            self._params.parallelism,
            self._params.hash_len,
        )

        master_key: bytes = hash_secret_raw(
            secret=password.encode("utf-8"),
            salt=salt_bytes,
            time_cost=self._params.time_cost,
            memory_cost=self._params.memory_cost,
            parallelism=self._params.parallelism,
            hash_len=self._params.hash_len,
            type=Type.ID,
            version=self._params.version,
        )

        logger.debug(
            "Master Key derived successfully (key_bytes=%d)",
            len(master_key),
        )

        return master_key

    def verify_password(
        self,
        password: str,
        salt_hex: str,
        expected_key: bytes,
    ) -> bool:
        derived: bytes = self.derive_master_key(password, salt_hex)
        match: bool = secrets.compare_digest(derived, expected_key)


        logger.info(
            "Password verification completed (match=%s)",
            match,
        )

        return match

    def write_metadata(self, vault_id: str, salt_hex: str) -> None:
        if not salt_hex or not salt_hex.strip():
            raise MissingSaltError(
                f"Cannot write password_meta.json for vault '{vault_id}': salt is empty.",
                detail=(
                    "A non-empty salt is required before writing "
                    "password_meta.json.  Call generate_salt() first."
                ),
            )


        try:
            bytes.fromhex(salt_hex)
        except ValueError as exc:
            raise MissingSaltError(
                f"Cannot write password_meta.json for vault '{vault_id}': "
                f"salt is not valid hexadecimal: {exc}",
                detail=(
                    "The salt must be a valid hex string (as produced by "
                    "generate_salt()).  A non-hex salt cannot be stored "
                    "because it would make the vault permanently unreadable."
                ),
            ) from exc

        payload: dict[str, Any] = {
            "kdf": self._params.to_dict(),
            "salt": salt_hex,
            "schema_version": _SCHEMA_VERSION,
        }

        logger.debug(
            "Writing password_meta.json for vault '%s' at %s",
            vault_id,
            self._meta_path,
        )

        try:
            self._meta_path.write_text(
                json.dumps(payload, indent=4),
                encoding="utf-8",
            )
        except OSError as exc:
            raise InvalidKdfParamsError(
                f"Failed to write password_meta.json for vault '{vault_id}': {exc}",
                detail=(
                    f"OS error while writing password_meta.json for vault "
                    f"'{vault_id}': {exc.strerror}. "
                    "Check filesystem permissions."
                ),
            ) from exc

        logger.info(
            "password_meta.json created for vault '%s' "
            "(algorithm=%s, time_cost=%d, memory_cost=%d, "
            "parallelism=%d, hash_len=%d)",
            vault_id,
            self._params.algorithm,
            self._params.time_cost,
            self._params.memory_cost,
            self._params.parallelism,
            self._params.hash_len,
        )

    def read_metadata(self, vault_id: str) -> tuple[str, KdfParams]:
        if not self._meta_path.is_file():
            logger.warning(
                "Read failed: password_meta.json missing for vault '%s' at %s",
                vault_id,
                self._meta_path,
            )
            raise MissingSaltError(
                f"password_meta.json not found for vault '{vault_id}'.",
                detail=(
                    f"Vault '{vault_id}' is missing password_meta.json. "
                    "The vault may have been created before password-based "
                    "key derivation was introduced, or the file may have "
                    "been deleted."
                ),
            )

        try:
            raw: dict[str, Any] = json.loads(
                self._meta_path.read_text(encoding="utf-8")
            )
        except (OSError, json.JSONDecodeError) as exc:
            raise InvalidKdfParamsError(
                f"Cannot read password_meta.json for vault '{vault_id}': {exc}",
                detail=(
                    f"Vault '{vault_id}' has a malformed or unreadable "
                    f"password_meta.json: {exc}"
                ),
            ) from exc

        try:
            salt_hex: str = raw["salt"]
            kdf_data: dict[str, Any] = raw["kdf"]
            kdf_params: KdfParams = KdfParams.from_dict(kdf_data)
        except (KeyError, TypeError) as exc:
            raise InvalidKdfParamsError(
                f"password_meta.json for vault '{vault_id}' is missing "
                f"required fields: {exc}",
                detail=(
                    f"The file password_meta.json for vault '{vault_id}' "
                    f"is missing or has malformed required fields: {exc}. "
                    "The file may be corrupt."
                ),
            ) from exc


        try:
            self._decode_salt(salt_hex)
        except MissingSaltError as exc:
            logger.warning(
                "password_meta.json for vault '%s' has an invalid or missing "
                "salt: %s",
                vault_id,
                exc,
            )
            raise
        self._validate_params(kdf_params)

        logger.debug(
            "password_meta.json read for vault '%s' "
            "(algorithm=%s, time_cost=%d, memory_cost=%d)",
            vault_id,
            kdf_params.algorithm,
            kdf_params.time_cost,
            kdf_params.memory_cost,
        )

        return salt_hex, kdf_params

    def validate_metadata(self, vault_id: str) -> None:
        logger.debug(
            "Validating password_meta.json for vault '%s'", vault_id
        )


        self.read_metadata(vault_id)
        logger.debug(
            "password_meta.json validation passed for vault '%s'", vault_id
        )

    def _validate_params(self, params: KdfParams) -> None:
        invalid: list[str] = []

        if not isinstance(params.time_cost, int) or params.time_cost < 1:
            invalid.append(f"time_cost={params.time_cost!r} (must be >= 1)")
        if not isinstance(params.memory_cost, int) or params.memory_cost < 8:
            invalid.append(f"memory_cost={params.memory_cost!r} (must be >= 8 KiB)")
        if not isinstance(params.parallelism, int) or params.parallelism < 1:
            invalid.append(f"parallelism={params.parallelism!r} (must be >= 1)")
        if not isinstance(params.hash_len, int) or params.hash_len < 4:
            invalid.append(f"hash_len={params.hash_len!r} (must be >= 4 bytes)")

        if invalid:
            msg = "Invalid Argon2id parameters: " + "; ".join(invalid)
            logger.warning("KDF parameter validation failed: %s", msg)
            raise InvalidKdfParamsError(
                msg,
                detail=(
                    "The Argon2id KDF parameters stored in password_meta.json "
                    "are invalid and cannot be used for key derivation.  "
                    "Details: " + "; ".join(invalid)
                ),
            )

    def _decode_salt(self, salt_hex: str) -> bytes:
        if not isinstance(salt_hex, str) or not salt_hex.strip():
            raise MissingSaltError(
                "Salt is missing or empty.",
                detail=(
                    "A non-empty hex-encoded salt is required for Master Key "
                    "derivation.  The salt must be present in password_meta.json."
                ),
            )

        try:
            return bytes.fromhex(salt_hex)
        except ValueError as exc:
            raise MissingSaltError(
                f"Salt is not valid hexadecimal: {exc}",
                detail=(
                    "The salt stored in password_meta.json is not a valid "
                    f"hex string: {exc}.  The file may be corrupt."
                ),
            ) from exc
