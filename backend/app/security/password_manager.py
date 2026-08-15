"""
security/password_manager.py
----------------------------
Password-based Master Key derivation using Argon2id.

This module is the single authority for everything related to turning a
user's password into a cryptographic Master Key.  Its responsibilities are:

* **Generate salt** -- produce a cryptographically secure random salt,
  unique per vault, encoded as a hex string for safe storage.
* **Derive Master Key** -- run Argon2id over (password, salt, params) and
  return raw key bytes.  The key is **never** stored anywhere.
* **Verify password** -- re-derive the Master Key and confirm it matches an
  expected value, or verify a stored Argon2id hash (used for password check
  without exposing the Master Key).
* **Store/read/validate metadata** -- persist only the salt, algorithm name,
  and KDF parameters to ``password_meta.json``; never the password or key.

Key hierarchy recap
-------------------
::

    User Password  +  Salt  (both supplied at unlock time)
          │
          │  Argon2id (this module)
          ▼
    Master Key  ─── ephemeral, 256-bit, NEVER stored ─────────────────────►
          │
          │  AES-256-GCM key-wrap (future milestone)
          ▼
    Vault Key  ─── stored encrypted in key.json ────► encrypts documents

Why Argon2id?
    Argon2id is the winner of the Password Hashing Competition (2015) and
    the algorithm recommended by OWASP, NIST SP 800-63B, and RFC 9106 for
    password-based key derivation.  Its three configurable cost parameters
    allow tuning to available hardware while remaining resistant to both
    time–memory trade-off (TMTO) attacks (via memory-hardness) and
    side-channel timing attacks (via the hybrid data/independent access
    pattern of the "id" variant).

Password hashing vs. key derivation
    * **Password hashing** (e.g. ``argon2.PasswordHasher``) produces a
      self-contained string that includes the salt, parameters, and hash.
      It is designed for *verification*: given a candidate password, check
      whether it matches the stored hash.  The output is not suitable as a
      cryptographic key because it is variable-length, Base64-encoded, and
      includes metadata bytes.
    * **Key derivation** (``argon2.low_level.hash_secret_raw``) produces a
      fixed-length byte string of exactly the requested ``hash_len`` bytes.
      This is the correct primitive for producing AES-256 keys: 32 bytes of
      high-entropy output derived deterministically from (password, salt).

    Cipherix uses ``hash_secret_raw`` here because the goal is to produce a
    256-bit symmetric key, not to store a verifiable password record.

Why the Master Key is never stored
    Storing the Master Key defeats the purpose of key derivation:

    1. **An attacker who reads disk** recovers the Master Key directly,
       bypassing the Argon2id cost entirely.
    2. **Password rotation** would require re-encrypting the Master Key
       rather than simply re-deriving it from the new password.
    3. **Separation of secrets**: the only secret on disk is the wrapped
       Vault Key (future milestone).  An attacker needs *both* the stored
       ciphertext *and* the user's live password to recover any plaintext.

    The Master Key is re-derived on every unlock operation and discarded
    as soon as it has been used to unwrap the Vault Key.

Filesystem layout
    ``password_meta.json`` is written to the vault root during vault
    initialisation (alongside ``manifest.json``, ``security.json``, and
    ``key.json``).  It contains:

    .. code-block:: json

        {
            "kdf": {
                "algorithm": "argon2id",
                "version": 19,
                "time_cost": 3,
                "memory_cost": 65536,
                "parallelism": 4,
                "hash_len": 32,
                "salt_encoding": "hex"
            },
            "salt": "<64-character hex string>",
            "schema_version": "1"
        }

Design decisions
----------------
* **pathlib throughout** -- all path composition uses :class:`~pathlib.Path`.
* **Typed exceptions** -- every failure surface raises a typed domain
  exception from :mod:`app.core.exceptions`.
* **No passwords or keys on disk** -- only the salt and KDF parameters are
  persisted.
* **Hex-encoded salt** -- hex is human-readable in an editor, unambiguous,
  and not confused with Base64 padding or URL-encoding artefacts.
* **Extensible parameters** -- :class:`~app.security.kdf_params.KdfParams`
  is a separate dataclass so that parameter sets can evolve independently of
  the manager.

Extensibility notes
-------------------
* **Password change**: call :meth:`PasswordManager.generate_salt` to get a
  new salt, re-derive the Master Key, use it to re-wrap the Vault Key, then
  call :meth:`PasswordManager.write_metadata` with the new salt.
* **KDF upgrade**: add a ``migration_strategy`` field to
  :class:`~app.security.kdf_params.KdfParams`; the unlock path reads the
  stored parameters and uses them, then re-derives with the new parameters
  and re-wraps the Vault Key.
* **Multiple credentials**: each credential (e.g. recovery key) has its own
  ``password_meta.json``-equivalent, all wrapping the same Vault Key.
"""

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

# Top-level schema version for password_meta.json.
# Increment when the shape of the file changes in a backward-incompatible way.
_SCHEMA_VERSION: str = "1"


class PasswordManager:
    """
    Manages Argon2id-based Master Key derivation for a single vault.

    This class is the single authority for:

    * Generating the per-vault salt used in key derivation.
    * Deriving the Master Key from (password, salt, KDF params).
    * Verifying that a candidate password produces the expected Master Key.
    * Persisting and reading back ``password_meta.json``.
    * Validating the structural integrity of stored metadata.

    The Master Key produced by :meth:`derive_master_key` is **never**
    stored by this class.  Callers are responsible for using it immediately
    (e.g. to unwrap the Vault Key) and discarding it.

    Parameters
    ----------
    vault_root:
        Absolute path to the vault's root directory
        (e.g. ``vaults/<vault_uuid>/``).  ``password_meta.json`` will be
        read from and written to this directory.
    params:
        Argon2id cost parameters to use for key derivation.  Defaults to
        :meth:`~app.security.kdf_params.KdfParams.default` (OWASP profile 2).
        Supply a custom instance only for testing or future parameter upgrades.
    """

    def __init__(
        self,
        vault_root: Path,
        params: KdfParams | None = None,
    ) -> None:
        self._vault_root: Path = vault_root
        self._meta_path: Path = vault_root / _PASSWORD_META_FILENAME
        self._params: KdfParams = params if params is not None else KdfParams.default()

    def generate_salt(self) -> str:
        """
        Generate a cryptographically secure random salt for this vault.

        Uses :func:`secrets.token_hex` (OS CSPRNG) to produce
        :data:`~app.security.kdf_params.SALT_BYTES` bytes of random data,
        returned as a lowercase hex string.

        The salt must be:

        * **Unique per vault** — using the same salt across vaults allows
          an attacker to compare derived keys, revealing whether two vaults
          share the same password.
        * **Stored alongside the KDF parameters** — Argon2id is deterministic:
          the same (password, salt, params) always produces the same key.
          The salt must be stored so the unlock path can reproduce the derivation.

        Returns
        -------
        str
            Hex-encoded random salt
            (``2 * SALT_BYTES`` characters, all lowercase).
        """
        salt_hex: str = secrets.token_hex(SALT_BYTES)
        logger.debug(
            "Salt generated for vault at '%s' (bytes=%d, encoding=hex)",
            self._vault_root,
            SALT_BYTES,
        )
        return salt_hex

    def derive_master_key(self, password: str, salt_hex: str) -> bytes:
        """
        Derive a 256-bit Master Key from a password and salt using Argon2id.

        Uses ``argon2.low_level.hash_secret_raw`` with ``Type.ID``
        (Argon2id) to produce a fixed-length byte string of exactly
        ``params.hash_len`` bytes.

        The derived key is returned to the caller and **never stored** by
        this method.  The caller must use it immediately and discard it
        once it is no longer needed.

        Why ``hash_secret_raw`` and not ``PasswordHasher``?
            :class:`argon2.PasswordHasher` produces a verifiable hash string
            (containing the salt, parameters, and hash) suited for password
            *authentication*.  For key *derivation*, we need exactly
            ``hash_len`` raw bytes — no metadata, no encoding — matching the
            AES-256 key length expected by the encryption layer.

        Parameters
        ----------
        password:
            The user's plaintext password.  Encoded to UTF-8 bytes
            internally; the caller's string is not retained beyond this
            call.  Must be a non-empty, non-whitespace-only string —
            passing an empty password would produce a zero-entropy secret
            that is equivalent to having no password at all.
        salt_hex:
            Hex-encoded salt previously produced by :meth:`generate_salt`
            or read from ``password_meta.json``.

        Returns
        -------
        bytes
            ``params.hash_len`` bytes of derived key material (32 bytes /
            256 bits by default).

        Raises
        ------
        InvalidPasswordError
            If ``password`` is empty or contains only whitespace.
        InvalidKdfParamsError
            If the stored KDF parameters are structurally invalid (e.g.
            ``time_cost`` is zero or negative).
        MissingSaltError
            If ``salt_hex`` is empty or not a valid hex string.
        """
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
        """
        Verify that a candidate password produces an expected Master Key.

        Re-derives the Master Key from the given password and salt, then
        compares the result to ``expected_key`` using a constant-time
        equality check (:func:`secrets.compare_digest`) to prevent timing
        attacks.

        This method is designed for the vault *unlock* flow:

        1. Caller supplies the candidate password.
        2. Manager re-derives the Master Key.
        3. Manager compares the derived key to the expected key (which
           the caller obtained by, e.g., decrypting a test block).

        Note that this does **not** verify against a stored password hash —
        it verifies against a known-good derived key value.  For use cases
        where no expected key is available, the caller should instead
        attempt to use the derived key for decryption and catch the
        resulting authentication error.

        Parameters
        ----------
        password:
            Candidate password to test.  Must be non-empty; emptiness is
            rejected by :meth:`derive_master_key` before any Argon2id work
            is performed.
        salt_hex:
            Hex-encoded salt from ``password_meta.json``.
        expected_key:
            The Master Key that the correct password should produce.

        Returns
        -------
        bool
            ``True`` if the derived key matches ``expected_key``;
            ``False`` otherwise.

        Raises
        ------
        InvalidPasswordError
            If ``password`` is empty or contains only whitespace.
        InvalidKdfParamsError
            If KDF parameters are structurally invalid.
        MissingSaltError
            If ``salt_hex`` is empty or malformed.
        """
        derived: bytes = self.derive_master_key(password, salt_hex)
        match: bool = secrets.compare_digest(derived, expected_key)

        # Log at INFO: authentication outcomes are security-relevant audit events
        # that must appear in production logs.  We never log the password itself.
        logger.info(
            "Password verification completed (match=%s)",
            match,
        )

        return match

    def write_metadata(self, vault_id: str, salt_hex: str) -> None:
        """
        Persist salt and KDF parameters to ``password_meta.json``.

        Writes the following structure to disk:

        .. code-block:: json

            {
                "kdf": { "algorithm": "argon2id", "version": 19, ... },
                "salt": "<hex>",
                "schema_version": "1"
            }

        **What is stored:**

        * The salt (hex-encoded random bytes).
        * The exact KDF parameters used for derivation.
        * The schema version of this file.

        **What is NOT stored:**

        * The password (plaintext or hashed).
        * The Master Key (derived or otherwise).
        * The Vault Key (managed by :class:`~app.security.key_manager.KeyManager`).

        Parameters
        ----------
        vault_id:
            UUID4 string used in log and error messages.
        salt_hex:
            Hex-encoded salt produced by :meth:`generate_salt`.

        Raises
        ------
        MissingSaltError
            If ``salt_hex`` is empty.
        OSError
            If the file cannot be written (re-raised as
            :class:`~app.core.exceptions.InvalidKdfParamsError` with context).
        """
        if not salt_hex or not salt_hex.strip():
            raise MissingSaltError(
                f"Cannot write password_meta.json for vault '{vault_id}': salt is empty.",
                detail=(
                    "A non-empty salt is required before writing "
                    "password_meta.json.  Call generate_salt() first."
                ),
            )

        # Validate that the salt is well-formed hex before persisting it.
        # A non-hex value stored here would only be caught later at read time,
        # making the vault permanently unreadable.
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
        """
        Read and return the stored salt and KDF parameters.

        Parses ``password_meta.json`` and returns the salt and parameters
        needed to reproduce the Master Key derivation at unlock time.

        Parameters
        ----------
        vault_id:
            UUID4 string used in log and error messages.

        Returns
        -------
        tuple[str, KdfParams]
            ``(salt_hex, kdf_params)`` — the hex-encoded salt and the KDF
            parameter set used during vault initialisation.

        Raises
        ------
        MissingSaltError
            If ``password_meta.json`` does not exist.
        InvalidKdfParamsError
            If the file exists but is malformed, missing required fields,
            or contains invalid parameter values.
        """
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

        # Route through _decode_salt — the single canonical validation point.
        # On failure, add vault context to the warning log before re-raising.
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
        """
        Assert that ``password_meta.json`` exists, is parseable, and has
        valid KDF parameters.

        Performs a complete read-and-validate cycle.  Intended for use by
        future milestones that need to confirm a vault is cryptographically
        ready before performing sensitive operations.

        Parameters
        ----------
        vault_id:
            UUID4 string used in log and error messages.

        Raises
        ------
        MissingSaltError
            If ``password_meta.json`` does not exist.
        InvalidKdfParamsError
            If the file exists but is malformed or has invalid parameters.
        """
        logger.debug(
            "Validating password_meta.json for vault '%s'", vault_id
        )
        # read_metadata performs the full parse + validate cycle;
        # if it returns without raising, validation has passed.
        self.read_metadata(vault_id)
        logger.debug(
            "password_meta.json validation passed for vault '%s'", vault_id
        )

    def _validate_params(self, params: KdfParams) -> None:
        """
        Assert that KDF parameters are structurally valid.

        Raises :class:`~app.core.exceptions.InvalidKdfParamsError` if any
        cost parameter is zero or negative, which would make Argon2id
        trivially weak or outright fail at the C layer.

        Per RFC 9106, ``memory_cost`` must be at least ``8 * parallelism``.
        We enforce the simpler ``>= 8 KiB`` floor here (the minimum for any
        Argon2 instance regardless of parallelism) and rely on the C library
        to reject truly pathological combinations.

        Parameters
        ----------
        params:
            The :class:`~app.security.kdf_params.KdfParams` instance to check.

        Raises
        ------
        InvalidKdfParamsError
            If ``time_cost``, ``memory_cost``, ``parallelism``, or
            ``hash_len`` is not a positive integer meeting minimum thresholds.
        """
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
        """
        Decode a hex-encoded salt string into raw bytes.

        This is the single validation point for salts — both the
        derivation path (:meth:`derive_master_key`) and the read path
        (:meth:`read_metadata`) route through here, ensuring any invalid
        salt is caught and reported consistently regardless of the call site.

        Parameters
        ----------
        salt_hex:
            Hex-encoded salt (``2 * SALT_BYTES`` characters for the default
            32-byte salt).

        Returns
        -------
        bytes
            Raw salt bytes suitable for passing to ``hash_secret_raw``.

        Raises
        ------
        MissingSaltError
            If ``salt_hex`` is empty, ``None``, not a string, or contains
            characters that are not valid hexadecimal.
        """
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
