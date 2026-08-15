"""
security/models.py
------------------
Data structure and serialisation helpers for ``key.json``.

``key.json`` lives inside every vault root and records the metadata
needed to reconstruct, validate, and eventually rotate the Vault Key.
It stores **no plaintext key material** — only the administrative
envelope that describes the key.

Architecture
------------
Two logical keys govern every vault:

Master Key
    Derived from the user's password using Argon2id (future milestone).
    The Master Key is **never** stored anywhere on disk — it exists in
    memory only for the duration of a single unlock operation.  Once the
    session ends, it must be re-derived from the password.

Vault Key
    A 256-bit cryptographically random value generated once per vault at
    creation time.  The Vault Key will encrypt every document stored in
    the vault (AES-256-GCM, future milestone).  It is stored in
    ``key.json`` in a form that can later be *wrapped* (encrypted) with
    the Master Key; the placeholder ``"[PENDING_ENCRYPTION]"`` signals
    that wrapping has not yet been performed.

Why are they separate?
    *  **Key rotation without re-encryption of all documents**: to rotate
       the user's password, we only need to re-wrap the Vault Key with a
       new Master Key — the documents themselves do not move.
    *  **Multiple credentials**: future milestones can add a second
       credential (e.g. a recovery key) that wraps the *same* Vault Key,
       giving access without duplicating encrypted data.
    *  **Principle of least privilege**: the Master Key is ephemeral;
       only the wrapped Vault Key lives on disk.  An attacker who reads
       ``key.json`` without knowing the password cannot recover the Vault Key.

Why is the password never used directly?
    Passwords have low entropy and are predictable.  Using Argon2id to
    derive a Master Key stretches the password into a 256-bit key with
    memory-hardness (making GPU/ASIC attacks impractical) and adds a salt
    (preventing rainbow-table attacks).  The password itself is discarded
    immediately after derivation.

Design
------
* A ``@dataclass`` keeps the schema explicit and diffable.
* Factory, serialisation, and deserialisation live on the class.
* No filesystem paths are hard-coded — I/O goes through :class:`Path`
  arguments supplied by :class:`~app.security.key_manager.KeyManager`.
* No cryptographic key *generation* is performed here — that
  responsibility belongs to :class:`~app.security.key_manager.KeyManager`.
  This module generates only the ``key_id`` identifier (128-bit random
  hex, not sensitive key material).
* No encryption or key derivation is performed here.
"""

import json
import secrets
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


# Algorithm labels are recorded verbatim so that future readers of key.json
# can act on them without parsing free-form strings.
_DEFAULT_ALGORITHM: str = "AES-256-GCM"

# Initial schema version for key.json.  Bump this when the shape changes
# in a backward-incompatible way.
_DEFAULT_KEY_VERSION: str = "1"

# A vault key that has been generated but not yet wrapped by a Master Key.
# The string value is an intentionally unambiguous sentinel — it is not a
# hex value, a Base64 token, or any byte-string encoding.
# Retained for backward-compatibility detection and migration guards.
_PENDING_SENTINEL: str = "[PENDING_ENCRYPTION]"

# Lifecycle states for a key record.
_STATUS_ACTIVE: str = "active"



@dataclass
class KeyMetadata:
    """
    In-memory representation of a vault's ``key.json``.

    This record is created once during vault scaffolding.  Its fields
    become fully operational in future milestones when Master-Key wrapping
    and AES-256-GCM encryption are implemented.

    Using a ``@dataclass`` (rather than a plain dict) gives us:

    * Type safety and IDE auto-complete.
    * A clear schema that can be diffed in code review when fields change.
    * Trivial conversion to/from JSON via :func:`dataclasses.asdict`.

    Field ordering follows the Python dataclass rule: required fields
    (no default) precede optional fields (with default).  The required
    fields ``created_at`` and ``key_id`` are always generated at creation
    time and must always be present in a valid ``key.json``; an empty
    string for either would be a structural defect.

    Attributes
    ----------
    created_at:
        UTC creation timestamp in ISO-8601 format.  Set once at vault
        creation and never modified thereafter.  Required — no default.
    key_id:
        A unique identifier for this key generation, used to correlate
        ``key.json`` records across key-rotation events.  Generated as a
        random hex string (128 bits) so it is globally unique and contains
        no sensitive information.  Required — no default.
    key_version:
        Schema version for this record.  Start at ``"1"``; increment when
        the shape of ``key.json`` changes in a backward-incompatible way.
    algorithm:
        Symmetric cipher that will protect vault documents.  Fixed at
        ``"AES-256-GCM"`` for now; recorded here so future milestones can
        read the intent without hard-coding assumptions.
    status:
        Lifecycle state of the key record.  ``"active"`` means the key is
        the current generation Vault Key for this vault.  Future milestones
        may add ``"rotated"`` or ``"revoked"`` to support key rotation.
    encrypted_vault_key:
        The Vault Key, encrypted (wrapped) by the Master Key.  While
        Master-Key wrapping is not yet implemented, this field holds the
        sentinel string ``"[PENDING_ENCRYPTION]"`` — a deliberate,
    """

    created_at: str
    key_id: str

    key_version: str = field(default=_DEFAULT_KEY_VERSION)
    algorithm: str = field(default=_DEFAULT_ALGORITHM)
    status: str = field(default=_STATUS_ACTIVE)
    encrypted_vault_key: str = field(default=_PENDING_SENTINEL)
    # Base64-encoded 12-byte AES-GCM nonce stored alongside the
    # encrypted Vault Key.  Empty string signals the vault pre-dates
    # AES-256-GCM wrapping (migration required).
    nonce: str = field(default="")

    @classmethod
    def create(
        cls,
        encrypted_vault_key: str,
        nonce: str,
    ) -> "KeyMetadata":
        """
        Build a brand-new :class:`KeyMetadata` for a vault created *now*.
        """
        return cls(
            created_at=datetime.now(UTC).isoformat(),
            key_id=secrets.token_hex(16),
            key_version=_DEFAULT_KEY_VERSION,
            algorithm=_DEFAULT_ALGORITHM,
            status=_STATUS_ACTIVE,
            encrypted_vault_key=encrypted_vault_key,
            nonce=nonce,
        )

    def to_dict(self) -> dict[str, Any]:
        """Return a plain dictionary representation of the key metadata."""
        return asdict(self)

    def write(self, path: Path) -> None:
        """
        Serialise the key metadata to ``path`` as pretty-printed JSON.

        Parameters
        ----------
        path:
            Full file path (including filename) to write to.
            The parent directory must already exist.

        Raises
        ------
        OSError
            Propagated from :func:`pathlib.Path.write_text` on any I/O
            error (permission denied, disk full, etc.).
        """
        path.write_text(
            json.dumps(self.to_dict(), indent=4),
            encoding="utf-8",
        )

    @classmethod
    def read(cls, path: Path) -> "KeyMetadata":
        """
        Deserialise a ``key.json`` from disk into a :class:`KeyMetadata`.

        Unknown fields are silently ignored for forward compatibility:
        a ``key.json`` written by a newer version of Cipherix that added
        extra metadata fields can still be read by this version.

        Parameters
        ----------
        path:
            Full path to the ``key.json`` file.

        Returns
        -------
        KeyMetadata

        Raises
        ------
        FileNotFoundError
            If ``path`` does not exist.
        json.JSONDecodeError
            If the file content is not valid JSON.
        KeyError
            If a required field is missing from the JSON object.
        TypeError
            If a field value has an unexpected type.
        """
        import dataclasses

        data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
        known: set[str] = {f.name for f in dataclasses.fields(cls)}
        filtered: dict[str, Any] = {k: v for k, v in data.items() if k in known}
        return cls(**filtered)
