"""
vault/security.py
-----------------
Data structure and serialisation helpers for ``security.json``.

``security.json`` lives alongside ``manifest.json`` in every vault root and
records the cryptographic algorithm, key-derivation scheme, and
initialisation state that will govern future AES-256-GCM encryption.

Design mirrors :mod:`vault.manifest` exactly:

* A ``@dataclass`` keeps the schema explicit and diffable.
* Factory, serialisation, and deserialisation live on the class itself.
* No filesystem paths are hard-coded -- all I/O goes through :class:`Path`
  arguments supplied by :class:`~app.vault.security_manager.SecurityMetadataManager`.
* No cryptographic operations are performed here.  This module is a
  pure data-modelling and JSON-serialisation layer.

This module is intentionally ignorant of FastAPI, HTTP, and business rules.
"""

import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Constants -- cryptographic parameters recorded for future use
# ---------------------------------------------------------------------------

_DEFAULT_ALGORITHM: str = "AES-256-GCM"
_DEFAULT_KEY_DERIVATION: str = "Argon2id"
_DEFAULT_VERSION: str = "1.0"
_DEFAULT_STATUS: str = "uninitialized"


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class SecurityMetadata:
    """
    In-memory representation of a vault's ``security.json``.

    This file is created once during vault scaffolding and records the
    *intended* cryptographic posture of the vault.  The fields become
    operational in future milestones when actual key derivation and
    encryption are implemented.

    Using a ``@dataclass`` (rather than a plain dict) gives us:

    * Type safety and IDE auto-complete.
    * A clear schema that can be diffed in code review when fields change.
    * Trivial conversion to/from JSON via :func:`dataclasses.asdict`.

    Attributes
    ----------
    algorithm:
        Symmetric encryption algorithm that will be used to protect vault
        documents.  Fixed at ``"AES-256-GCM"`` for now; stored here so
        that future milestones can read it without hard-coding assumptions.
    key_derivation:
        Password-based key-derivation function.  Fixed at ``"Argon2id"``,
        the memory-hard KDF recommended by the OWASP Password Storage
        Cheat Sheet.  Not yet invoked -- recorded for forward compatibility.
    version:
        Schema version of this file.  Increment when the shape of
        ``security.json`` changes in a backward-incompatible way.
    status:
        Cryptographic initialisation state.  ``"uninitialized"`` means no
        master key has been derived yet.  Future milestones will transition
        this to ``"initialized"`` once a vault key is securely established.
    created_at:
        UTC creation timestamp in ISO-8601 format.  Set once at vault
        creation; never updated thereafter.
    """

    algorithm: str = field(default=_DEFAULT_ALGORITHM)
    key_derivation: str = field(default=_DEFAULT_KEY_DERIVATION)
    version: str = field(default=_DEFAULT_VERSION)
    status: str = field(default=_DEFAULT_STATUS)
    created_at: str = field(default="")

    # ------------------------------------------------------------------
    # Factory helpers
    # ------------------------------------------------------------------

    @classmethod
    def create(cls) -> "SecurityMetadata":
        """
        Build a brand-new ``SecurityMetadata`` for a vault created *now*.

        The UTC timestamp is captured inside this method so that callers
        never need to know about timezone handling or ISO-8601 formatting.

        All algorithm/KDF choices are fixed defaults -- no parameters are
        accepted because no cryptographic decisions are made at this stage.

        Returns
        -------
        SecurityMetadata
            A fresh, ready-to-write instance with ``status="uninitialized"``.
        """
        return cls(created_at=datetime.now(UTC).isoformat())

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """Return a plain dictionary representation of the metadata."""
        return asdict(self)

    def write(self, path: Path) -> None:
        """
        Serialise the metadata to ``path`` as pretty-printed JSON.

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
    def read(cls, path: Path) -> "SecurityMetadata":
        """
        Deserialise a ``security.json`` from disk into a
        :class:`SecurityMetadata` instance.

        Parameters
        ----------
        path:
            Full path to the ``security.json`` file.

        Returns
        -------
        SecurityMetadata

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
        data: dict = json.loads(path.read_text(encoding="utf-8"))
        return cls(**data)
