"""
vault/manifest.py
-----------------
Data structure and serialisation helpers for ``manifest.json``.

The manifest is the single source of truth for vault metadata stored
on disk.  Keeping it in its own module means:

* :class:`VaultManager` stays focused on *filesystem operations* and
  delegates manifest construction and I/O to this module.
* The manifest schema can be versioned and evolved without touching the
  manager or the service.
* Unit tests can construct :class:`VaultManifest` objects directly without
  touching the filesystem at all.
"""

import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class VaultManifest:
    """
    In-memory representation of a vault's ``manifest.json``.

    Using a ``@dataclass`` (rather than a plain dict) gives us:

    * Type safety and IDE auto-complete.
    * A clear schema that can be diffed in code review when fields change.
    * Trivial conversion to/from JSON via :func:`dataclasses.asdict`.

    Attributes
    ----------
    vault_id:
        UUID4 string that also serves as the folder name under ``vaults/``.
    name:
        Human-readable vault name provided by the user.
    created_at:
        UTC creation timestamp stored in ISO-8601 format.
    version:
        Manifest schema version.  Increment this when the shape of
        ``manifest.json`` changes in a backward-incompatible way.
    status:
        Lifecycle state of the vault.  Starts as ``"locked"`` and will
        be managed by future unlock/lock operations.
    """

    vault_id: str
    name: str
    created_at: str
    version: str = field(default="1.0")
    status: str = field(default="locked")

    # ------------------------------------------------------------------
    # Factory helpers
    # ------------------------------------------------------------------

    @classmethod
    def create(cls, vault_id: str, name: str) -> "VaultManifest":
        """
        Build a brand-new manifest for a vault that is being created *now*.

        The timestamp is captured inside this method so that the caller
        does not need to know about UTC or ISO-8601 formatting.

        Parameters
        ----------
        vault_id:
            The UUID4 that identifies the vault.
        name:
            The normalised (trimmed) vault name from the request.

        Returns
        -------
        VaultManifest
            A fresh manifest ready to be written to disk.
        """
        return cls(
            vault_id=vault_id,
            name=name,
            created_at=datetime.now(UTC).isoformat(),
        )

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        """Return a plain dictionary representation of the manifest."""
        return asdict(self)

    def write(self, path: Path) -> None:
        """
        Serialise the manifest to ``path`` as pretty-printed JSON.

        Parameters
        ----------
        path:
            The full file path (including filename) to write to.
            Parent directory must already exist.

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
    def read(cls, path: Path) -> "VaultManifest":
        """
        Deserialise a ``manifest.json`` from disk into a :class:`VaultManifest`.

        Parameters
        ----------
        path:
            Full path to the ``manifest.json`` file.

        Returns
        -------
        VaultManifest

        Raises
        ------
        FileNotFoundError
            If ``path`` does not exist.
        json.JSONDecodeError
            If the file content is not valid JSON.
        KeyError
            If a required field is missing from the JSON.
        """
        data: dict = json.loads(path.read_text(encoding="utf-8"))
        return cls(**data)
