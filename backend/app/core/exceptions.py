"""
exceptions.py
-------------
Custom exception hierarchy for Cipherix.

Raising typed exceptions instead of bare ``Exception`` gives every
layer of the stack a clear contract:

* API routes can catch ``CipherixError`` and map it to an HTTP status.
* Services can catch specific subclasses (e.g. ``VaultAlreadyExistsError``)
  and apply domain-specific recovery logic.
* The global exception handler in ``main.py`` remains the final safety net
  for anything that slips through.

All public exceptions in this module inherit from :class:`CipherixError`
so callers can handle them at whatever granularity they need.
"""


# ---------------------------------------------------------------------------
# Base
# ---------------------------------------------------------------------------


class CipherixError(Exception):
    """
    Root exception for all Cipherix domain errors.

    Carry an optional ``detail`` string so that API error responses
    can surface a safe, human-readable message without exposing
    internal implementation details.
    """

    def __init__(self, message: str, detail: str | None = None) -> None:
        super().__init__(message)
        self.message: str = message
        self.detail: str = detail or message


# ---------------------------------------------------------------------------
# Vault errors
# ---------------------------------------------------------------------------


class VaultError(CipherixError):
    """Base class for all vault-related errors."""


class VaultCreationError(VaultError):
    """
    Raised when the filesystem scaffolding for a new vault cannot be
    completed (e.g. permission denied, disk full, unexpected OS error).
    """


class VaultAlreadyExistsError(VaultError):
    """
    Raised when a vault directory already exists at the target path.

    This should not happen under normal operation because vault IDs are
    UUID4s, but it is a meaningful guard against external filesystem
    interference or UUID collisions (astronomically unlikely, but worth
    naming explicitly).
    """


class VaultValidationError(VaultError):
    """
    Raised when a request fails business-rule validation before any
    filesystem work is attempted.

    Examples
    --------
    * Vault name is blank after stripping whitespace.
    * Vault name exceeds the allowed character limit.
    * ``vault_id`` is not a well-formed UUID string.
    """


class VaultManifestError(VaultError):
    """
    Raised when a ``manifest.json`` is found on disk but cannot be read
    or parsed (missing, malformed JSON, missing required fields, etc.).

    Callers that are iterating over multiple vaults should catch this,
    log it, and *skip* the offending vault rather than aborting the
    entire listing operation.  This preserves a best-effort read
    guarantee: one corrupt vault must never hide all other valid vaults.
    """


class VaultNotFoundError(VaultError):
    """
    Raised when a requested vault directory does not exist on disk.

    This is the canonical "404" signal in the domain layer.  Routes
    should catch it and return ``HTTP 404 Not Found`` to the client.
    """


class VaultDeletionError(VaultError):
    """
    Raised when the filesystem cannot remove a vault directory tree
    (e.g. permission denied, directory in use on Windows, I/O error).

    This represents a server-side failure — the vault existed and the
    request was valid, but the OS prevented removal.  Routes should
    map this to ``HTTP 500 Internal Server Error``.
    """
