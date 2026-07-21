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
    Raised when the incoming vault creation request fails business-rule
    validation *before* any filesystem work is attempted.

    Examples
    --------
    * Name is blank after stripping whitespace.
    * Name exceeds the allowed character limit.
    """
