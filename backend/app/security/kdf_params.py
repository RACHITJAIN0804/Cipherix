"""
security/kdf_params.py
----------------------
Data structure and serialisation helpers for Argon2id KDF parameters.

:class:`KdfParams` records the exact Argon2id configuration used when a
Master Key was derived.  It is stored inside ``password_meta.json`` in
every vault root so that future unlock operations can reproduce the *same*
derivation from the user's password.

Design
------
* A ``@dataclass`` keeps the schema explicit and diffable.
* Factory and serialisation live on the class, matching the pattern
  established by :class:`~app.security.models.KeyMetadata` and
  :class:`~app.vault.security.SecurityMetadata`.
* No cryptographic operations are performed here — this module is a
  pure data-modelling layer.
* All algorithm values are stored as plain strings so future readers
  can act on them without parsing numeric codes.

Why store KDF parameters?
    Argon2id's security properties depend on its cost parameters
    (``time_cost``, ``memory_cost``, ``parallelism``).  If these change
    between versions — e.g. a higher ``memory_cost`` in a security upgrade
    — the stored parameters tell the unlock path exactly how the original
    derivation was performed, enabling smooth migration without breaking
    existing vaults.
"""

from dataclasses import asdict, dataclass, field
from typing import Any


# References:
#   https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
#   https://datatracker.ietf.org/doc/html/rfc9106  (Argon2 RFC)
#
# OWASP minimum: time_cost=1, memory_cost=47104 (46 MiB), parallelism=1
# We use the OWASP recommended profile 2:
#   time_cost=3, memory_cost=65536 (64 MiB), parallelism=4, hash_len=32
_KDF_ALGORITHM: str = "argon2id"
_KDF_VERSION: int = 19  # Argon2 version 1.3 → integer 19 per RFC 9106
_DEFAULT_TIME_COST: int = 3
_DEFAULT_MEMORY_COST: int = 65536
_DEFAULT_PARALLELISM: int = 4
_DEFAULT_HASH_LEN: int = 32

# Salt length in bytes. 16 bytes (128 bits) is the minimum; we use 32 for margin.
SALT_BYTES: int = 32



@dataclass
class KdfParams:
    """
    Argon2id key-derivation parameters stored in ``password_meta.json``.

    Every field is stored verbatim so that a future unlock operation can
    reproduce the *exact* same derivation without guessing or hard-coding
    any parameter.

    Attributes
    ----------
    algorithm:
        KDF algorithm identifier.  Always ``"argon2id"`` for this
        implementation.  Stored as a string so callers can branch on it
        without knowing numeric type codes.
    version:
        Argon2 protocol version number.  ``19`` corresponds to Argon2
        version 1.3 (the current recommended version as per RFC 9106).
    time_cost:
        Number of iterations (passes over memory).  Higher values
        increase computation time linearly.  OWASP recommends at least 1;
        we default to 3.
    memory_cost:
        Memory usage in kibibytes.  Higher values increase the memory
        required per derivation, making parallel brute-force more
        expensive.  OWASP recommends 46 MiB minimum; we default to 64 MiB.

        Per RFC 9106, ``memory_cost`` must be at least ``8 * parallelism``.
        The Argon2 C library rounds up automatically, but values below this
        threshold should be considered misconfigured and will be rejected by
        :meth:`~app.security.password_manager.PasswordManager._validate_params`.
    parallelism:
        Number of parallel threads.  Should be set to the number of
        available CPU cores for maximum security; defaults to 4.
    hash_len:
        Length of the derived key in bytes.  32 bytes = 256 bits, matching
        the AES-256 key length used in future encryption milestones.
    salt_encoding:
        Encoding used for the salt stored in ``password_meta.json``.
        Always ``"hex"``; stored explicitly so future readers never need to
        guess the encoding.
    """

    algorithm: str = field(default=_KDF_ALGORITHM)
    version: int = field(default=_KDF_VERSION)
    time_cost: int = field(default=_DEFAULT_TIME_COST)
    memory_cost: int = field(default=_DEFAULT_MEMORY_COST)
    parallelism: int = field(default=_DEFAULT_PARALLELISM)
    hash_len: int = field(default=_DEFAULT_HASH_LEN)
    salt_encoding: str = field(default="hex")

    @classmethod
    def default(cls) -> "KdfParams":
        """
        Return a :class:`KdfParams` instance with OWASP-recommended defaults.

        This is the canonical factory for vault initialisation.  All
        cost parameters use the OWASP Password Storage Cheat Sheet profile 2
        values, providing a strong baseline for password-based key derivation.

        Returns
        -------
        KdfParams
            A ready-to-use parameter set.
        """
        return cls()

    def to_dict(self) -> dict[str, Any]:
        """Return a plain dictionary representation of the parameters."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "KdfParams":
        """
        Construct a :class:`KdfParams` from a plain dictionary.

        Unknown keys in ``data`` are silently ignored rather than raising
        ``TypeError``.  This provides forward compatibility: a
        ``password_meta.json`` written by a *newer* version of Cipherix
        that added extra KDF fields can still be read by this version
        without crashing.

        Parameters
        ----------
        data:
            Dictionary as returned by ``json.loads`` on a stored
            ``password_meta.json``.

        Returns
        -------
        KdfParams

        Raises
        ------
        TypeError
            If a known field has the wrong type (e.g. string instead
            of integer for ``time_cost``).
        KeyError
            If a required field is absent.
        """
        import dataclasses

        known: set[str] = {f.name for f in dataclasses.fields(cls)}
        filtered: dict[str, Any] = {k: v for k, v in data.items() if k in known}
        return cls(**filtered)
