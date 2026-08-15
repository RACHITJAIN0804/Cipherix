"""
security/encryption.py
----------------------
AES-256-GCM Vault Key encryption and decryption.

:class:`EncryptionManager` is the single authority for all symmetric
encryption operations performed on key material inside Cipherix.  Its
only job in this milestone is to **wrap** (encrypt) and **unwrap**
(decrypt) the Vault Key using the ephemeral Master Key.

Key hierarchy reminder
----------------------
::

    User Password  +  Salt
          │
          │  Argon2id  (PasswordManager)
          ▼
    Master Key  ── ephemeral, 256-bit, NEVER stored ──► RAM only
          │
          │  AES-256-GCM  (this module)
          ▼
    Encrypted Vault Key  ── stored in key.json ──► ``encrypted_vault_key``
    Nonce                ── stored in key.json ──► ``nonce``

Why AES-256-GCM?
    AES-256-GCM is Authenticated Encryption with Associated Data (AEAD).
    "Authenticated" means the ciphertext includes a 128-bit authentication
    tag that is verified on decryption.  If even a single bit of the
    stored ciphertext or nonce is altered, decryption raises
    :class:`cryptography.exceptions.InvalidTag` before returning any bytes.
    This property is critical for key wrapping:

    * **Confidentiality**: without the Master Key, the Vault Key cannot be
      recovered (AES in any mode).
    * **Integrity**: without a valid authentication tag, the Vault Key cannot
      be *forged* or silently *corrupted*.  An attacker cannot flip bits in
      the stored ciphertext and produce a different, accepted plaintext.
    * **Authenticity**: the authentication tag ties the ciphertext to the
      specific key.  A ciphertext encrypted under a different Master Key
      (e.g. wrong password) will never produce a valid decryption.

    AES-GCM uses a 96-bit (12-byte) nonce.  The nonce does not need to be
    secret — it is stored alongside the ciphertext — but it must be unique
    for every (key, nonce) pair used.  We generate it from the OS CSPRNG so
    the probability of collision is negligible (birthday bound: 2^48 for
    random nonces under the same key, which will never be reached for key
    wrapping which happens once per vault).

Why a nonce per vault key, not a global counter?
    A counter requires persistent, crash-safe state — hard to guarantee in
    a filesystem-backed server.  A random nonce from a CSPRNG is simpler,
    stateless, and safe for our usage pattern (one nonce per vault key,
    vault keys are never re-encrypted with the same Master Key nonce unless
    the password changes, at which point a new nonce is generated anyway).

Why encrypt the Vault Key rather than documents directly?
    Direct password-based document encryption couples decryption to the
    password.  If the user changes their password, every document must be
    re-encrypted.  With a two-layer scheme:

    1. The Vault Key encrypts documents (future milestone).
    2. The Master Key wraps the Vault Key (this milestone).

    A password change only requires re-wrapping the single Vault Key —
    documents remain untouched.  Similarly, a recovery credential can wrap
    the same Vault Key without duplicating encrypted documents.

Why is ``None`` passed as the Associated Data (AAD)?
    AAD allows additional context to be authenticated without being
    encrypted (e.g. the vault ID could be AAD to prevent one vault's
    ciphertext from being swapped into another).  For this milestone we
    pass ``None`` because:

    * The nonce is unique per vault key, already preventing cross-vault
      replay without explicit AAD.
    * Adding the vault ID as AAD is a natural future hardening step that
      does not require a schema migration (AAD is not stored, it is
      supplied by the caller at decryption time).

    This is documented as an extensibility note so future milestones can
    add it without surprise.

Nonce length
    96 bits (12 bytes) is the recommended nonce length for AES-GCM per
    NIST SP 800-38D.  Using the recommended length avoids the complexity
    of GHASH-based nonce derivation required for other lengths and matches
    the default assumed by all major AES-GCM implementations.

Storage format
    The encrypted Vault Key and nonce are stored as Base64-encoded strings
    in ``key.json``.  Base64 is chosen because:

    * JSON does not have a native binary type.
    * Base64 is the industry standard for binary-in-JSON (JWK, JWE, etc.).
    * Unlike hex, Base64 produces shorter strings for the same number of
      bytes (4/3 overhead vs. 2x for hex).

Design decisions
----------------
* **No filesystem I/O** — :class:`EncryptionManager` operates purely on
  byte strings.  All file operations live in :class:`KeyManager`.
* **Typed exceptions** — every failure raises a subclass of
  :class:`~app.core.exceptions.EncryptionError`.
* **``InvalidTag`` is always wrapped** — the raw
  :class:`~cryptography.exceptions.InvalidTag` exception from the
  cryptography library is never allowed to propagate to callers.  It is
  caught and re-raised as :class:`~app.core.exceptions.VaultKeyDecryptionError`
  with a safe, non-leaking error message.
* **NONCE_BYTES is a module-level constant** — consumers can read it
  without instantiating the class, enabling forward-compatible validation.

Extensibility notes
-------------------
* **Key rotation**: generate a new nonce, decrypt with the old Master Key,
  re-encrypt with the new Master Key.  No document changes required.
* **Multiple encryption versions**: add a ``version`` parameter to
  :meth:`encrypt_vault_key`; the caller stores it in ``key.json``;
  :meth:`decrypt_vault_key` branches on the version field.
* **Hardware-backed key storage** (HSM / TPM): replace the
  :meth:`encrypt_vault_key` and :meth:`decrypt_vault_key` bodies with calls
  to the HSM provider's key-wrapping API.  The interface does not change.
* **AAD hardening**: pass ``vault_id.encode()`` as the ``aad`` parameter to
  both ``AESGCM.encrypt`` and ``AESGCM.decrypt`` to bind the ciphertext to
  a specific vault.  Both sides must supply the same AAD value.
"""

import base64
import hashlib
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.core.exceptions import (
    InvalidNonceError,
    VaultKeyDecryptionError,
    VaultKeyEncryptionError,
)
from app.core.logger import get_logger

logger = get_logger(__name__)

# AES-GCM recommended nonce length per NIST SP 800-38D: 96 bits (12 bytes).
# This is a module-level constant so callers can validate nonces without
# instantiating EncryptionManager.
NONCE_BYTES: int = 12

# Expected key length for AES-256: 32 bytes.
_KEY_BYTES: int = 32

# AES-GCM authentication tag length: always 128 bits (16 bytes).
# Used in both _validate_ciphertext and validate_envelope.
_GCM_TAG_BYTES: int = 16

# Algorithm label recorded in key.json for future schema branching.
ALGORITHM_LABEL: str = "AES-256-GCM"


class EncryptionManager:
    """
    Provides AES-256-GCM encryption and decryption for Vault Key material.

    This class is **stateless** — it carries no key material and holds no
    internal state beyond the module-level constants.  It is safe to
    instantiate once and reuse across multiple encrypt/decrypt calls, or to
    instantiate inline for a single operation.

    No filesystem operations are performed here.  All I/O lives in
    :class:`~app.security.key_manager.KeyManager`.

    No key material (Master Key or Vault Key) is retained after each method
    returns.  The caller is responsible for discarding sensitive byte strings
    as soon as they are no longer needed.
    """

    def generate_nonce(self) -> bytes:
        """
        Generate a cryptographically secure random 96-bit nonce.

        Uses :func:`os.urandom` (OS CSPRNG) to produce exactly
        :data:`NONCE_BYTES` bytes.  The nonce does not need to be
        secret — it is stored alongside the ciphertext in ``key.json``
        — but it must be **unique** for every (key, nonce) pair.

        Nonce reuse under the same key completely breaks AES-GCM
        confidentiality and authenticity.  Generating a fresh random nonce
        from the OS CSPRNG for every encryption operation ensures uniqueness
        without requiring persistent counter state.

        Returns
        -------
        bytes
            :data:`NONCE_BYTES` (12) bytes of random data.
        """
        nonce: bytes = os.urandom(NONCE_BYTES)

        logger.debug(
            "Nonce generated (bytes=%d, source=os_urandom)",
            NONCE_BYTES,
        )

        return nonce

    def encrypt_vault_key(
        self,
        vault_key: bytes,
        master_key: bytes,
        nonce: bytes,
    ) -> bytes:
        """
        Encrypt a raw Vault Key with the Master Key using AES-256-GCM.

        Produces a ciphertext that includes the 128-bit GCM authentication
        tag appended to the end (the ``cryptography`` library handles this
        automatically).  The result must be stored alongside the nonce in
        ``key.json``; decryption requires both.

        **Nothing is stored by this method** — it returns raw bytes for the
        caller to encode and persist.

        Parameters
        ----------
        vault_key:
            Raw 32-byte (256-bit) Vault Key to encrypt.
        master_key:
            Raw 32-byte (256-bit) ephemeral Master Key derived by Argon2id.
            Must not be stored before or after this call.
        nonce:
            12-byte nonce produced by :meth:`generate_nonce`.  Must be
            fresh and unique — never reuse a nonce with the same Master Key.

        Returns
        -------
        bytes
            Encrypted Vault Key with appended 128-bit GCM authentication tag.
            Total length = ``len(vault_key) + 16`` bytes.

        Raises
        ------
        VaultKeyEncryptionError
            If ``vault_key`` or ``master_key`` is not 32 bytes, or ``nonce``
            is not 12 bytes, or if the underlying AES-GCM operation fails.
        """
        self._validate_key_bytes(master_key, "master_key")
        self._validate_key_bytes(vault_key, "vault_key")
        self._validate_nonce(nonce)

        logger.debug(
            "Encrypting Vault Key (algorithm=%s, nonce_bytes=%d, key_bytes=%d)",
            ALGORITHM_LABEL,
            NONCE_BYTES,
            _KEY_BYTES,
        )

        try:
            ciphertext: bytes = AESGCM(master_key).encrypt(
                nonce,
                vault_key,
                None,  # No additional authenticated data (AAD) at this milestone.
                       # Future hardening: pass vault_id.encode() as AAD to bind
                       # the ciphertext to its vault.
            )
        except ValueError as exc:
            # AESGCM.encrypt raises ValueError for invalid key length, which
            # our _validate_key_bytes guard should have already prevented.
            # Catching ValueError here means a programming error (bypassing
            # validation) surfaces as a typed exception rather than a raw
            # library error propagating to the route layer.
            logger.error(
                "AES-256-GCM encryption raised ValueError: %s", exc
            )
            raise VaultKeyEncryptionError(
                f"Vault Key encryption failed: {exc}",
                detail=(
                    "AES-256-GCM encryption could not complete.  "
                    "This is an internal server error.  The Vault Key "
                    "was not stored."
                ),
            ) from exc

        logger.info(
            "Vault Key encrypted successfully "
            "(algorithm=%s, ciphertext_bytes=%d)",
            ALGORITHM_LABEL,
            len(ciphertext),
        )

        return ciphertext

    def decrypt_vault_key(
        self,
        ciphertext: bytes,
        master_key: bytes,
        nonce: bytes,
    ) -> bytes:
        """
        Decrypt a wrapped Vault Key and verify its authentication tag.

        AES-GCM decryption is **authenticated**: if the ciphertext, nonce,
        or key is not exactly what was used during encryption, decryption
        raises :class:`~app.core.exceptions.VaultKeyDecryptionError` before
        returning any bytes.  This means:

        * A wrong password (which produces a wrong Master Key) is detected
          here, not by a length check or a sentinel comparison.
        * A tampered ``key.json`` (e.g. single bit flip) is detected here.
        * A file copy/paste attack (wrong nonce for the ciphertext) is
          detected here.

        Parameters
        ----------
        ciphertext:
            Encrypted Vault Key bytes (including the 128-bit appended GCM
            authentication tag) as returned by :meth:`encrypt_vault_key`.
        master_key:
            Raw 32-byte ephemeral Master Key.  Re-derived from the user's
            password by :class:`~app.security.password_manager.PasswordManager`
            at unlock time.
        nonce:
            Raw 12-byte nonce, as stored in ``key.json``.

        Returns
        -------
        bytes
            The raw 32-byte Vault Key plaintext.

        Raises
        ------
        VaultKeyDecryptionError
            If the GCM authentication tag does not match (wrong key, wrong
            nonce, or tampered ciphertext) or if the ciphertext is too short
            to contain the authentication tag.
        VaultKeyEncryptionError
            If ``master_key`` length is not 32 bytes or ``nonce`` length is
            not 12 bytes (structural validation, not cryptographic failure).
        """
        self._validate_key_bytes(master_key, "master_key")
        self._validate_nonce(nonce)
        self._validate_ciphertext(ciphertext)

        logger.debug(
            "Decrypting Vault Key (algorithm=%s, nonce_bytes=%d)",
            ALGORITHM_LABEL,
            NONCE_BYTES,
        )

        try:
            vault_key: bytes = AESGCM(master_key).decrypt(
                nonce,
                ciphertext,
                None,  # Must match the AAD used during encryption.
            )
        except InvalidTag:
            # Do NOT include any ciphertext bytes, nonce bytes, or key
            # bytes in the log or exception message.  Leaking them would
            # give an attacker information about the encrypted material.
            logger.warning(
                "Vault Key decryption failed: GCM authentication tag mismatch. "
                "Possible causes: wrong password, tampered key.json, or corrupt nonce."
            )
            raise VaultKeyDecryptionError(
                "Vault Key decryption failed: authentication tag mismatch.",
                detail=(
                    "The GCM authentication tag did not verify.  This usually means "
                    "the password is incorrect.  It may also indicate that key.json "
                    "has been tampered with or is corrupt."
                ),
            )
        except Exception as exc:
            logger.error(
                "Vault Key decryption raised an unexpected error: %s",
                type(exc).__name__,
            )
            raise VaultKeyDecryptionError(
                f"Vault Key decryption failed unexpectedly: {type(exc).__name__}",
                detail=(
                    "An unexpected error occurred during Vault Key decryption.  "
                    "This is an internal server error."
                ),
            ) from exc

        logger.info(
            "Vault Key decrypted and authenticated successfully "
            "(algorithm=%s, key_bytes=%d)",
            ALGORITHM_LABEL,
            len(vault_key),
        )

        return vault_key

    def encrypt_bytes(
        self,
        plaintext: bytes,
        vault_key: bytes,
        nonce: bytes,
    ) -> bytes:
        """
        Encrypt arbitrary plaintext bytes with a Vault Key using AES-256-GCM.

        Unlike :meth:`encrypt_vault_key`, this method does **not** validate
        the length of ``plaintext`` — it may be any non-negative number of
        bytes, making it suitable for encrypting documents of any size.

        Parameters
        ----------
        plaintext:
            Raw bytes to encrypt (e.g. the content of an uploaded file).
        vault_key:
            Raw 32-byte (256-bit) Vault Key.
        nonce:
            12-byte nonce produced by :meth:`generate_nonce`.  Must be
            fresh and unique for every (vault_key, document) pair.

        Returns
        -------
        bytes
            AES-256-GCM ciphertext with the 128-bit GCM authentication tag
            appended.  Total length = ``len(plaintext) + 16`` bytes.

        Raises
        ------
        VaultKeyEncryptionError
            If ``vault_key`` is not 32 bytes, or ``nonce`` is not 12 bytes.
        """
        self._validate_key_bytes(vault_key, "vault_key")
        self._validate_nonce(nonce)

        logger.debug(
            "Encrypting document bytes (algorithm=%s, plaintext_bytes=%d)",
            ALGORITHM_LABEL,
            len(plaintext),
        )

        try:
            ciphertext: bytes = AESGCM(vault_key).encrypt(nonce, plaintext, None)
        except ValueError as exc:
            raise VaultKeyEncryptionError(
                f"Document encryption failed: {exc}",
                detail="AES-256-GCM document encryption could not complete.",
            ) from exc

        logger.info(
            "Document encrypted (algorithm=%s, ciphertext_bytes=%d)",
            ALGORITHM_LABEL,
            len(ciphertext),
        )
        return ciphertext

    def decrypt_bytes(
        self,
        ciphertext: bytes,
        vault_key: bytes,
        nonce: bytes,
    ) -> bytes:
        """
        Decrypt AES-256-GCM ciphertext produced by :meth:`encrypt_bytes`.

        Parameters
        ----------
        ciphertext:
            Encrypted bytes including the appended 16-byte GCM tag.
        vault_key:
            Raw 32-byte Vault Key used during encryption.
        nonce:
            Raw 12-byte nonce used during encryption.

        Returns
        -------
        bytes
            Decrypted plaintext bytes.

        Raises
        ------
        VaultKeyDecryptionError
            If the GCM authentication tag does not verify (wrong key, wrong
            nonce, tampered data) or if the ciphertext is too short.
        VaultKeyEncryptionError
            If ``vault_key`` is not 32 bytes or ``nonce`` is not 12 bytes.
        """
        self._validate_key_bytes(vault_key, "vault_key")
        self._validate_nonce(nonce)
        self._validate_ciphertext(ciphertext)

        try:
            plaintext: bytes = AESGCM(vault_key).decrypt(nonce, ciphertext, None)
        except InvalidTag:
            logger.warning(
                "Document decryption failed: GCM authentication tag mismatch."
            )
            raise VaultKeyDecryptionError(
                "Document decryption failed: authentication tag mismatch.",
                detail=(
                    "The GCM authentication tag did not verify.  The document "
                    "blob may be corrupt, or the wrong Vault Key was supplied."
                ),
            )
        except Exception as exc:
            raise VaultKeyDecryptionError(
                f"Document decryption failed unexpectedly: {type(exc).__name__}",
                detail="An unexpected error occurred during document decryption.",
            ) from exc

        logger.info(
            "Document decrypted (algorithm=%s, plaintext_bytes=%d)",
            ALGORITHM_LABEL,
            len(plaintext),
        )
        return plaintext

    def encode_for_storage(self, data: bytes) -> str:
        """
        Base64-encode raw bytes for safe storage in ``key.json``.

        JSON does not have a native binary type.  Base64 is the industry
        standard encoding for binary data in JSON (used by JWK, JWE, etc.).

        Parameters
        ----------
        data:
            Raw bytes to encode (ciphertext or nonce).

        Returns
        -------
        str
            Standard Base64-encoded string (RFC 4648 §4) with ``=`` padding,
            as produced by :func:`base64.b64encode`.  Uses the standard
            alphabet (``+`` and ``/``), not the URL-safe alphabet
            (``-`` and ``_``).
        """
        return base64.b64encode(data).decode("ascii")

    def decode_from_storage(self, encoded: str, field_name: str) -> bytes:
        """
        Decode a Base64 string from ``key.json`` back to raw bytes.

        Parameters
        ----------
        encoded:
            Base64-encoded string as stored in ``key.json``.
        field_name:
            Name of the field being decoded (used in error messages only;
            never included in logs).

        Returns
        -------
        bytes
            Raw bytes.

        Raises
        ------
        CorruptedVaultKeyError
            If ``encoded`` is missing, empty, or not valid Base64.  These
            are structural corruption signals — the field value is unusable
            before any cryptographic work has been attempted.
        """
        from app.core.exceptions import CorruptedVaultKeyError  # avoids circular at module level

        if not isinstance(encoded, str) or not encoded.strip():
            raise CorruptedVaultKeyError(
                f"key.json field '{field_name}' is empty or missing.",
                detail=(
                    f"The '{field_name}' field in key.json must be a non-empty "
                    "Base64 string.  The file may be corrupt."
                ),
            )

        try:
            return base64.b64decode(encoded.encode("ascii"))
        except Exception as exc:
            raise CorruptedVaultKeyError(
                f"key.json field '{field_name}' is not valid Base64.",
                detail=(
                    f"The '{field_name}' field in key.json could not be decoded "
                    f"as Base64: {exc}.  The file may be corrupt."
                ),
            ) from exc

    def compute_sha256(self, data: bytes) -> str:
        """
        Return the hex-encoded SHA-256 digest of ``data``.

        Used to produce an integrity fingerprint of encrypted document blobs
        immediately after encryption.  Only ciphertext is ever passed here —
        plaintext documents are never hashed directly.

        Parameters
        ----------
        data:
            Raw bytes to hash.  For document integrity, this must be the
            AES-256-GCM ciphertext (including the 16-byte GCM tag), never
            the plaintext.

        Returns
        -------
        str
            Lowercase hex string of the 256-bit (32-byte) SHA-256 digest.
            Example: ``"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"``.

        Extensibility
        -------------
        * **Algorithm agility**: add an ``algorithm`` parameter defaulting to
          ``"sha256"`` and forward it to :func:`hashlib.new`.  Callers store
          the algorithm name alongside the hash so future readers know which
          function to use for verification.
        * **Streaming**: replace the single ``hashlib.sha256(data)`` call with
          a loop that feeds chunks of a file object so large blobs do not need
          to be loaded fully into memory.
        * **Blockchain notarization**: the returned hex digest is exactly the
          value you would publish to a smart contract or an anchoring service
          (e.g. OpenTimestamps) — no transformation needed.
        """
        return hashlib.sha256(data).hexdigest()

    def validate_envelope(
        self,
        encrypted_vault_key_b64: str,
        nonce_b64: str,
        algorithm: str,
    ) -> None:
        """
        Assert that the stored encryption envelope is structurally valid.

        Checks that:

        * ``encrypted_vault_key_b64`` is a non-empty Base64 string that
          decodes to at least 17 bytes (1 plaintext byte + 16-byte GCM tag).
        * ``nonce_b64`` is a non-empty Base64 string that decodes to exactly
          :data:`NONCE_BYTES` bytes.
        * ``algorithm`` matches :data:`ALGORITHM_LABEL`.

        This method does **not** decrypt or verify the ciphertext —
        cryptographic verification happens in :meth:`decrypt_vault_key`.
        This is a purely structural check intended for fast health checks
        and schema migration guards.

        Parameters
        ----------
        encrypted_vault_key_b64:
            Base64-encoded ciphertext as stored in ``key.json``.
        nonce_b64:
            Base64-encoded nonce as stored in ``key.json``.
        algorithm:
            Algorithm label string as stored in ``key.json``
            (expected: ``"AES-256-GCM"``).

        Raises
        ------
        VaultKeyDecryptionError
            If any of the fields fail structural validation.
        """
        ct_bytes: bytes = self.decode_from_storage(
            encrypted_vault_key_b64, "encrypted_vault_key"
        )
        nonce_bytes: bytes = self.decode_from_storage(nonce_b64, "nonce")

        # Minimum ciphertext length: 1 byte plaintext + 16-byte GCM tag.
        if len(ct_bytes) < _GCM_TAG_BYTES + 1:
            raise VaultKeyDecryptionError(
                "encrypted_vault_key is too short to contain a GCM tag.",
                detail=(
                    f"The 'encrypted_vault_key' in key.json is {len(ct_bytes)} bytes, "
                    f"which is shorter than the minimum {_GCM_TAG_BYTES + 1} bytes "
                    "(1 plaintext byte + 16-byte GCM authentication tag).  "
                    "The file may be corrupt."
                ),
            )

        if len(nonce_bytes) != NONCE_BYTES:
            raise InvalidNonceError(
                f"nonce in key.json has wrong length: "
                f"expected {NONCE_BYTES} bytes, got {len(nonce_bytes)}.",
                detail=(
                    f"The 'nonce' field in key.json decoded to {len(nonce_bytes)} bytes "
                    f"but AES-256-GCM requires exactly {NONCE_BYTES} bytes (96 bits).  "
                    "The file may be corrupt."
                ),
            )

        if algorithm != ALGORITHM_LABEL:
            raise VaultKeyDecryptionError(
                f"Unsupported algorithm in key.json: '{algorithm}'.",
                detail=(
                    f"key.json specifies algorithm '{algorithm}' but this "
                    f"version of Cipherix only supports '{ALGORITHM_LABEL}'.  "
                    "A schema migration may be required."
                ),
            )

        logger.debug(
            "Encryption envelope validated (algorithm=%s, "
            "ciphertext_bytes=%d, nonce_bytes=%d)",
            algorithm,
            len(ct_bytes),
            len(nonce_bytes),
        )

    @staticmethod
    def _validate_key_bytes(key: bytes, param_name: str) -> None:
        """
        Assert that a key is exactly :data:`_KEY_BYTES` bytes long.

        Raises
        ------
        VaultKeyEncryptionError
            If the key is not exactly 32 bytes.
        """
        if not isinstance(key, bytes) or len(key) != _KEY_BYTES:
            raise VaultKeyEncryptionError(
                f"'{param_name}' must be exactly {_KEY_BYTES} bytes "
                f"(got {len(key) if isinstance(key, bytes) else type(key).__name__}).",
                detail=(
                    f"AES-256 requires a {_KEY_BYTES}-byte ({_KEY_BYTES * 8}-bit) key.  "
                    f"The supplied '{param_name}' has the wrong length.  "
                    "This is an internal programming error."
                ),
            )

    @staticmethod
    def _validate_nonce(nonce: bytes) -> None:
        """
        Assert that the nonce is exactly :data:`NONCE_BYTES` bytes long.

        Raises
        ------
        InvalidNonceError
            If the nonce is not exactly 12 bytes.
        """
        if not isinstance(nonce, bytes) or len(nonce) != NONCE_BYTES:
            raise InvalidNonceError(
                f"Nonce must be exactly {NONCE_BYTES} bytes "
                f"(got {len(nonce) if isinstance(nonce, bytes) else type(nonce).__name__}).",
                detail=(
                    f"AES-256-GCM requires a {NONCE_BYTES}-byte ({NONCE_BYTES * 8}-bit) "
                    "nonce per NIST SP 800-38D.  The supplied nonce has the wrong length.  "
                    "This is an internal programming error."
                ),
            )

    @staticmethod
    def _validate_ciphertext(ciphertext: bytes) -> None:
        """
        Assert that the ciphertext is at least long enough to contain a GCM tag.

        AES-GCM always appends a 16-byte authentication tag.  A ciphertext
        shorter than 17 bytes cannot be valid (it would not even hold a
        single plaintext byte plus the tag).

        Raises
        ------
        VaultKeyDecryptionError
            If the ciphertext is shorter than 17 bytes.
        """
        _MIN_CIPHERTEXT: int = _GCM_TAG_BYTES + 1

        if not isinstance(ciphertext, bytes) or len(ciphertext) < _MIN_CIPHERTEXT:
            raise VaultKeyDecryptionError(
                f"Ciphertext is too short: expected >= {_MIN_CIPHERTEXT} bytes, "
                f"got {len(ciphertext) if isinstance(ciphertext, bytes) else type(ciphertext).__name__}.",
                detail=(
                    f"The provided ciphertext is shorter than the minimum valid "
                    f"AES-256-GCM ciphertext length ({_MIN_CIPHERTEXT} bytes).  "
                    "The stored key.json may be corrupt."
                ),
            )
