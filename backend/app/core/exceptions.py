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


class VaultStateError(VaultError):
    """
    Raised when a lock or unlock transition is a no-op.

    Examples
    --------
    * Calling ``POST /vaults/{id}/lock`` on a vault that is already locked.
    * Calling ``POST /vaults/{id}/unlock`` on a vault that is already unlocked.

    Routes should map this to ``HTTP 409 Conflict`` so that callers
    receive a clear signal that the vault is already in the desired state,
    rather than a generic 400 or 500 response.
    """


# ---------------------------------------------------------------------------
# Security errors
# ---------------------------------------------------------------------------


class SecurityMetadataNotFoundError(VaultError):
    """
    Raised when ``security.json`` is absent from a vault directory.

    Every Cipherix vault must contain a ``security.json`` file that
    records the cryptographic algorithm, key-derivation scheme, and
    initialisation status.  A vault without this file is considered
    structurally incomplete.

    This is distinct from :class:`VaultManifestError` so that callers
    can tell apart a missing *identity* file (``manifest.json``) from a
    missing *cryptography* file (``security.json``).
    """


class SecurityMetadataError(VaultError):
    """
    Raised when ``security.json`` exists but cannot be read or parsed.

    Examples
    --------
    * The file contains malformed JSON (e.g. truncated write).
    * A required field (``algorithm``, ``key_derivation``, etc.) is absent.
    * The file exists but cannot be opened due to a permissions error.

    Callers should treat this as a corrupt-vault signal and handle it
    the same way they would handle :class:`VaultManifestError`.
    """


# ---------------------------------------------------------------------------
# Key management errors
# ---------------------------------------------------------------------------


class KeyMetadataNotFoundError(VaultError):
    """
    Raised when ``key.json`` is absent from a vault directory.

    Every Cipherix vault must contain a ``key.json`` file that records
    the key version, algorithm, and lifecycle status of the vault's
    encryption key.  A vault without this file is considered
    cryptographically incomplete.

    This is distinct from :class:`SecurityMetadataNotFoundError` (which
    covers ``security.json``) and :class:`VaultManifestError` (which
    covers ``manifest.json``), giving callers precise signal about
    *which* file is missing.
    """


class KeyMetadataError(VaultError):
    """
    Raised when ``key.json`` exists but cannot be read, parsed, or validated.

    Examples
    --------
    * The file contains malformed JSON (e.g. truncated write).
    * A required field (``key_version``, ``algorithm``, ``key_id``, etc.)
      is absent or empty.
    * The file exists but cannot be opened due to a permissions error.
    * A field value has an unexpected type (e.g. integer instead of string).

    Callers should treat this as a corrupt-vault signal.  The vault's
    encryption posture is indeterminate until the file is repaired or
    the vault is re-initialised.
    """


# ---------------------------------------------------------------------------
# Password / key-derivation errors
# ---------------------------------------------------------------------------


class PasswordError(CipherixError):
    """Base class for all password and key-derivation errors."""


class InvalidPasswordError(PasswordError):
    """
    Raised when a password supplied to
    :class:`~app.security.password_manager.PasswordManager` is empty,
    contains only whitespace, or otherwise fails pre-derivation validation.

    This is a *client input* error — the user provided an unusable password.
    Routes should map this to ``HTTP 422 Unprocessable Entity`` or
    ``HTTP 400 Bad Request``.

    Examples
    --------
    * Password is an empty string.
    * Password is a string of only spaces or control characters.

    .. note::
        This exception is **not** raised when a password is merely *wrong*
        (i.e. produces a Master Key that does not match the expected key).
        Wrong-password failures are signalled by a ``False`` return value
        from :meth:`~app.security.password_manager.PasswordManager.verify_password`
        or by an AES-GCM authentication tag mismatch (future milestone).
    """


class MissingSaltError(PasswordError):
    """
    Raised when ``password_meta.json`` is absent from a vault directory,
    or when the ``salt`` field within it is empty, null, or not valid
    hexadecimal.

    Every Cipherix vault that has been initialised with a password must
    contain a ``password_meta.json`` file that records the per-vault salt
    and Argon2id parameters.  Without the salt, the Master Key cannot be
    re-derived and the vault cannot be unlocked.

    Examples
    --------
    * ``password_meta.json`` does not exist (vault created before this
      milestone, or file was deleted).
    * The ``"salt"`` key is present but its value is ``null`` or ``""``.
    * The ``"salt"`` value is not valid hexadecimal.
    """


class InvalidKdfParamsError(PasswordError):
    """
    Raised when the Argon2id KDF parameters stored in
    ``password_meta.json`` are structurally invalid or cannot be used
    for key derivation.

    Examples
    --------
    * A required field (``time_cost``, ``memory_cost``, ``parallelism``,
      ``hash_len``) is missing from the ``"kdf"`` object.
    * ``time_cost`` is zero or negative (Argon2id requires at least 1).
    * ``memory_cost`` is below the Argon2id minimum of 8 KiB.
    * ``hash_len`` is less than 4 bytes.
    * The ``"kdf"`` object itself is absent from ``password_meta.json``.
    * The file exists but cannot be written (I/O error during initialisation).

    Callers should treat this as a corrupt-vault signal and prevent any
    further cryptographic operations until the vault is re-initialised or
    repaired.
    """


class PasswordChangeError(PasswordError):
    """
    Raised when a vault password-change operation fails.

    This exception is the top-level signal for the change-password flow.
    Callers that do not need to distinguish between sub-causes can catch
    this class alone.

    Examples
    --------
    * ``old_password`` is incorrect — the derived Master Key does not
      decrypt the Vault Key (AES-GCM authentication tag mismatch).
    * ``old_password`` is structurally invalid (empty, whitespace-only).
    * The Vault Key could not be re-encrypted under the new Master Key.
    * ``password_meta.json`` or ``key.json`` cannot be written after the
      re-wrap — partial-write guard prevents the vault from being left in
      an indeterminate state.

    Routes should map this to:

    * ``HTTP 401 Unauthorized`` when the old password is wrong.
    * ``HTTP 422 Unprocessable Entity`` when the new password fails
      structural validation (too short, whitespace-only, etc.).
    * ``HTTP 500 Internal Server Error`` for storage or encryption failures.

    Extensibility
    -------------
    * Subclass with ``OldPasswordIncorrectError`` and
      ``NewPasswordValidationError`` once callers need to distinguish
      between them programmatically.
    * Add a ``reason`` field (enum) for machine-readable differentiation.
    """


# ---------------------------------------------------------------------------
# Encryption errors
# ---------------------------------------------------------------------------


class EncryptionError(CipherixError):
    """
    Base class for all AES-256-GCM encryption and decryption errors.

    Catch this in places where you want to handle any encryption failure
    without distinguishing between encrypt, decrypt, nonce, or corruption
    failures.
    """


class VaultKeyEncryptionError(EncryptionError):
    """
    Raised when AES-256-GCM encryption of the Vault Key fails.

    Examples
    --------
    * The ``master_key`` or ``vault_key`` supplied to
      :meth:`~app.security.encryption.EncryptionManager.encrypt_vault_key`
      is not exactly 32 bytes.
    * The ``nonce`` is not exactly 12 bytes.
    * The underlying cryptographic operation raises an unexpected error.

    Routes should map this to ``HTTP 500 Internal Server Error``.  The
    Vault Key has **not** been stored when this exception is raised.
    """


class VaultKeyDecryptionError(EncryptionError):
    """
    Raised when AES-256-GCM decryption of the Vault Key fails.

    The most common cause is an incorrect password (which produces a wrong
    Master Key and therefore a GCM authentication tag mismatch).

    Examples
    --------
    * The GCM authentication tag does not verify (wrong password, tampered
      ``key.json``, or wrong nonce).
    * The ciphertext stored in ``key.json`` is too short to be valid.
    * A ``key.json`` field that should contain Base64 contains garbage.

    Routes should map this to ``HTTP 401 Unauthorized`` (wrong password)
    or ``HTTP 500 Internal Server Error`` (structural corruption).  In
    either case **no plaintext Vault Key bytes are exposed**.
    """


class InvalidNonceError(EncryptionError):
    """
    Raised when the nonce stored in or supplied to
    :class:`~app.security.encryption.EncryptionManager` has the wrong
    length or is otherwise unusable.

    AES-256-GCM requires exactly 12 bytes (96 bits) per NIST SP 800-38D.
    Any other length is rejected before the cryptographic operation runs.

    Examples
    --------
    * The ``nonce`` field in ``key.json`` decodes from Base64 to a byte
      string that is not exactly 12 bytes (corrupt file).
    * A nonce produced by a non-standard source is passed directly.

    Routes should map this to ``HTTP 500 Internal Server Error`` and treat
    the vault as structurally corrupt.
    """


class CorruptedVaultKeyError(EncryptionError):
    """
    Raised when ``key.json`` is present and parseable but the encrypted
    Vault Key envelope fails structural validation before any decryption is
    attempted.

    Examples
    --------
    * ``encrypted_vault_key`` in ``key.json`` is still the legacy sentinel
      ``"[PENDING_ENCRYPTION]"`` — the vault was created before AES-256-GCM
      wrapping was implemented and has never been migrated.
    * ``encrypted_vault_key`` decodes to fewer bytes than the minimum valid
      AES-256-GCM ciphertext (1 plaintext byte + 16-byte authentication tag).
    * The ``algorithm`` field in ``key.json`` is not ``"AES-256-GCM"``.

    Routes should map this to ``HTTP 500 Internal Server Error`` and treat
    the vault as requiring re-initialisation or migration.
    """


# ---------------------------------------------------------------------------
# Document errors
# ---------------------------------------------------------------------------


class DocumentError(CipherixError):
    """
    Base class for all document-related errors.

    Catch this in places where you want to handle any document operation
    failure without distinguishing between specific subtypes.
    """


class VaultLockedError(DocumentError):
    """
    Raised when an operation is attempted on a vault that is currently locked.

    All document operations (upload, list, delete) require an unlocked vault
    so that the Vault Key can be derived and used for encryption/decryption.

    Routes should map this to ``HTTP 423 Locked`` or ``HTTP 403 Forbidden``
    to give the client a clear signal that they need to unlock the vault first.
    """


class DocumentNotFoundError(DocumentError):
    """
    Raised when a requested document does not exist in the vault.

    Examples
    --------
    * ``GET /vaults/{vault_id}/documents/{document_id}`` — document does
      not exist.
    * ``DELETE /vaults/{vault_id}/documents/{document_id}`` — trying to
      delete a document that has already been deleted or never uploaded.

    Routes should map this to ``HTTP 404 Not Found``.
    """


class DocumentEncryptionError(DocumentError):
    """
    Raised when AES-256-GCM encryption of a document fails.

    Examples
    --------
    * The Vault Key could not be decrypted (wrong password or corrupt
      ``key.json``).
    * The underlying AES-GCM operation raised an unexpected error.

    Routes should map this to ``HTTP 500 Internal Server Error``.  The
    document has **not** been stored when this exception is raised.
    """


class InvalidUploadError(DocumentError):
    """
    Raised when the uploaded file fails validation before any filesystem
    or cryptographic work is attempted.

    Examples
    --------
    * No file was included in the multipart request.
    * The original filename is absent, empty, or contains path-traversal
      sequences (e.g. ``../../etc/passwd``).
    * The filename contains characters not permitted by the filesystem
      policy (e.g. null bytes, leading dots beyond a normal hidden-file).
    * The file content is empty (zero-byte upload).

    Routes should map this to ``HTTP 422 Unprocessable Entity`` or
    ``HTTP 400 Bad Request``.
    """


class DocumentStorageError(DocumentError):
    """
    Raised when the filesystem cannot write, read, or delete a document's
    encrypted content or metadata file.

    Examples
    --------
    * Permission denied when writing ``encrypted/<document_id>.bin``.
    * Permission denied when writing ``metadata/<document_id>.json``.
    * Disk full during an upload.
    * OS-level I/O error on the metadata directory.

    Routes should map this to ``HTTP 500 Internal Server Error``.
    """


# ---------------------------------------------------------------------------
# Integrity errors
# ---------------------------------------------------------------------------


class IntegrityError(DocumentError):
    """Base class for all document integrity verification errors."""


class IntegrityVerificationError(IntegrityError):
    """
    Raised when the SHA-256 hash of a stored encrypted document does not match
    the hash recorded in its metadata sidecar at upload time.

    This signals that the encrypted blob has been **modified or corrupted**
    after it was written.  The modification could be:

    * External tampering (an attacker or unauthorized process overwrote the file).
    * Silent data corruption (storage layer bit-rot, incomplete write, etc.).
    * A bug in a write path that clobbered the file.

    Note that this exception says nothing about whether the *plaintext* is
    intact — only that the ciphertext on disk differs from what was stored.
    AES-GCM would also detect such corruption at decryption time, but this
    check is faster (no password or Vault Key required) and can be run as a
    standalone health check.

    Extensibility
    -------------
    * **Digital signatures**: store a Ed25519 signature of the hash alongside
      it so that tampering by the server itself can be detected by the client.
    * **Blockchain notarization**: publish ``sha256_ciphertext`` to an
      immutable ledger at upload time; verification compares the current hash
      against the on-chain record rather than the local metadata.
    * **Audit history**: emit an audit event here so every failed verification
      is permanently recorded with vault, document, timestamp, and both hashes.

    Routes should map this to ``HTTP 409 Conflict`` or ``HTTP 422 Unprocessable
    Entity`` to indicate that the resource exists but its integrity cannot be
    confirmed.
    """


class MissingIntegrityMetadataError(IntegrityError):
    """
    Raised when a document's metadata sidecar does not contain a
    ``sha256_ciphertext`` field.

    This happens when a document was uploaded before integrity hashing was
    introduced (i.e. before this milestone).  The document may be perfectly
    valid, but it cannot be verified because no baseline hash was recorded.

    Routes should map this to ``HTTP 409 Conflict`` with a message explaining
    that the document predates integrity verification and must be re-uploaded
    to generate a baseline hash.
    """


class CorruptedDocumentError(IntegrityError):
    """
    Raised when a document's encrypted blob cannot be read or is structurally
    invalid during an integrity verification attempt.

    This is distinct from :class:`IntegrityVerificationError`:

    * ``CorruptedDocumentError`` — the file cannot even be *read* cleanly
      (missing, zero-byte, or OS-level I/O failure).
    * ``IntegrityVerificationError`` — the file was read successfully but
      its hash does not match the stored hash.

    Routes should map this to ``HTTP 500 Internal Server Error``.
    """


# ---------------------------------------------------------------------------
# Recovery seed errors
# ---------------------------------------------------------------------------


class RecoveryError(CipherixError):
    """Base class for all recovery seed errors."""


class InvalidRecoverySeedError(RecoveryError):
    """
    Raised when a candidate recovery seed fails BIP-39 validation.

    Examples
    --------
    * The mnemonic has the wrong number of words (not 24).
    * One or more words are not in the BIP-39 English wordlist.
    * The embedded BIP-39 checksum does not verify.

    Routes should map this to ``HTTP 422 Unprocessable Entity``.
    """


class InvalidSeedChecksumError(RecoveryError):
    """
    Raised when a structurally valid BIP-39 mnemonic's fingerprint does
    not match the fingerprint stored in ``recovery_meta.json``.

    This means the seed passed BIP-39 validation but is not the seed that
    was generated for this specific vault.

    Routes should map this to ``HTTP 401 Unauthorized``.
    """


class UnsupportedRecoveryVersionError(RecoveryError):
    """
    Raised when ``recovery_meta.json`` contains a ``recovery_version``
    value that this version of Cipherix does not recognise.

    This signals that the vault was created or migrated by a newer version
    of the application and the current version cannot safely handle it.

    Routes should map this to ``HTTP 422 Unprocessable Entity``.
    """


class RecoveryMetadataMissingError(RecoveryError):
    """
    Raised when ``recovery_meta.json`` is absent from a vault directory.

    This means no recovery seed has been generated for this vault yet.

    Routes should map this to ``HTTP 404 Not Found`` or
    ``HTTP 409 Conflict`` (the resource exists but recovery is not
    configured).
    """
