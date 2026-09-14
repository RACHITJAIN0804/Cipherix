class CipherixError(Exception):
    def __init__(self, message: str, detail: str | None = None) -> None:
        super().__init__(message)
        self.message: str = message
        self.detail: str = detail or message


class VaultError(CipherixError):
    pass


class VaultCreationError(VaultError):
    pass


class VaultAlreadyExistsError(VaultError):
    pass


class VaultValidationError(VaultError):
    pass


class VaultManifestError(VaultError):
    pass


class VaultNotFoundError(VaultError):
    pass


class VaultAccessDeniedError(VaultError):
    pass


class VaultDeletionError(VaultError):
    pass


class VaultStateError(VaultError):
    pass


class SecurityMetadataNotFoundError(VaultError):
    pass


class SecurityMetadataError(VaultError):
    pass


class KeyMetadataNotFoundError(VaultError):
    pass


class KeyMetadataError(VaultError):
    pass


class PasswordError(CipherixError):
    pass


class InvalidPasswordError(PasswordError):
    pass


class MissingSaltError(PasswordError):
    pass


class InvalidKdfParamsError(PasswordError):
    pass


class PasswordChangeError(PasswordError):
    pass


class EncryptionError(CipherixError):
    pass


class VaultKeyEncryptionError(EncryptionError):
    pass


class VaultKeyDecryptionError(EncryptionError):
    pass


class InvalidNonceError(EncryptionError):
    pass


class CorruptedVaultKeyError(EncryptionError):
    pass


class DocumentError(CipherixError):
    pass


class VaultLockedError(DocumentError):
    pass


class DocumentNotFoundError(DocumentError):
    pass


class DocumentEncryptionError(DocumentError):
    pass


class InvalidUploadError(DocumentError):
    pass


class DocumentStorageError(DocumentError):
    pass


class DocumentProcessingError(DocumentError):
    pass


class UnsupportedFileTypeError(DocumentProcessingError):
    pass


class DocumentExtractionError(DocumentProcessingError):
    pass


class EmptyDocumentError(DocumentProcessingError):
    pass


class IntegrityError(DocumentError):
    pass


class IntegrityVerificationError(IntegrityError):
    pass


class MissingIntegrityMetadataError(IntegrityError):
    pass


class CorruptedDocumentError(IntegrityError):
    pass


class RecoveryError(CipherixError):
    pass


class InvalidRecoverySeedError(RecoveryError):
    pass


class InvalidSeedChecksumError(RecoveryError):
    pass


class UnsupportedRecoveryVersionError(RecoveryError):
    pass


class RecoveryMetadataMissingError(RecoveryError):
    pass


class DatabaseError(CipherixError):
    pass


class VaultRecordNotFoundError(DatabaseError):
    pass


class DocumentRecordNotFoundError(DatabaseError):
    pass


class SecurityMetadataRecordNotFoundError(DatabaseError):
    pass


class AuthError(CipherixError):
    pass


class UserAlreadyExistsError(AuthError):
    pass


class UserNotFoundError(AuthError):
    pass


class InvalidCredentialsError(AuthError):
    pass


class InactiveUserError(AuthError):
    pass


class TokenError(AuthError):
    pass


class ExpiredTokenError(TokenError):
    pass


class InvalidTokenError(TokenError):
    pass


class LLMError(CipherixError):
    pass


class LLMUnavailableError(LLMError):
    pass


class LLMGenerationError(LLMError):
    pass


class LLMTimeoutError(LLMError):
    pass


class RAGError(CipherixError):
    pass


class RAGEmptyQueryError(RAGError):
    pass


class RAGNoContextError(RAGError):
    pass


class ComputerAccessError(CipherixError):
    pass


class ComputerAccessDisabledError(ComputerAccessError):
    pass


class PathGuardError(ComputerAccessError):
    pass


class ActionNotAllowedError(ComputerAccessError):
    pass


class ApprovalRequiredError(ComputerAccessError):
    pass


class ActionExecutionError(ComputerAccessError):
    pass


class BlockchainError(CipherixError):
    pass


class BlockchainUnavailableError(BlockchainError):
    pass


class AnchorNotFoundError(BlockchainError):
    pass


class AnchorAlreadyExistsError(BlockchainError):
    pass


class BlockchainVerificationError(BlockchainError):
    pass


class RateLimitExceededError(CipherixError):
    pass


class ConfigurationError(CipherixError):
    pass
