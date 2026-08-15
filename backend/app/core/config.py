from enum import Enum
from functools import lru_cache
from pathlib import Path

from pydantic import Field, computed_field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Environment(str, Enum):
    DEVELOPMENT = "development"
    TESTING = "testing"
    STAGING = "staging"
    PRODUCTION = "production"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    app_name: str = "Cipherix"
    app_env: Environment = Environment.DEVELOPMENT
    debug: bool = True
    version: str = "0.1.0"

    secret_key: str = Field(default="change_this_in_production")

    log_level: str = "INFO"
    log_filename: str = "cipherix.log"
    log_max_bytes: int = 5 * 1024 * 1024
    log_backup_count: int = 3

    cors_origins: list[str] = [
        "http://localhost:3000",
        "http://localhost:5173",
    ]
    cors_allow_credentials: bool = True
    cors_allow_methods: list[str] = ["*"]
    cors_allow_headers: list[str] = ["*"]

    BASE_DIR: Path = Path(__file__).resolve().parents[3]
    BACKEND_DIR: Path = BASE_DIR / "backend"
    LOG_DIR: Path = BASE_DIR / "logs"
    VAULT_DIR: Path = BASE_DIR / "vaults"
    MODELS_DIR: Path = BASE_DIR / "models"
    VECTOR_DB_DIR: Path = BASE_DIR / "vector_db"
    DATABASE_DIR: Path = BASE_DIR / "database"
    DOCS_DIR: Path = BASE_DIR / "docs"
    SCRIPTS_DIR: Path = BASE_DIR / "scripts"
    COMPUTER_ACCESS_WORKSPACE_DIR: Path = BASE_DIR / "CIPHERIX_WORKSPACE"

    # SQLite database filename — relative to DATABASE_DIR.
    # Override via DATABASE_FILENAME env var to point at a different file
    # (e.g. "cipherix_test.db" in tests).
    database_filename: str = "cipherix.db"
    # Secret used to sign JWTs.  MUST be overridden in production via the
    # JWT_SECRET_KEY environment variable.  The default is intentionally
    # weak and flagged in the field description.
    jwt_secret_key: str = Field(
        default="change_this_jwt_secret_in_production",
        description="HS256 signing secret for JWTs.  Override in production.",
    )
    # HMAC-SHA256 — fast, widely supported, and sufficient for server-side
    # JWTs where we control both signing and verification.
    jwt_algorithm: str = Field(default="HS256")

    # Access token lifetime.  Short-lived to limit the blast radius of a
    # stolen token.  Refresh tokens are longer-lived and separated by type.
    access_token_expire_minutes: int = Field(default=30)
    refresh_token_expire_days: int = Field(default=7)

    # RAG Document Processing Settings
    rag_chunk_size: int = Field(default=500, description="Default character size per chunk.")
    rag_chunk_overlap: int = Field(default=50, description="Default character overlap between consecutive chunks.")
    max_document_processing_size_bytes: int = Field(
        default=10 * 1024 * 1024,
        description="Maximum allowed file size for document text extraction and chunking (10 MB).",
    )
    supported_processing_mime_types: list[str] = Field(
        default=[
            "text/plain",
            "application/pdf",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        ],
        description="Allowed MIME types for document processing pipeline.",
    )

    # Embedding and Vector Storage Settings
    embedding_model_name: str = Field(
        default="all-MiniLM-L6-v2",
        description="Local Sentence Transformers embedding model name.",
    )
    vector_db_dir_name: str = Field(
        default="cipherix_vectors",
        description="Directory name for ChromaDB vector storage under VECTOR_DB_DIR.",
    )
    embedding_batch_size: int = Field(
        default=32,
        description="Default batch size for generating text chunk embeddings.",
    )
    search_default_top_k: int = Field(
        default=5,
        description="Default number of top semantic search results to return.",
    )

    # LLM Settings
    llm_provider: str = Field(
        default="ollama",
        description="Local LLM backend provider. Supported: 'ollama', 'disabled'.",
    )
    llm_base_url: str = Field(
        default="http://localhost:11434",
        description="Base URL for the Ollama REST API server.",
    )
    llm_model_name: str = Field(
        default="llama3.2:1b",
        description="Ollama model name to use for RAG generation (e.g. 'llama3.2:1b', 'phi3.5').",
    )
    llm_temperature: float = Field(
        default=0.1,
        ge=0.0,
        le=2.0,
        description="Sampling temperature for LLM generation. Lower = more deterministic.",
    )
    llm_max_tokens: int = Field(
        default=1024,
        ge=64,
        description="Maximum number of tokens the LLM may generate in a single response.",
    )
    llm_timeout_seconds: int = Field(
        default=60,
        ge=5,
        description="HTTP timeout in seconds for Ollama generation requests.",
    )

    # RAG Pipeline Settings
    rag_max_chunks: int = Field(
        default=5,
        ge=1,
        le=20,
        description="Maximum number of retrieved chunks passed to the LLM context.",
    )
    rag_max_context_chars: int = Field(
        default=4000,
        ge=500,
        description="Maximum total characters allowed in the assembled LLM context.",
    )
    rag_min_similarity: float = Field(
        default=0.30,
        ge=0.0,
        le=1.0,
        description="Minimum cosine similarity score for a chunk to be included in RAG context.",
    )

    # Blockchain Settings
    blockchain_enabled: bool = Field(
        default=True,
        description="Whether blockchain document integrity anchoring is enabled.",
    )
    blockchain_provider: str = Field(
        default="local",
        description="Blockchain adapter provider name ('local').",
    )
    blockchain_network: str = Field(
        default="local-development",
        description="Blockchain network identifier label.",
    )


    @computed_field  # type: ignore[prop-decorator]
    @property
    def database_url(self) -> str:
        """
        SQLAlchemy-compatible SQLite URL built from DATABASE_DIR and filename.

        Uses three slashes for a relative path from the DB file's perspective.
        The path is absolute so SQLAlchemy opens the same file regardless of
        the process working directory.
        """
        db_path = self.DATABASE_DIR / self.database_filename
        return f"sqlite:///{db_path}"


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()