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