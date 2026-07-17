from enum import Enum
from functools import lru_cache
from pathlib import Path

from pydantic import Field
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


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()