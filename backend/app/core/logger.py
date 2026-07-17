import logging
import sys
from logging.handlers import RotatingFileHandler

from app.core.config import settings


LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s:%(lineno)d | %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def _console_handler() -> logging.StreamHandler:
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter(LOG_FORMAT, DATE_FORMAT))
    return handler


def _file_handler() -> RotatingFileHandler:
    settings.LOG_DIR.mkdir(parents=True, exist_ok=True)

    handler = RotatingFileHandler(
        filename=settings.LOG_DIR / settings.log_filename,
        maxBytes=settings.log_max_bytes,
        backupCount=settings.log_backup_count,
        encoding="utf-8",
    )

    handler.setFormatter(logging.Formatter(LOG_FORMAT, DATE_FORMAT))
    return handler


def configure_logging() -> None:
    root = logging.getLogger()

    level = getattr(logging, settings.log_level.upper(), logging.INFO)

    root.setLevel(level)

    if not root.handlers:
        root.addHandler(_console_handler())
        root.addHandler(_file_handler())

    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("multipart").setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)