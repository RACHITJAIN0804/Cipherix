"""
constants.py
------------
Application-wide immutable constants for Cipherix.

Only values that are truly fixed and environment-independent
belong here. Anything that varies per deployment goes in config.py.
"""

# ---------------------------------------------------------------------------
# Application identity
# ---------------------------------------------------------------------------

APP_VERSION: str = "0.1.0"
APP_DESCRIPTION: str = (
    "Cipherix – a privacy-first, local AI knowledge vault."
)

# ---------------------------------------------------------------------------
# API metadata
# ---------------------------------------------------------------------------

API_V1_PREFIX: str = "/api/v1"

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

LOG_DIR: str = "logs"
LOG_FILENAME: str = "cipherix.log"
LOG_MAX_BYTES: int = 5 * 1024 * 1024   # 5 MB per log file
LOG_BACKUP_COUNT: int = 3              # keep 3 rotated files
