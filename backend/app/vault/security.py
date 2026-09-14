
import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


_DEFAULT_ALGORITHM: str = "AES-256-GCM"
_DEFAULT_KEY_DERIVATION: str = "Argon2id"
_DEFAULT_VERSION: str = "1.0"
_DEFAULT_STATUS: str = "uninitialized"


@dataclass
class SecurityMetadata:

    algorithm: str = field(default=_DEFAULT_ALGORITHM)
    key_derivation: str = field(default=_DEFAULT_KEY_DERIVATION)
    version: str = field(default=_DEFAULT_VERSION)
    status: str = field(default=_DEFAULT_STATUS)
    created_at: str = field(default="")

    @classmethod
    def create(cls) -> "SecurityMetadata":
        return cls(created_at=datetime.now(UTC).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def write(self, path: Path) -> None:
        path.write_text(
            json.dumps(self.to_dict(), indent=4),
            encoding="utf-8",
        )

    @classmethod
    def read(cls, path: Path) -> "SecurityMetadata":
        data: dict = json.loads(path.read_text(encoding="utf-8"))
        return cls(**data)
