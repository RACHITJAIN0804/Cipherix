
import json
import secrets
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


_DEFAULT_ALGORITHM: str = "AES-256-GCM"


_DEFAULT_KEY_VERSION: str = "1"


_PENDING_SENTINEL: str = "[PENDING_ENCRYPTION]"


_STATUS_ACTIVE: str = "active"


@dataclass
class KeyMetadata:

    created_at: str
    key_id: str

    key_version: str = field(default=_DEFAULT_KEY_VERSION)
    algorithm: str = field(default=_DEFAULT_ALGORITHM)
    status: str = field(default=_STATUS_ACTIVE)
    encrypted_vault_key: str = field(default=_PENDING_SENTINEL)


    nonce: str = field(default="")

    @classmethod
    def create(
        cls,
        encrypted_vault_key: str,
        nonce: str,
    ) -> "KeyMetadata":
        return cls(
            created_at=datetime.now(UTC).isoformat(),
            key_id=secrets.token_hex(16),
            key_version=_DEFAULT_KEY_VERSION,
            algorithm=_DEFAULT_ALGORITHM,
            status=_STATUS_ACTIVE,
            encrypted_vault_key=encrypted_vault_key,
            nonce=nonce,
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def write(self, path: Path) -> None:
        path.write_text(
            json.dumps(self.to_dict(), indent=4),
            encoding="utf-8",
        )

    @classmethod
    def read(cls, path: Path) -> "KeyMetadata":
        import dataclasses

        data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
        known: set[str] = {f.name for f in dataclasses.fields(cls)}
        filtered: dict[str, Any] = {k: v for k, v in data.items() if k in known}
        return cls(**filtered)
