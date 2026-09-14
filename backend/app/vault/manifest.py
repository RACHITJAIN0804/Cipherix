
import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path


@dataclass
class VaultManifest:

    vault_id: str
    name: str
    created_at: str
    version: str = field(default="1.0")
    status: str = field(default="locked")

    @classmethod
    def create(cls, vault_id: str, name: str) -> "VaultManifest":
        return cls(
            vault_id=vault_id,
            name=name,
            created_at=datetime.now(UTC).isoformat(),
        )

    def to_dict(self) -> dict[str, str]:
        return asdict(self)

    def write(self, path: Path) -> None:
        path.write_text(
            json.dumps(self.to_dict(), indent=4),
            encoding="utf-8",
        )

    @classmethod
    def read(cls, path: Path) -> "VaultManifest":
        data: dict = json.loads(path.read_text(encoding="utf-8"))
        return cls(**data)
