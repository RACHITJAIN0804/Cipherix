
from dataclasses import asdict, dataclass, field
from typing import Any


_KDF_ALGORITHM: str = "argon2id"
_KDF_VERSION: int = 19
_DEFAULT_TIME_COST: int = 3
_DEFAULT_MEMORY_COST: int = 65536
_DEFAULT_PARALLELISM: int = 4
_DEFAULT_HASH_LEN: int = 32


SALT_BYTES: int = 32


@dataclass
class KdfParams:

    algorithm: str = field(default=_KDF_ALGORITHM)
    version: int = field(default=_KDF_VERSION)
    time_cost: int = field(default=_DEFAULT_TIME_COST)
    memory_cost: int = field(default=_DEFAULT_MEMORY_COST)
    parallelism: int = field(default=_DEFAULT_PARALLELISM)
    hash_len: int = field(default=_DEFAULT_HASH_LEN)
    salt_encoding: str = field(default="hex")

    @classmethod
    def default(cls) -> "KdfParams":
        return cls()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "KdfParams":
        import dataclasses

        known: set[str] = {f.name for f in dataclasses.fields(cls)}
        filtered: dict[str, Any] = {k: v for k, v in data.items() if k in known}
        return cls(**filtered)
