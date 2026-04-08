"""Abstract base for cloud sync providers."""

from __future__ import annotations

import base64
import hashlib
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Protocol


@dataclass(frozen=True)
class SyncResult:
    """Outcome of a sync operation."""

    provider: str
    downloaded: int = 0
    uploaded: int = 0
    errors: tuple[str, ...] = ()
    success: bool = True


@dataclass(frozen=True)
class ComparableDigest:
    """Remote digest representation that can be compared to a local file checksum."""

    algorithm: str
    value: str


class _HashLike(Protocol):
    """Minimal hashlib interface used by the local checksum helpers."""

    def update(self, data: bytes) -> object: ...

    def hexdigest(self) -> str: ...

    def digest(self) -> bytes: ...


class SyncProvider(ABC):
    """Interface that all cloud sync backends must implement.

    Providers are responsible for:
      - Listing remote policy files
      - Downloading policies to local disk
      - Uploading local policies to cloud storage
      - Computing ETags/checksums to skip unchanged files

    Subclasses must set ``_prefix`` in their ``__init__``.
    """

    _prefix: str

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable provider name (e.g., 'aws-s3')."""

    @abstractmethod
    def list_remote(self) -> list[dict[str, Any]]:
        """Return metadata for all remote policy files.

        Each dict must contain at least:
          - "key": str — the object key / blob name / path
          - "size": int — bytes

        Providers may also include:
          - "content_hash": str — content digest comparable to file_md5()
          - "content_hash_algorithm": str — checksum algorithm for content_hash
        """

    @abstractmethod
    def download(self, remote_key: str, local_path: Path) -> None:
        """Download a single policy file from the remote store."""

    @abstractmethod
    def upload(self, local_path: Path, remote_key: str) -> None:
        """Upload a single policy file to the remote store."""

    def remote_key_for(self, filename: str) -> str:
        """Construct the full remote key/path for a given local filename.

        Default implementation prepends self._prefix. Override if your
        provider uses a different key structure.
        """
        normalized_path = self.local_relative_path_for(filename).as_posix()
        return f"{self._prefix}{normalized_path}"

    def local_relative_path_for(self, remote_key: str) -> Path:
        """Return a safe local relative path for a remote object key."""
        normalized_key = remote_key.replace("\\", "/")
        normalized_prefix = self._prefix.replace("\\", "/")

        if normalized_key.startswith("/"):
            raise ValueError(f"Unsafe remote key: {remote_key}")

        relative_key = normalized_key
        if normalized_prefix and normalized_key.startswith(normalized_prefix):
            relative_key = normalized_key[len(normalized_prefix) :]

        relative_path = PurePosixPath(relative_key)
        if not relative_path.parts or any(part in ("", ".", "..") for part in relative_path.parts):
            raise ValueError(f"Unsafe remote key: {remote_key}")

        return Path(*relative_path.parts)

    def comparable_remote_digest(
        self,
        remote_metadata: dict[str, Any] | None,
    ) -> ComparableDigest | None:
        """Return a remote digest that is safe to compare to a local file."""
        if remote_metadata is None:
            return None

        remote_hash = remote_metadata.get("content_hash")
        if isinstance(remote_hash, str) and remote_hash:
            algorithm = remote_metadata.get("content_hash_algorithm", "md5-hex")
            if isinstance(algorithm, str) and algorithm:
                return ComparableDigest(
                    algorithm=algorithm,
                    value=self._normalize_digest_value(algorithm, remote_hash),
                )
        return None

    @staticmethod
    def _normalize_digest_value(algorithm: str, digest: str) -> str:
        normalized = digest.strip()
        if algorithm.endswith("-hex"):
            return normalized.lower()
        return normalized

    @staticmethod
    def file_md5(path: Path) -> str:
        """Compute MD5 hex digest of a local file for backward-compatible callers."""
        return SyncProvider.file_checksum(path, "md5-hex")

    @staticmethod
    def file_checksum(path: Path, algorithm: str) -> str:
        """Compute a checksum for a local file using a supported algorithm."""
        if algorithm == "md5-hex":
            return SyncProvider._hash_file(path, hashlib.md5).hexdigest()  # noqa: S324
        if algorithm == "md5-base64":
            digest = SyncProvider._hash_file(path, hashlib.md5).digest()  # noqa: S324
            return base64.b64encode(digest).decode("ascii")
        if algorithm == "sha256-base64":
            digest = SyncProvider._hash_file(path, hashlib.sha256).digest()
            return base64.b64encode(digest).decode("ascii")
        raise ValueError(f"Unsupported checksum algorithm: {algorithm}")

    @staticmethod
    def _hash_file(path: Path, factory: Callable[[], _HashLike]) -> _HashLike:
        """Hash file contents with the provided hashlib constructor."""
        hasher = factory()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                hasher.update(chunk)
        return hasher
