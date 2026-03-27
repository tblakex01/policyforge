"""Abstract base for cloud sync providers."""

from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class SyncResult:
    """Outcome of a sync operation."""

    provider: str
    downloaded: int = 0
    uploaded: int = 0
    errors: tuple[str, ...] = ()
    success: bool = True


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
          - "etag": str — content hash for change detection
          - "size": int — bytes
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
        return f"{self._prefix}{filename}"

    @staticmethod
    def file_md5(path: Path) -> str:
        """Compute MD5 hex digest of a local file for ETag comparison."""
        h = hashlib.md5()  # noqa: S324 — used only for ETag matching, not security
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
