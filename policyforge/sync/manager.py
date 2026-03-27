"""Sync manager — orchestrates pull/push across one or more cloud providers."""

from __future__ import annotations

import logging
import tempfile
from pathlib import Path
from typing import Any

from policyforge.sync.base import SyncProvider, SyncResult

logger = logging.getLogger(__name__)


class SyncManager:
    """Coordinate policy sync across multiple cloud providers.

    Typical usage:
        from policyforge.sync.s3 import S3SyncProvider
        from policyforge.sync.azure_blob import AzureBlobSyncProvider

        manager = SyncManager(local_dir="./policies")
        manager.add_provider(S3SyncProvider(bucket="my-policies"))
        manager.add_provider(AzureBlobSyncProvider(container="policies"))

        # Pull latest from all providers
        results = manager.pull()

        # Push local to all providers
        results = manager.push()

    Args:
        local_dir: Local directory where policies live.
    """

    def __init__(self, local_dir: str | Path) -> None:
        self._local_dir = Path(local_dir)
        self._local_dir.mkdir(parents=True, exist_ok=True)
        self._providers: list[SyncProvider] = []

    def add_provider(self, provider: SyncProvider) -> None:
        self._providers.append(provider)
        logger.info("Registered sync provider: %s", provider.name)

    def pull(self) -> list[SyncResult]:
        """Download policies from all providers, skipping unchanged files.

        Uses ETag/MD5 comparison to avoid re-downloading identical files.
        Returns one SyncResult per provider.
        """
        results: list[SyncResult] = []

        for provider in self._providers:
            downloaded = 0
            errors: list[str] = []

            try:
                remote_files = provider.list_remote()
            except Exception as exc:
                logger.error("Failed to list remote for %s: %s", provider.name, exc)
                results.append(SyncResult(
                    provider=provider.name, errors=(str(exc),), success=False
                ))
                continue

            for remote in remote_files:
                key: str = remote["key"]
                # Flatten remote prefix into local filename
                local_name = key.rsplit("/", 1)[-1]
                local_path = self._local_dir / local_name

                # Skip if local file matches remote ETag
                if local_path.exists():
                    local_hash = SyncProvider.file_md5(local_path)
                    if local_hash == remote.get("etag", ""):
                        logger.debug("Skipping unchanged: %s", key)
                        continue

                try:
                    provider.download(key, local_path)
                    downloaded += 1
                except Exception as exc:
                    msg = f"Failed to download {key}: {exc}"
                    logger.error(msg)
                    errors.append(msg)

            results.append(SyncResult(
                provider=provider.name,
                downloaded=downloaded,
                errors=tuple(errors),
                success=len(errors) == 0,
            ))

        return results

    def push(self) -> list[SyncResult]:
        """Upload local policies to all providers.

        Only uploads .yaml/.yml files from the local directory.
        Uses ETag comparison to skip unchanged files.
        """
        results: list[SyncResult] = []
        local_files = sorted(self._local_dir.glob("*.y*ml"))
        local_files = [f for f in local_files if f.suffix in (".yaml", ".yml")]

        for provider in self._providers:
            uploaded = 0
            errors: list[str] = []

            try:
                remote_files = {
                    r["key"].rsplit("/", 1)[-1]: r
                    for r in provider.list_remote()
                }
            except Exception as exc:
                logger.error("Failed to list remote for %s: %s", provider.name, exc)
                results.append(SyncResult(
                    provider=provider.name, errors=(str(exc),), success=False
                ))
                continue

            for local_path in local_files:
                local_hash = SyncProvider.file_md5(local_path)
                remote_meta = remote_files.get(local_path.name)

                if remote_meta and remote_meta.get("etag") == local_hash:
                    logger.debug("Skipping unchanged: %s", local_path.name)
                    continue

                # Construct remote key using provider's prefix convention
                remote_key = self._infer_remote_key(provider, local_path.name)
                try:
                    provider.upload(local_path, remote_key)
                    uploaded += 1
                except Exception as exc:
                    msg = f"Failed to upload {local_path.name}: {exc}"
                    logger.error(msg)
                    errors.append(msg)

            results.append(SyncResult(
                provider=provider.name,
                uploaded=uploaded,
                errors=tuple(errors),
                success=len(errors) == 0,
            ))

        return results

    @staticmethod
    def _infer_remote_key(provider: SyncProvider, filename: str) -> str:
        """Reconstruct the remote key from the provider's name pattern."""
        # Provider names follow pattern: "type://container/prefix/"
        name = provider.name
        if "://" in name:
            _, rest = name.split("://", 1)
            # rest is like "bucket/prefix/"
            parts = rest.split("/", 1)
            prefix = parts[1] if len(parts) > 1 else ""
            return f"{prefix}{filename}"
        return filename
