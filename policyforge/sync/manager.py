"""Sync manager — orchestrates pull/push across one or more cloud providers."""

from __future__ import annotations

import logging
import tempfile
from pathlib import Path

from policyforge.sync._local import LocalPolicyStore
from policyforge.sync.base import MAX_POLICY_BYTES, SyncProvider, SyncResult

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
        self._store = LocalPolicyStore(self._local_dir)
        self._local_dir = self._store.root
        self._providers: list[SyncProvider] = []

    def add_provider(self, provider: SyncProvider) -> None:
        self._providers.append(provider)
        logger.info("Registered sync provider: %s", provider.name)

    def pull(self) -> list[SyncResult]:
        """Download policies from all providers, skipping unchanged files.

        Uses provider-supplied content hashes when available to avoid
        re-downloading identical files.
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
                results.append(
                    SyncResult(provider=provider.name, errors=(str(exc),), success=False)
                )
                continue

            for remote in remote_files:
                key: str = remote["key"]
                try:
                    local_relative_path = provider.local_relative_path_for(key)
                except ValueError as exc:
                    msg = f"Unsafe remote key {key}: {exc}"
                    logger.error(msg)
                    errors.append(msg)
                    continue

                try:
                    size = remote.get("size")
                    if isinstance(size, bool) or not isinstance(size, int) or size < 0:
                        raise ValueError("Remote policy size is missing or invalid")
                    if size > MAX_POLICY_BYTES:
                        raise ValueError("Remote policy size exceeds maximum")

                    self._store.validate(local_relative_path)
                    local_path = self._local_dir / local_relative_path
                    with tempfile.TemporaryDirectory(prefix="policyforge-pull-") as staging:
                        stage_dir = Path(staging)
                        if local_path.exists():
                            existing = self._store.snapshot(
                                local_relative_path, stage_dir / "existing.yaml"
                            )
                            if self._matches_local_checksum(provider, existing, remote, errors):
                                logger.debug("Skipping unchanged: %s", key)
                                continue

                        downloaded_path = stage_dir / "downloaded.yaml"
                        provider.download(key, downloaded_path)
                        if downloaded_path.stat().st_size > MAX_POLICY_BYTES:
                            raise ValueError("Downloaded policy size exceeds maximum")
                        self._store.install(local_relative_path, downloaded_path)
                    downloaded += 1
                except Exception as exc:
                    msg = f"Failed to download {key}: {exc}"
                    logger.error(msg)
                    errors.append(msg)

            results.append(
                SyncResult(
                    provider=provider.name,
                    downloaded=downloaded,
                    errors=tuple(errors),
                    success=len(errors) == 0,
                )
            )

        return results

    def push(self) -> list[SyncResult]:
        """Upload local policies to all providers.

        Only uploads .yaml/.yml files from the local directory.
        Uses provider-supplied content hashes when available to skip unchanged files.
        """
        results: list[SyncResult] = []
        local_files = sorted(self._local_dir.rglob("*.y*ml"))
        local_files = [f for f in local_files if f.suffix in (".yaml", ".yml")]

        for provider in self._providers:
            uploaded = 0
            errors: list[str] = []

            try:
                remote_files = {
                    str(provider.local_relative_path_for(r["key"]).as_posix()): r
                    for r in provider.list_remote()
                }
            except Exception as exc:
                logger.error("Failed to list remote for %s: %s", provider.name, exc)
                results.append(
                    SyncResult(provider=provider.name, errors=(str(exc),), success=False)
                )
                continue

            for local_path in local_files:
                relative_path = local_path.relative_to(self._local_dir)
                relative_key = relative_path.as_posix()
                remote_meta = remote_files.get(relative_key)

                try:
                    with tempfile.TemporaryDirectory(prefix="policyforge-push-") as staging:
                        staged = self._store.snapshot(relative_path, Path(staging) / "policy.yaml")
                        if self._matches_local_checksum(provider, staged, remote_meta, errors):
                            logger.debug("Skipping unchanged: %s", relative_key)
                            continue

                        # Construct remote key using provider's own prefix logic.
                        remote_key = provider.remote_key_for(relative_key)
                        provider.upload(staged, remote_key)
                    uploaded += 1
                except Exception as exc:
                    msg = f"Failed to upload {relative_key}: {exc}"
                    logger.error(msg)
                    errors.append(msg)

            results.append(
                SyncResult(
                    provider=provider.name,
                    uploaded=uploaded,
                    errors=tuple(errors),
                    success=len(errors) == 0,
                )
            )

        return results

    @staticmethod
    def _matches_local_checksum(
        provider: SyncProvider,
        local_path: Path,
        remote_meta: dict[str, object] | None,
        errors: list[str],
    ) -> bool:
        """Return True when provider metadata proves the local file is unchanged."""
        remote_digest = provider.comparable_remote_digest(remote_meta)
        if remote_digest is None:
            return False

        try:
            return (
                SyncProvider.file_checksum(local_path, remote_digest.algorithm)
                == remote_digest.value
            )
        except ValueError as exc:
            msg = (
                f"Unsupported checksum algorithm '{remote_digest.algorithm}' for "
                f"{provider.name}: {exc}"
            )
            logger.error(msg)
            errors.append(msg)
            return False
