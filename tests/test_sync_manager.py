"""Tests for sync manager path handling and change detection."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from policyforge.sync.base import SyncProvider
from policyforge.sync.manager import SyncManager


class FakeSyncProvider(SyncProvider):
    """In-memory sync provider for manager tests."""

    def __init__(self, remote_files: list[dict[str, Any]]) -> None:
        self._prefix = "policies/"
        self._remote_files = remote_files
        self.download_calls: list[tuple[str, Path]] = []
        self.upload_calls: list[tuple[Path, str]] = []

    @property
    def name(self) -> str:
        return "fake-sync"

    def list_remote(self) -> list[dict[str, Any]]:
        return list(self._remote_files)

    def download(self, remote_key: str, local_path: Path) -> None:
        local_path.parent.mkdir(parents=True, exist_ok=True)
        local_path.write_text(f"downloaded:{remote_key}", encoding="utf-8")
        self.download_calls.append((remote_key, local_path))

    def upload(self, local_path: Path, remote_key: str) -> None:
        self.upload_calls.append((local_path, remote_key))


class TestSyncManagerPaths:
    def test_pull_preserves_remote_relative_paths(self, tmp_path):
        provider = FakeSyncProvider(
            [
                {"key": "policies/team-a/policy.yaml", "size": 1},
                {"key": "policies/team-b/policy.yaml", "size": 1},
            ]
        )
        manager = SyncManager(local_dir=tmp_path)
        manager.add_provider(provider)

        results = manager.pull()

        assert results[0].downloaded == 2
        assert (tmp_path / "team-a" / "policy.yaml").read_text(encoding="utf-8") == (
            "downloaded:policies/team-a/policy.yaml"
        )
        assert (tmp_path / "team-b" / "policy.yaml").read_text(encoding="utf-8") == (
            "downloaded:policies/team-b/policy.yaml"
        )

    def test_push_uses_nested_relative_paths(self, tmp_path):
        provider = FakeSyncProvider([])
        manager = SyncManager(local_dir=tmp_path)
        manager.add_provider(provider)

        nested_policy = tmp_path / "team-a" / "policy.yaml"
        nested_policy.parent.mkdir(parents=True)
        nested_policy.write_text("name: nested\n", encoding="utf-8")

        results = manager.push()

        assert results[0].uploaded == 1
        assert provider.upload_calls == [
            (nested_policy, "policies/team-a/policy.yaml"),
        ]

    def test_pull_skips_when_remote_md5_base64_matches(self, tmp_path):
        local_policy = tmp_path / "team-a" / "policy.yaml"
        local_policy.parent.mkdir(parents=True)
        local_policy.write_text("name: team-a\n", encoding="utf-8")

        provider = FakeSyncProvider(
            [
                {
                    "key": "policies/team-a/policy.yaml",
                    "size": 1,
                    "content_hash": SyncProvider.file_checksum(local_policy, "md5-base64"),
                    "content_hash_algorithm": "md5-base64",
                }
            ]
        )
        manager = SyncManager(local_dir=tmp_path)
        manager.add_provider(provider)

        results = manager.pull()

        assert results[0].downloaded == 0
        assert provider.download_calls == []

    def test_push_skips_when_remote_sha256_matches(self, tmp_path):
        provider = FakeSyncProvider(
            [
                {
                    "key": "policies/team-a/policy.yaml",
                    "size": 1,
                    "content_hash": None,
                    "content_hash_algorithm": "sha256-base64",
                }
            ]
        )
        manager = SyncManager(local_dir=tmp_path)
        manager.add_provider(provider)

        nested_policy = tmp_path / "team-a" / "policy.yaml"
        nested_policy.parent.mkdir(parents=True)
        nested_policy.write_text("name: nested\n", encoding="utf-8")
        provider._remote_files[0]["content_hash"] = SyncProvider.file_checksum(
            nested_policy,
            "sha256-base64",
        )

        results = manager.push()

        assert results[0].uploaded == 0
        assert provider.upload_calls == []

    def test_push_reports_unsupported_remote_digest_and_continues(self, tmp_path):
        provider = FakeSyncProvider(
            [
                {
                    "key": "policies/team-a/policy.yaml",
                    "size": 1,
                    "content_hash": "value",
                    "content_hash_algorithm": "sha512-hex",
                }
            ]
        )
        manager = SyncManager(local_dir=tmp_path)
        manager.add_provider(provider)

        nested_policy = tmp_path / "team-a" / "policy.yaml"
        nested_policy.parent.mkdir(parents=True)
        nested_policy.write_text("name: nested\n", encoding="utf-8")

        results = manager.push()

        assert results[0].uploaded == 1
        assert results[0].success is False
        assert "Unsupported checksum algorithm" in results[0].errors[0]
        assert provider.upload_calls == [
            (nested_policy, "policies/team-a/policy.yaml"),
        ]

    def test_pull_reports_unsupported_remote_digest_and_continues(self, tmp_path):
        local_policy = tmp_path / "team-a" / "policy.yaml"
        local_policy.parent.mkdir(parents=True)
        local_policy.write_text("name: team-a\n", encoding="utf-8")

        provider = FakeSyncProvider(
            [
                {
                    "key": "policies/team-a/policy.yaml",
                    "size": 1,
                    "content_hash": "value",
                    "content_hash_algorithm": "sha512-hex",
                }
            ]
        )
        manager = SyncManager(local_dir=tmp_path)
        manager.add_provider(provider)

        results = manager.pull()

        assert results[0].downloaded == 1
        assert results[0].success is False
        assert "Unsupported checksum algorithm" in results[0].errors[0]
        assert provider.download_calls == [
            ("policies/team-a/policy.yaml", local_policy),
        ]
