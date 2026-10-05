"""Tests for sync manager path handling and change detection."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from policyforge.sync.base import SyncProvider
from policyforge.sync.manager import SyncManager


class FakeSyncProvider(SyncProvider):
    """In-memory sync provider for manager tests."""

    def __init__(self, remote_files: list[dict[str, Any]]) -> None:
        self._prefix = "policies/"
        self._remote_files = remote_files
        self.download_calls: list[tuple[str, Path]] = []
        self.upload_calls: list[tuple[Path, str]] = []
        self.uploaded_contents: list[str] = []

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
        self.uploaded_contents.append(local_path.read_text(encoding="utf-8"))


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
        assert [key for _, key in provider.upload_calls] == ["policies/team-a/policy.yaml"]
        assert provider.uploaded_contents == ["name: nested\n"]

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
        assert [key for _, key in provider.upload_calls] == ["policies/team-a/policy.yaml"]
        assert provider.uploaded_contents == ["name: nested\n"]

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
        assert [key for key, _ in provider.download_calls] == ["policies/team-a/policy.yaml"]
        assert local_policy.read_text(encoding="utf-8") == (
            "downloaded:policies/team-a/policy.yaml"
        )


class FailingListProvider(FakeSyncProvider):
    """Provider whose list_remote raises."""

    def list_remote(self) -> list[dict[str, Any]]:
        raise ConnectionError("Network unreachable")


class FailingDownloadProvider(FakeSyncProvider):
    """Provider whose download raises."""

    def download(self, remote_key: str, local_path: Path) -> None:
        raise OSError(f"Download failed: {remote_key}")


class FailingUploadProvider(FakeSyncProvider):
    """Provider whose upload raises."""

    def upload(self, local_path: Path, remote_key: str) -> None:
        raise OSError(f"Upload failed: {remote_key}")


class UnsafeKeyProvider(FakeSyncProvider):
    """Provider that returns an unsafe key from list_remote."""

    def __init__(self) -> None:
        super().__init__([{"key": "/etc/passwd", "size": 100}])


class TestSyncManagerFailures:
    @staticmethod
    def _make_link(link: Path, target: Path, *, is_directory: bool = False) -> None:
        try:
            link.symlink_to(target, target_is_directory=is_directory)
        except (OSError, NotImplementedError) as exc:
            pytest.skip(f"Links unavailable on this host: {exc}")

    def test_pull_rejects_linked_parent_outside_local_dir(self, tmp_path):
        root = tmp_path / "local"
        outside = tmp_path / "outside"
        outside.mkdir()
        target = outside / "policy.yaml"
        target.write_text("original", encoding="utf-8")
        root.mkdir()
        self._make_link(root / "linked", outside, is_directory=True)
        provider = FakeSyncProvider([{"key": "policies/linked/policy.yaml", "size": 12}])
        manager = SyncManager(local_dir=root)
        manager.add_provider(provider)

        result = manager.pull()[0]

        assert result.success is False
        assert result.downloaded == 0
        assert provider.download_calls == []
        assert target.read_text(encoding="utf-8") == "original"

    def test_pull_rejects_linked_leaf_before_checksum(self, tmp_path):
        root = tmp_path / "local"
        root.mkdir()
        target = tmp_path / "outside.yaml"
        target.write_text("original", encoding="utf-8")
        self._make_link(root / "policy.yaml", target)
        provider = FakeSyncProvider(
            [
                {
                    "key": "policies/policy.yaml",
                    "size": 8,
                    "content_hash": SyncProvider.file_checksum(target, "md5-hex"),
                    "content_hash_algorithm": "md5-hex",
                }
            ]
        )
        manager = SyncManager(local_dir=root)
        manager.add_provider(provider)

        result = manager.pull()[0]

        assert result.success is False
        assert result.downloaded == 0
        assert "Unsafe local path" in result.errors[0]

    def test_pull_rejects_dangling_leaf_link(self, tmp_path):
        root = tmp_path / "local"
        root.mkdir()
        self._make_link(root / "policy.yaml", tmp_path / "missing.yaml")
        provider = FakeSyncProvider([{"key": "policies/policy.yaml", "size": 5}])
        manager = SyncManager(local_dir=root)
        manager.add_provider(provider)

        result = manager.pull()[0]

        assert result.success is False
        assert result.downloaded == 0
        assert provider.download_calls == []

    def test_push_rejects_yaml_symlink_outside_local_dir(self, tmp_path):
        root = tmp_path / "local"
        root.mkdir()
        target = tmp_path / "outside.yaml"
        target.write_text("secret", encoding="utf-8")
        self._make_link(root / "linked.yaml", target)
        provider = FakeSyncProvider([])
        manager = SyncManager(local_dir=root)
        manager.add_provider(provider)

        result = manager.push()[0]

        assert result.success is False
        assert result.uploaded == 0
        assert provider.upload_calls == []

    def test_push_rejects_link_swapped_at_open(self, tmp_path, monkeypatch):
        root = tmp_path / "local"
        root.mkdir()
        policy = root / "policy.yaml"
        policy.write_text("name: safe\n", encoding="utf-8")
        outside = tmp_path / "outside.yaml"
        outside.write_text("secret", encoding="utf-8")
        provider = FakeSyncProvider([])
        manager = SyncManager(local_dir=root)
        manager.add_provider(provider)

        from policyforge.sync import _local

        real_open = _local.os.open
        swapped = False

        def swap_before_open(path, flags, mode=0o777):
            nonlocal swapped
            if Path(path) == policy and not swapped:
                swapped = True
                policy.unlink()
                self._make_link(policy, outside)
            return real_open(path, flags, mode)

        monkeypatch.setattr(_local.os, "open", swap_before_open)
        result = manager.push()[0]

        assert swapped
        assert result.success is False
        assert result.uploaded == 0
        assert provider.upload_calls == []
        assert outside.read_text(encoding="utf-8") == "secret"

    def test_pull_rejects_oversized_listed_object(self, tmp_path):
        provider = FakeSyncProvider([{"key": "policies/large.yaml", "size": 11 * 1024 * 1024}])
        manager = SyncManager(local_dir=tmp_path)
        manager.add_provider(provider)

        result = manager.pull()[0]

        assert result.success is False
        assert result.downloaded == 0
        assert provider.download_calls == []
        assert "size" in result.errors[0].lower()

    def test_pull_handles_list_remote_failure(self, tmp_path):
        provider = FailingListProvider([])
        manager = SyncManager(local_dir=tmp_path)
        manager.add_provider(provider)

        results = manager.pull()

        assert len(results) == 1
        assert results[0].success is False
        assert "Network unreachable" in results[0].errors[0]

    def test_pull_handles_download_failure(self, tmp_path):
        provider = FailingDownloadProvider([{"key": "policies/policy.yaml", "size": 1}])
        manager = SyncManager(local_dir=tmp_path)
        manager.add_provider(provider)

        results = manager.pull()

        assert results[0].success is False
        assert any("Download failed" in e for e in results[0].errors)

    def test_pull_handles_unsafe_remote_key(self, tmp_path):
        provider = UnsafeKeyProvider()
        manager = SyncManager(local_dir=tmp_path)
        manager.add_provider(provider)

        results = manager.pull()

        assert results[0].success is False
        assert any("Unsafe" in e for e in results[0].errors)

    def test_pull_rejects_prefix_stripped_absolute_remote_key(self, tmp_path):
        provider = FakeSyncProvider([{"key": "policies//tmp/escape.yaml", "size": 1}])
        manager = SyncManager(local_dir=tmp_path)
        manager.add_provider(provider)

        results = manager.pull()

        assert results[0].success is False
        assert any("Unsafe" in e for e in results[0].errors)
        assert provider.download_calls == []

    def test_pull_rejects_windows_drive_qualified_remote_key(self, tmp_path):
        provider = FakeSyncProvider([{"key": "policies/D:/escape/policy.yaml", "size": 1}])
        manager = SyncManager(local_dir=tmp_path)
        manager.add_provider(provider)

        results = manager.pull()

        assert results[0].success is False
        assert any("Unsafe" in e for e in results[0].errors)
        assert provider.download_calls == []

    def test_push_handles_list_remote_failure(self, tmp_path):
        provider = FailingListProvider([])
        manager = SyncManager(local_dir=tmp_path)
        manager.add_provider(provider)

        policy = tmp_path / "policy.yaml"
        policy.write_text("name: test\n", encoding="utf-8")

        results = manager.push()

        assert len(results) == 1
        assert results[0].success is False
        assert "Network unreachable" in results[0].errors[0]

    def test_push_handles_upload_failure(self, tmp_path):
        provider = FailingUploadProvider([])
        manager = SyncManager(local_dir=tmp_path)
        manager.add_provider(provider)

        policy = tmp_path / "policy.yaml"
        policy.write_text("name: test\n", encoding="utf-8")

        results = manager.push()

        assert results[0].success is False
        assert any("Upload failed" in e for e in results[0].errors)
