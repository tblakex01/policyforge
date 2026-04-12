"""Tests for provider-specific checksum metadata, path safety, and download/upload."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from policyforge.sync.azure_blob import AzureBlobSyncProvider
from policyforge.sync.base import ComparableDigest, SyncProvider
from policyforge.sync.oci_os import OCISyncProvider
from policyforge.sync.s3 import S3SyncProvider


class FakeS3Paginator:
    def paginate(self, **_: object):
        yield {
            "Contents": [
                {"Key": "policies/a.yaml", "ETag": '"etag-value"', "Size": 1},
                {"Key": "policies/b.yaml", "ETag": '"multipart-etag-2"', "Size": 1},
            ]
        }


class FakeS3Client:
    def get_paginator(self, _: str) -> FakeS3Paginator:
        return FakeS3Paginator()

    def head_object(self, **kwargs: object):
        key = kwargs["Key"]
        if key == "policies/a.yaml":
            return {
                "Metadata": {"policyforge-md5": "abc123"},
                "ChecksumSHA256": "sha256-value",
            }
        return {}


class FakeBlobClient:
    def __init__(self, properties: object) -> None:
        self._properties = properties

    def get_blob_properties(self) -> object:
        return self._properties


class FakeAzureClient:
    def __init__(self, properties_by_name: dict[str, object]) -> None:
        self._properties_by_name = properties_by_name

    def list_blobs(self, **_: object):
        return [
            SimpleNamespace(name="policies/a.yaml", size=1),
            SimpleNamespace(name="policies/b.yaml", size=1),
        ]

    def get_blob_client(self, name: str) -> FakeBlobClient:
        return FakeBlobClient(self._properties_by_name[name])


class FakeOCIClient:
    def list_objects(self, **_: object):
        return SimpleNamespace(
            data=SimpleNamespace(
                objects=[
                    SimpleNamespace(name="policies/a.yaml", size=1, md5="base64-md5"),
                ],
                next_start_with=None,
            )
        )


class TestSyncProviderChecksums:
    def test_file_checksum_supports_multiple_algorithms(self, tmp_path):
        policy = tmp_path / "policy.yaml"
        policy.write_text("name: x\n", encoding="utf-8")

        assert SyncProvider.file_checksum(policy, "md5-hex")
        assert SyncProvider.file_checksum(policy, "md5-base64")
        assert SyncProvider.file_checksum(policy, "sha256-base64")

    def test_s3_list_remote_prefers_policyforge_md5_metadata(self):
        provider = S3SyncProvider.__new__(S3SyncProvider)
        provider._prefix = "policies/"
        provider._bucket = "bucket"
        provider._s3 = FakeS3Client()

        remote_files = provider.list_remote()

        assert remote_files[0]["content_hash"] == "abc123"
        assert remote_files[0]["content_hash_algorithm"] == "md5-hex"
        assert "content_hash" not in remote_files[1]

    def test_azure_list_remote_uses_content_md5_when_present(self):
        provider = AzureBlobSyncProvider.__new__(AzureBlobSyncProvider)
        provider._prefix = "policies/"
        provider._container = "policies"
        provider._client = FakeAzureClient(
            {
                "policies/a.yaml": SimpleNamespace(
                    content_settings=SimpleNamespace(
                        content_md5=bytes.fromhex("00112233445566778899aabbccddeeff")
                    ),
                    metadata={},
                ),
                "policies/b.yaml": SimpleNamespace(
                    content_settings=SimpleNamespace(content_md5=None),
                    metadata={"policyforge-md5": "deadbeef"},
                ),
            }
        )

        remote_files = provider.list_remote()

        assert remote_files[0]["content_hash_algorithm"] == "md5-base64"
        assert remote_files[1]["content_hash"] == "deadbeef"
        assert remote_files[1]["content_hash_algorithm"] == "md5-hex"

    def test_oci_list_remote_reports_base64_md5(self):
        provider = OCISyncProvider.__new__(OCISyncProvider)
        provider._prefix = "policies/"
        provider._namespace = "namespace"
        provider._bucket = "bucket"
        provider._client = FakeOCIClient()

        remote_files = provider.list_remote()

        assert remote_files == [
            {
                "key": "policies/a.yaml",
                "size": 1,
                "content_hash": "base64-md5",
                "content_hash_algorithm": "md5-base64",
            }
        ]

    def test_comparable_remote_digest_uses_algorithm_hint(self):
        provider = S3SyncProvider.__new__(S3SyncProvider)

        digest = provider.comparable_remote_digest(
            {
                "content_hash": "ABC123",
                "content_hash_algorithm": "md5-hex",
            }
        )

        assert digest == ComparableDigest(algorithm="md5-hex", value="abc123")

    def test_comparable_remote_digest_returns_none_for_missing_hash(self):
        provider = S3SyncProvider.__new__(S3SyncProvider)
        assert provider.comparable_remote_digest(None) is None
        assert provider.comparable_remote_digest({}) is None
        assert provider.comparable_remote_digest({"content_hash": ""}) is None

    def test_file_md5_backward_compat(self, tmp_path):
        policy = tmp_path / "p.yaml"
        policy.write_text("name: x\n", encoding="utf-8")
        assert SyncProvider.file_md5(policy) == SyncProvider.file_checksum(policy, "md5-hex")

    def test_unsupported_algorithm_raises(self, tmp_path):
        policy = tmp_path / "p.yaml"
        policy.write_text("name: x\n", encoding="utf-8")
        with pytest.raises(ValueError, match="Unsupported checksum"):
            SyncProvider.file_checksum(policy, "sha512-hex")


class TestPathTraversalSecurity:
    """Security tests for local_relative_path_for — prevents arbitrary file overwrites."""

    @pytest.fixture
    def provider(self):
        p = S3SyncProvider.__new__(S3SyncProvider)
        p._prefix = "policies/"
        return p

    def test_rejects_absolute_path(self, provider):
        with pytest.raises(ValueError, match="Unsafe remote key"):
            provider.local_relative_path_for("/etc/passwd")

    def test_rejects_dot_dot_traversal(self, provider):
        with pytest.raises(ValueError, match="Unsafe remote key"):
            provider.local_relative_path_for("policies/../../../etc/passwd")

    def test_rejects_single_dot(self, provider):
        with pytest.raises(ValueError, match="Unsafe remote key"):
            provider.local_relative_path_for("policies/.")

    def test_rejects_backslash_traversal(self, provider):
        with pytest.raises(ValueError, match="Unsafe remote key"):
            provider.local_relative_path_for("policies\\..\\..\\etc\\passwd")

    def test_accepts_valid_nested_key(self, provider):
        result = provider.local_relative_path_for("policies/team-a/policy.yaml")
        assert result == Path("team-a") / "policy.yaml"

    def test_accepts_key_without_prefix(self, provider):
        result = provider.local_relative_path_for("other/path.yaml")
        assert result == Path("other") / "path.yaml"

    @pytest.mark.parametrize(
        "key",
        [
            "policies/../etc/shadow",
            "/absolute/path.yaml",
            "policies\\..\\windows.yaml",
            "policies/..",
        ],
    )
    def test_rejects_unsafe_keys_parametrized(self, provider, key):
        with pytest.raises(ValueError, match="Unsafe remote key"):
            provider.local_relative_path_for(key)


class TestS3DownloadUpload:
    def test_download_writes_to_local_file(self, tmp_path):
        provider = S3SyncProvider.__new__(S3SyncProvider)
        provider._bucket = "test-bucket"

        downloads = []

        def fake_download_file(bucket, key, path):
            downloads.append((bucket, key, path))
            Path(path).write_text("downloaded content", encoding="utf-8")

        provider._s3 = SimpleNamespace(download_file=fake_download_file)

        local_path = tmp_path / "sub" / "policy.yaml"
        provider.download("policies/sub/policy.yaml", local_path)

        assert local_path.exists()
        assert downloads == [("test-bucket", "policies/sub/policy.yaml", str(local_path))]

    def test_upload_sends_file_with_checksum(self, tmp_path):
        provider = S3SyncProvider.__new__(S3SyncProvider)
        provider._bucket = "test-bucket"

        uploads = []

        def fake_upload_file(path, bucket, key, ExtraArgs=None):
            uploads.append((path, bucket, key, ExtraArgs))

        provider._s3 = SimpleNamespace(upload_file=fake_upload_file)

        local_file = tmp_path / "policy.yaml"
        local_file.write_text("name: test\n", encoding="utf-8")
        provider.upload(local_file, "policies/policy.yaml")

        assert len(uploads) == 1
        assert uploads[0][1] == "test-bucket"
        assert uploads[0][2] == "policies/policy.yaml"
        assert "ChecksumAlgorithm" in uploads[0][3]

    def test_head_object_fallback_on_checksum_error(self):
        provider = S3SyncProvider.__new__(S3SyncProvider)
        provider._bucket = "bucket"

        call_log = []

        def fake_head_object(**kwargs):
            call_log.append(kwargs)
            if "ChecksumMode" in kwargs:
                raise Exception("ChecksumMode not supported")
            return {"Metadata": {}}

        provider._s3 = SimpleNamespace(head_object=fake_head_object)
        result = provider._head_object("some-key")
        assert len(call_log) == 2  # first call with ChecksumMode, retry without
        assert result == {"Metadata": {}}


class TestAzureDownloadUpload:
    def test_download_writes_blob_content(self, tmp_path):
        provider = AzureBlobSyncProvider.__new__(AzureBlobSyncProvider)
        provider._container = "policies"

        blob_content = b"name: azure-policy\n"

        class FakeStream:
            def readall(self):
                return blob_content

        class FakeBlobDl:
            def download_blob(self):
                return FakeStream()

        class FakeClient:
            def get_blob_client(self, key):
                return FakeBlobDl()

        provider._client = FakeClient()
        local_path = tmp_path / "nested" / "policy.yaml"
        provider.download("policies/nested/policy.yaml", local_path)

        assert local_path.read_bytes() == blob_content

    def test_upload_sends_blob_with_md5(self, tmp_path):
        provider = AzureBlobSyncProvider.__new__(AzureBlobSyncProvider)
        provider._container = "policies"
        provider._content_settings_cls = lambda content_md5=None: SimpleNamespace(
            content_md5=content_md5
        )

        uploads = []

        class FakeBlobUp:
            def upload_blob(self, data, overwrite=False, content_settings=None, metadata=None):
                uploads.append(
                    {"overwrite": overwrite, "metadata": metadata, "has_data": data is not None}
                )

        class FakeClient:
            def get_blob_client(self, key):
                return FakeBlobUp()

        provider._client = FakeClient()
        local_file = tmp_path / "policy.yaml"
        local_file.write_text("name: azure\n", encoding="utf-8")

        provider.upload(local_file, "policies/policy.yaml")

        assert len(uploads) == 1
        assert uploads[0]["overwrite"] is True
        assert "policyforge-md5" in uploads[0]["metadata"]


class TestOCIDownloadUpload:
    def test_download_streams_to_local_file(self, tmp_path):
        provider = OCISyncProvider.__new__(OCISyncProvider)
        provider._namespace = "ns"
        provider._bucket = "bucket"

        class FakeRaw:
            def stream(self, chunk_size, decode_content=False):
                yield b"name: oci-policy\n"

        class FakeResponse:
            data = SimpleNamespace(raw=FakeRaw())

        class FakeClient:
            def get_object(self, **kwargs):
                return FakeResponse()

        provider._client = FakeClient()
        local_path = tmp_path / "deep" / "policy.yaml"
        provider.download("policies/deep/policy.yaml", local_path)

        assert local_path.read_bytes() == b"name: oci-policy\n"

    def test_upload_puts_object(self, tmp_path):
        provider = OCISyncProvider.__new__(OCISyncProvider)
        provider._namespace = "ns"
        provider._bucket = "bucket"

        puts = []

        class FakeClient:
            def put_object(self, **kwargs):
                puts.append(kwargs)

        provider._client = FakeClient()
        local_file = tmp_path / "policy.yaml"
        local_file.write_text("name: oci\n", encoding="utf-8")

        provider.upload(local_file, "policies/policy.yaml")

        assert len(puts) == 1
        assert puts[0]["namespace_name"] == "ns"
        assert puts[0]["object_name"] == "policies/policy.yaml"

    def test_list_remote_handles_pagination(self):
        provider = OCISyncProvider.__new__(OCISyncProvider)
        provider._namespace = "ns"
        provider._bucket = "bucket"
        provider._prefix = "policies/"

        call_count = [0]

        class FakeClient:
            def list_objects(self, **kwargs):
                call_count[0] += 1
                if call_count[0] == 1:
                    return SimpleNamespace(
                        data=SimpleNamespace(
                            objects=[
                                SimpleNamespace(name="policies/a.yaml", size=10, md5="md5a"),
                            ],
                            next_start_with="policies/b.yaml",
                        )
                    )
                return SimpleNamespace(
                    data=SimpleNamespace(
                        objects=[
                            SimpleNamespace(name="policies/b.yaml", size=20, md5="md5b"),
                        ],
                        next_start_with=None,
                    )
                )

        provider._client = FakeClient()
        results = provider.list_remote()

        assert len(results) == 2
        assert results[0]["key"] == "policies/a.yaml"
        assert results[1]["key"] == "policies/b.yaml"
        assert call_count[0] == 2
