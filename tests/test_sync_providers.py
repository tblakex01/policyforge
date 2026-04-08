"""Tests for provider-specific checksum metadata."""

from __future__ import annotations

from types import SimpleNamespace

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
