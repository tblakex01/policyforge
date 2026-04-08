"""AWS S3 sync provider."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, cast

from policyforge.sync.base import SyncProvider

logger = logging.getLogger(__name__)


class S3SyncProvider(SyncProvider):
    """Sync policies to/from an S3 bucket.

    Args:
        bucket: S3 bucket name.
        prefix: Key prefix for policy files (e.g., "policies/").
        region: AWS region. Defaults to boto3 session default.
        profile_name: Named AWS CLI profile (optional).
    """

    def __init__(
        self,
        bucket: str,
        prefix: str = "policies/",
        region: str | None = None,
        profile_name: str | None = None,
    ) -> None:
        try:
            import boto3
        except ImportError as exc:
            raise ImportError(
                "boto3 is required for S3 sync. Install with: " "pip install policyforge[aws]"
            ) from exc

        session_kwargs: dict[str, Any] = {}
        if region:
            session_kwargs["region_name"] = region
        if profile_name:
            session_kwargs["profile_name"] = profile_name

        session = boto3.Session(**session_kwargs)
        self._s3 = session.client("s3")
        self._bucket = bucket
        self._prefix = prefix.rstrip("/") + "/"

    @property
    def name(self) -> str:
        return f"aws-s3://{self._bucket}/{self._prefix}"

    def list_remote(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        paginator = self._s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=self._bucket, Prefix=self._prefix):
            for obj in page.get("Contents", []):
                key = obj["Key"]
                if key.endswith((".yaml", ".yml")):
                    head = self._head_object(key)
                    results.append(
                        {
                            "key": key,
                            "size": obj["Size"],
                            **self._content_hash_metadata(head, obj),
                        }
                    )
        return results

    def download(self, remote_key: str, local_path: Path) -> None:
        local_path.parent.mkdir(parents=True, exist_ok=True)
        self._s3.download_file(self._bucket, remote_key, str(local_path))
        logger.info("Downloaded s3://%s/%s → %s", self._bucket, remote_key, local_path)

    def upload(self, local_path: Path, remote_key: str) -> None:
        self._s3.upload_file(
            str(local_path),
            self._bucket,
            remote_key,
            ExtraArgs={
                "ChecksumAlgorithm": "SHA256",
                "Metadata": {
                    "policyforge-md5": SyncProvider.file_checksum(local_path, "md5-hex"),
                },
            },
        )
        logger.info("Uploaded %s → s3://%s/%s", local_path, self._bucket, remote_key)

    def _head_object(self, key: str) -> dict[str, Any]:
        try:
            return cast(
                dict[str, Any],
                self._s3.head_object(
                    Bucket=self._bucket,
                    Key=key,
                    ChecksumMode="ENABLED",
                ),
            )
        except Exception:
            return cast(dict[str, Any], self._s3.head_object(Bucket=self._bucket, Key=key))

    @staticmethod
    def _content_hash_metadata(head: dict[str, Any], obj: dict[str, Any]) -> dict[str, Any]:
        metadata = head.get("Metadata", {})
        if isinstance(metadata, dict):
            md5_hex = metadata.get("policyforge-md5")
            if isinstance(md5_hex, str) and md5_hex:
                return {
                    "content_hash": md5_hex,
                    "content_hash_algorithm": "md5-hex",
                }

        checksum_sha256 = head.get("ChecksumSHA256")
        if isinstance(checksum_sha256, str) and checksum_sha256:
            return {
                "content_hash": checksum_sha256,
                "content_hash_algorithm": "sha256-base64",
            }

        return {}
