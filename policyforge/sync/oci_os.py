"""Oracle Cloud Infrastructure Object Storage sync provider."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from policyforge.sync.base import SyncProvider

logger = logging.getLogger(__name__)


class OCISyncProvider(SyncProvider):
    """Sync policies to/from OCI Object Storage.

    Auth uses the OCI SDK config file (~/.oci/config) by default.

    Args:
        namespace: OCI Object Storage namespace.
        bucket: Bucket name.
        prefix: Object name prefix for policy files.
        config_profile: OCI config profile name (default: "DEFAULT").
        config_path: Path to OCI config file (default: ~/.oci/config).
    """

    def __init__(
        self,
        namespace: str,
        bucket: str,
        prefix: str = "policies/",
        config_profile: str = "DEFAULT",
        config_path: str = "~/.oci/config",
    ) -> None:
        try:
            import oci
        except ImportError as exc:
            raise ImportError(
                "oci is required for OCI Object Storage sync. Install with: "
                "pip install policyforge[oci]"
            ) from exc

        config = oci.config.from_file(file_location=config_path, profile_name=config_profile)
        self._client = oci.object_storage.ObjectStorageClient(config)
        self._namespace = namespace
        self._bucket = bucket
        self._prefix = prefix.rstrip("/") + "/"

    @property
    def name(self) -> str:
        return f"oci-os://{self._namespace}/{self._bucket}/{self._prefix}"

    def list_remote(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        next_start = None

        while True:
            kwargs: dict[str, Any] = {
                "namespace_name": self._namespace,
                "bucket_name": self._bucket,
                "prefix": self._prefix,
                "fields": "name,size,md5",
            }
            if next_start:
                kwargs["start"] = next_start

            response = self._client.list_objects(**kwargs)
            for obj in response.data.objects:
                if obj.name.endswith((".yaml", ".yml")):
                    results.append(
                        {
                            "key": obj.name,
                            "size": obj.size or 0,
                            "content_hash": obj.md5 or "",
                            "content_hash_algorithm": "md5-base64",
                        }
                    )

            next_start = response.data.next_start_with
            if not next_start:
                break

        return results

    def download(self, remote_key: str, local_path: Path) -> None:
        local_path.parent.mkdir(parents=True, exist_ok=True)
        response = self._client.get_object(
            namespace_name=self._namespace,
            bucket_name=self._bucket,
            object_name=remote_key,
        )
        with open(local_path, "wb") as fh:
            for chunk in response.data.raw.stream(8192, decode_content=False):
                fh.write(chunk)
        logger.info(
            "Downloaded oci://%s/%s/%s → %s",
            self._namespace,
            self._bucket,
            remote_key,
            local_path,
        )

    def upload(self, local_path: Path, remote_key: str) -> None:
        with open(local_path, "rb") as fh:
            self._client.put_object(
                namespace_name=self._namespace,
                bucket_name=self._bucket,
                object_name=remote_key,
                put_object_body=fh,
            )
        logger.info(
            "Uploaded %s → oci://%s/%s/%s",
            local_path,
            self._namespace,
            self._bucket,
            remote_key,
        )
