"""Azure Blob Storage sync provider."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from policyforge.sync.base import SyncProvider

logger = logging.getLogger(__name__)


class AzureBlobSyncProvider(SyncProvider):
    """Sync policies to/from an Azure Blob Storage container.

    Auth follows the azure-identity DefaultAzureCredential chain unless
    a connection_string is provided explicitly.

    Args:
        container: Blob container name.
        prefix: Virtual directory prefix for policy blobs.
        connection_string: Full connection string (optional — falls back
                           to DefaultAzureCredential).
        account_url: Storage account URL (required if no connection_string).
    """

    def __init__(
        self,
        container: str,
        prefix: str = "policies/",
        connection_string: str | None = None,
        account_url: str | None = None,
    ) -> None:
        try:
            from azure.storage.blob import ContainerClient
        except ImportError as exc:
            raise ImportError(
                "azure-storage-blob is required for Azure sync. Install with: "
                "pip install policyforge[azure]"
            ) from exc

        self._prefix = prefix.rstrip("/") + "/"

        if connection_string:
            self._client = ContainerClient.from_connection_string(
                connection_string, container_name=container
            )
        elif account_url:
            from azure.identity import DefaultAzureCredential

            credential = DefaultAzureCredential()
            self._client = ContainerClient(
                account_url, container_name=container, credential=credential
            )
        else:
            raise ValueError("Provide either connection_string or account_url.")

        self._container = container

    @property
    def name(self) -> str:
        return f"azure-blob://{self._container}/{self._prefix}"

    def list_remote(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for blob in self._client.list_blobs(name_starts_with=self._prefix):
            if blob.name.endswith((".yaml", ".yml")):
                results.append({
                    "key": blob.name,
                    "etag": blob.etag.strip('"') if blob.etag else "",
                    "size": blob.size,
                })
        return results

    def download(self, remote_key: str, local_path: Path) -> None:
        local_path.parent.mkdir(parents=True, exist_ok=True)
        blob_client = self._client.get_blob_client(remote_key)
        with open(local_path, "wb") as fh:
            stream = blob_client.download_blob()
            fh.write(stream.readall())
        logger.info("Downloaded azure://%s/%s → %s", self._container, remote_key, local_path)

    def upload(self, local_path: Path, remote_key: str) -> None:
        blob_client = self._client.get_blob_client(remote_key)
        with open(local_path, "rb") as fh:
            blob_client.upload_blob(fh, overwrite=True)
        logger.info("Uploaded %s → azure://%s/%s", local_path, self._container, remote_key)
