"""Orchestrates fingerprint pinning and shadowing detection."""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

from policyforge.trust._normalize import nfkc
from policyforge.trust.ledger import LedgerReader, LedgerWriter
from policyforge.trust.models import (
    ToolFingerprint,
    TrustConfig,
    TrustMode,
    TrustResult,
)
from policyforge.trust.shadowing import canonicalize


class TrustManager:
    """Pre-flight trust check for tool calls.

    Performs, in order:
      1. Missing-metadata check.
      2. Shadowing detection against the approved set.
      3. Ledger lookup by (server_id, NFKC(name)).
      4. Fingerprint comparison (schema_hash + description_hash).
      5. Auto-approve if configured and the tool is unknown.
    """

    def __init__(
        self,
        config: TrustConfig,
        hmac_key: str | bytes | None = None,
        *,
        approved_by: str = "auto",
        now: Callable[[], float] = time.time,
    ) -> None:
        """Initialize the trust manager.

        Args:
            config: Parsed ``tool_trust`` YAML block.
            hmac_key: Secret for the approvals ledger's HMAC. Falls back to the
                ``POLICYFORGE_HMAC_KEY`` environment variable. Required when
                ``config.mode`` is not ``DISABLED``.
            approved_by: Identifier recorded in the ledger for auto-approved entries
                (``auto_approve=True``). Ignored otherwise.
            now: Injectable clock for tests.

        Note:
            The approvals ledger is snapshotted into memory at construction.
            Out-of-band appends (e.g. operator-run approval CLI) are NOT observed
            by a running TrustManager — re-instantiate to refresh.
        """
        self._config = config
        self._approved_by = approved_by
        self._now = now
        if config.mode != TrustMode.DISABLED:
            self._writer: LedgerWriter | None = LedgerWriter(
                path=config.ledger_path, hmac_key=hmac_key
            )
            self._reader: LedgerReader | None = LedgerReader(
                path=config.ledger_path, hmac_key=hmac_key
            )
            self._approved: dict[tuple[str, str], ToolFingerprint] = self._reader.load()
        else:
            self._writer = None
            self._reader = None
            self._approved = {}

    def check(
        self,
        tool_name: str,
        tool_meta: dict[str, Any] | None,
    ) -> TrustResult:
        """Run the full pre-flight sequence."""
        if self._config.mode == TrustMode.DISABLED:
            return TrustResult.ok()

        if not tool_meta:
            return self._mismatch(
                "tool_meta_missing",
                "Tool metadata (server_id, schema_hash, description_hash) required.",
            )

        server_id = tool_meta.get("server_id", "")
        schema_hash = tool_meta.get("schema_hash", "")
        description_hash = tool_meta.get("description_hash", "")
        nfkc_name = nfkc(tool_name)
        key = (server_id, nfkc_name)

        # 1. Shadowing check — compare against every approved name for this server.
        if self._config.detect_confusables or self._config.detect_nfkc:
            incoming_canon = canonicalize(tool_name)
            for s_id, stored_name in self._approved:
                if s_id != server_id:
                    continue
                if stored_name == nfkc_name:
                    continue
                if canonicalize(stored_name) == incoming_canon:
                    return self._mismatch(
                        "tool_shadow_detected",
                        f"Name '{tool_name}' shadows approved '{stored_name}'.",
                    )

        # 2. Ledger lookup.
        pinned = self._approved.get(key)
        if pinned is None:
            if self._config.auto_approve:
                fp = ToolFingerprint(
                    server_id=server_id,
                    name=nfkc_name,
                    schema_hash=schema_hash,
                    description_hash=description_hash,
                    first_seen=self._now(),
                    approved_by=self._approved_by,
                )
                # mode != DISABLED path: writer is guaranteed non-None (see __init__).
                assert self._writer is not None
                self._writer.append(fp)
                self._approved[key] = fp
                return TrustResult.ok()
            verdict = self._config.on_unknown
            return TrustResult(
                verdict=verdict,
                reason="tool_unknown",
                message=f"No approved fingerprint for {server_id}:{tool_name}.",
            )

        # 3. Fingerprint comparison.
        if pinned.schema_hash != schema_hash or pinned.description_hash != description_hash:
            return self._mismatch(
                "fingerprint_drift",
                f"Fingerprint drift for {server_id}:{tool_name}.",
            )

        return TrustResult.ok()

    def _mismatch(self, reason: str, message: str) -> TrustResult:
        """Apply the configured on_mismatch verdict to a detected mismatch."""
        return TrustResult(
            verdict=self._config.on_mismatch,
            reason=reason,
            message=message,
        )
