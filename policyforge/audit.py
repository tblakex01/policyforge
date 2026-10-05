"""Tamper-evident audit logger with HMAC integrity and log rotation."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import threading
import time
import uuid
from json import JSONDecodeError
from pathlib import Path
from typing import Any

from policyforge.models import AuditEntry

logger = logging.getLogger(__name__)

_DEFAULT_LOG_DIR = Path("./audit_logs")
_DEFAULT_MAX_BYTES = 50 * 1024 * 1024  # 50 MB per file
_ENV_HMAC_KEY = "POLICYFORGE_HMAC_KEY"


class AuditLogger:
    """Append-only, HMAC-signed audit logger for policy decisions.

    Each log entry is a single JSON line with an integrity_hash computed
    via HMAC-SHA256.  The HMAC key is sourced from:
      1. The ``hmac_key`` constructor arg, or
      2. The ``POLICYFORGE_HMAC_KEY`` environment variable.

    If neither is set, a RuntimeError is raised — we don't silently
    skip integrity checks.

    Args:
        log_dir: Directory to write audit log files.
        hmac_key: Secret key for HMAC signing. Falls back to env var.
        max_file_bytes: Rotate to a new file after this size.
        chain_hashes: If True, each entry's HMAC also covers the
                      previous entry's hash, creating a hash chain
                      (blockchain-lite tamper detection).
    """

    def __init__(
        self,
        log_dir: str | Path = _DEFAULT_LOG_DIR,
        hmac_key: str | bytes | None = None,
        max_file_bytes: int = _DEFAULT_MAX_BYTES,
        chain_hashes: bool = True,
    ) -> None:
        raw_key = hmac_key or os.environ.get(_ENV_HMAC_KEY)
        if not raw_key:
            raise RuntimeError(
                f"Audit HMAC key required. Pass hmac_key= or set {_ENV_HMAC_KEY} env var."
            )
        self._hmac_key = raw_key.encode("utf-8") if isinstance(raw_key, str) else raw_key
        self._log_dir = Path(log_dir)
        self._log_dir.mkdir(parents=True, exist_ok=True)
        self._max_bytes = max_file_bytes
        self._chain = chain_hashes
        self._last_hash = ""
        self._lock = threading.Lock()
        self._current_file = self._new_log_path()

    def _new_log_path(self) -> Path:
        ts = time.strftime("%Y%m%d_%H%M%S")
        return self._log_dir / f"audit_{ts}_{os.getpid()}_{uuid.uuid4().hex[:12]}.jsonl"

    @staticmethod
    def _anchor_path(path: Path) -> Path:
        return path.with_name(path.name + ".anchor")

    def _anchor_signature(self, payload: dict[str, Any]) -> str:
        serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hmac.new(self._hmac_key, serialized.encode("utf-8"), hashlib.sha256).hexdigest()

    def _write_anchor(self, path: Path, first_hash: str) -> None:
        """Bind a new log file to its first signed entry before writing it."""
        payload = {"version": 1, "file": path.name, "first_hmac": first_hash}
        record = {**payload, "hmac": self._anchor_signature(payload)}
        fd = os.open(self._anchor_path(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(record, separators=(",", ":")) + "\n")

    def _read_anchor(self, path: Path) -> str | None:
        """Return the authenticated first-entry hash, or None for invalid anchors."""
        try:
            record = json.loads(self._anchor_path(path).read_text(encoding="utf-8"))
            if not isinstance(record, dict):
                return None
            payload = {
                "version": record["version"],
                "file": record["file"],
                "first_hmac": record["first_hmac"],
            }
            if payload["version"] != 1 or payload["file"] != path.name:
                return None
            if not isinstance(payload["first_hmac"], str):
                return None
            if not hmac.compare_digest(record["hmac"], self._anchor_signature(payload)):
                return None
            return payload["first_hmac"]
        except (OSError, JSONDecodeError, KeyError, TypeError, ValueError):
            return None

    def log(
        self,
        request_id: str,
        tool_name: str,
        agent_id: str,
        args_hash: str,
        verdict: str,
        matched_rule: str = "",
        policy_name: str = "",
        message: str = "",
        evaluation_ms: float = 0.0,
    ) -> AuditEntry:
        """Create, sign, and persist an audit entry. Returns the entry."""
        entry = AuditEntry(
            timestamp=time.time(),
            request_id=request_id,
            tool_name=tool_name,
            agent_id=agent_id,
            args_hash=args_hash,
            verdict=verdict,
            matched_rule=matched_rule,
            policy_name=policy_name,
            message=message,
            evaluation_ms=evaluation_ms,
            entry_type="decision",
        )

        with self._lock:
            # Chain and HMAC sealing must happen under the same lock as the write.
            if self._chain and self._last_hash:
                entry.chain_prev = self._last_hash
            entry.seal(self._hmac_key)
            self._write(entry)
            if self._chain:
                self._last_hash = entry.integrity_hash

        return entry

    def log_event(
        self,
        request_id: str,
        event_type: str,
        *,
        tool_name: str = "",
        agent_id: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> AuditEntry:
        """Persist a signed product event in the audit trail."""
        entry = AuditEntry(
            timestamp=time.time(),
            request_id=request_id,
            tool_name=tool_name,
            agent_id=agent_id,
            entry_type="event",
            event_type=event_type,
            metadata=metadata or {},
        )

        with self._lock:
            if self._chain and self._last_hash:
                entry.chain_prev = self._last_hash
            entry.seal(self._hmac_key)
            self._write(entry)
            if self._chain:
                self._last_hash = entry.integrity_hash

        return entry

    def _write(self, entry: AuditEntry) -> None:
        """Append a JSON-lines record, rotating if needed."""
        try:
            if self._current_file.stat().st_size >= self._max_bytes:
                self._current_file = self._new_log_path()
                logger.info("Rotated audit log to %s", self._current_file)
        except FileNotFoundError:
            pass  # file doesn't exist yet, no rotation needed

        new_file = not self._current_file.exists()
        if new_file:
            self._write_anchor(self._current_file, entry.integrity_hash)

        record = {
            "ts": entry.timestamp,
            "rid": entry.request_id,
            "kind": entry.entry_type,
            "tool": entry.tool_name,
            "agent": entry.agent_id,
            "args_hash": entry.args_hash,
            "verdict": entry.verdict,
            "rule": entry.matched_rule,
            "policy": entry.policy_name,
            "msg": entry.message,
            "ms": entry.evaluation_ms,
            "event": entry.event_type,
            "meta": entry.metadata,
            "hmac": entry.integrity_hash,
            "chain_prev": entry.chain_prev,
        }
        with open(self._current_file, "x" if new_file else "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, separators=(",", ":"), default=str) + "\n")

    def verify_log(
        self, path: str | Path | None = None, *, allow_legacy_unanchored: bool = False
    ) -> tuple[int, int]:
        """Verify integrity of a log file. Returns (valid_count, tampered_count).

        Reads each JSON-lines entry and recomputes its HMAC.  If chain_hashes
        was enabled, also validates the hash chain. Legacy files lacking an
        authenticated first-entry anchor require explicit opt-in.
        """
        path = Path(path) if path else self._current_file
        valid = 0
        tampered = 0
        prev_hash = ""
        try:
            self._anchor_path(path).lstat()
            anchor_present = True
        except FileNotFoundError:
            anchor_present = False
        first_hash = self._read_anchor(path)
        if first_hash is None and (anchor_present or not allow_legacy_unanchored):
            logger.error("MISSING OR INVALID audit anchor for %s", path)
            tampered += 1
        first_entry = True

        with open(path, encoding="utf-8") as fh:
            for line_num, line in enumerate(fh, start=1):
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    raw: dict[str, Any] = json.loads(stripped)
                    include_event_fields = raw.get("kind") == "event"
                    entry = AuditEntry(
                        timestamp=raw["ts"],
                        request_id=raw["rid"],
                        tool_name=raw["tool"],
                        agent_id=raw["agent"],
                        args_hash=raw["args_hash"],
                        verdict=raw["verdict"],
                        matched_rule=raw["rule"],
                        policy_name=raw["policy"],
                        message=raw["msg"],
                        evaluation_ms=raw["ms"],
                        entry_type=raw.get("kind", "decision"),
                        event_type=raw.get("event", ""),
                        metadata=raw.get("meta", {}),
                        integrity_hash=raw["hmac"],
                        chain_prev=raw.get("chain_prev", ""),
                    )
                except (JSONDecodeError, KeyError, TypeError, ValueError) as exc:
                    logger.error("MALFORMED entry at line %d in %s: %s", line_num, path, exc)
                    tampered += 1
                    continue

                if first_entry:
                    if first_hash is not None and entry.integrity_hash != first_hash:
                        logger.error("AUDIT PREFIX REMOVED or changed in %s", path)
                        tampered += 1
                    first_entry = False

                if entry.verify(self._hmac_key, include_event_fields=include_event_fields):
                    valid += 1
                else:
                    logger.error("TAMPERED entry at line %d in %s", line_num, path)
                    tampered += 1

                # Chain verification
                if self._chain and prev_hash and entry.chain_prev != prev_hash:
                    logger.error("BROKEN CHAIN at line %d in %s", line_num, path)
                    tampered += 1

                prev_hash = entry.integrity_hash

        if first_entry and first_hash is not None:
            logger.error("AUDIT LOG EMPTY but anchored in %s", path)
            tampered += 1

        return valid, tampered
