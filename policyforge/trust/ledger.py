"""HMAC-signed, hash-chained single-file JSONL ledger for tool fingerprints."""

from __future__ import annotations

import hashlib
import hmac as _hmac
import json
import os
import threading
from pathlib import Path
from typing import Any

from policyforge.trust._normalize import nfkc
from policyforge.trust.models import ToolFingerprint

_ENV_HMAC_KEY = "POLICYFORGE_HMAC_KEY"


def _entry_payload(record: dict[str, Any]) -> str:
    """Canonical JSON payload over which the HMAC is computed.

    Uses sorted keys + compact separators for a self-delimiting encoding
    that cannot be ambiguously re-parsed if an attacker stuffs the
    separator into a field value.
    """
    return json.dumps(record, sort_keys=True, separators=(",", ":"))


def _sign(payload: str, key: bytes) -> str:
    return _hmac.new(key, payload.encode("utf-8"), hashlib.sha256).hexdigest()


class LedgerWriter:
    """Append-only writer for the approvals ledger.

    Thread-safe within a single process via an internal lock. The writer
    does NOT guard against concurrent writes from multiple processes —
    running two LedgerWriters against the same path will race on chain
    recovery and produce an irrecoverably broken chain. Single-process
    ownership is assumed; deploy accordingly (or layer a file lock
    outside this class).
    """

    def __init__(self, path: Path, hmac_key: str | bytes | None = None) -> None:
        raw = hmac_key or os.environ.get(_ENV_HMAC_KEY)
        if not raw:
            raise RuntimeError(f"Ledger HMAC key required. Pass hmac_key= or set {_ENV_HMAC_KEY}.")
        self._key = raw.encode("utf-8") if isinstance(raw, str) else raw
        self._path = Path(path)
        self._lock = threading.Lock()
        self._last_hash = self._recover_last_hash()

    def _recover_last_hash(self) -> str:
        """Verify and recover the last HMAC from an existing ledger.

        Uses LedgerReader.load() so any tamper or chain break surfaces
        immediately; silently chaining to a bogus hash would permanently
        break the file.
        """
        if not self._path.exists():
            return ""
        reader = LedgerReader(path=self._path, hmac_key=self._key)
        reader.load()  # raises ValueError on tamper/chain break
        # Reader's verify also walks the file — grab the terminal hmac.
        last = ""
        with self._path.open(encoding="utf-8") as fh:
            for line in fh:
                stripped = line.strip()
                if stripped:
                    last = json.loads(stripped)["hmac"]
        return last

    def append(self, fp: ToolFingerprint) -> None:
        """Append a fingerprint record to the ledger, chaining to the previous entry."""
        record: dict[str, Any] = {
            "server_id": fp.server_id,
            "name": fp.name,
            "schema_hash": fp.schema_hash,
            "description_hash": fp.description_hash,
            "first_seen": fp.first_seen,
            "approved_by": fp.approved_by,
        }
        with self._lock:
            record["chain_prev"] = self._last_hash
            record["hmac"] = _sign(_entry_payload(record), self._key)
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with self._path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, separators=(",", ":")) + "\n")
            self._last_hash = record["hmac"]


class LedgerReader:
    """Verifying reader for the approvals ledger."""

    def __init__(self, path: Path, hmac_key: str | bytes | None = None) -> None:
        raw = hmac_key or os.environ.get(_ENV_HMAC_KEY)
        if not raw:
            raise RuntimeError(f"Ledger HMAC key required. Pass hmac_key= or set {_ENV_HMAC_KEY}.")
        self._key = raw.encode("utf-8") if isinstance(raw, str) else raw
        self._path = Path(path)

    def load(self) -> dict[tuple[str, str], ToolFingerprint]:
        """Return the latest fingerprint per (server_id, NFKC(name)).

        Raises ValueError on tampering or a broken hash chain.
        """
        if not self._path.exists():
            return {}

        out: dict[tuple[str, str], ToolFingerprint] = {}
        prev = ""
        with self._path.open(encoding="utf-8") as fh:
            for line_num, line in enumerate(fh, start=1):
                stripped = line.strip()
                if not stripped:
                    continue
                record = json.loads(stripped)

                # Chain check
                if record["chain_prev"] != prev:
                    raise ValueError(f"Broken chain at line {line_num} in {self._path}")

                # HMAC check (strip hmac field before recomputing)
                stored = record["hmac"]
                payload_record = {k: record[k] for k in record if k != "hmac"}
                expected = _sign(_entry_payload(payload_record), self._key)
                if not _hmac.compare_digest(stored, expected):
                    raise ValueError(f"Ledger entry tamper detected at line {line_num}")

                fp = ToolFingerprint(
                    server_id=record["server_id"],
                    name=record["name"],
                    schema_hash=record["schema_hash"],
                    description_hash=record["description_hash"],
                    first_seen=float(record["first_seen"]),
                    approved_by=record["approved_by"],
                )
                out[(fp.server_id, nfkc(fp.name))] = fp
                prev = stored

        return out
