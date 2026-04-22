"""Data models for the tool-fingerprint trust subsystem."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

_DEFAULT_LEDGER_PATH = Path(".policyforge") / "approvals.jsonl"


class TrustMode(str, Enum):
    """How strictly the trust manager enforces fingerprints."""

    ENFORCE = "enforce"
    WARN = "warn"
    DISABLED = "disabled"


class TrustVerdict(str, Enum):
    """Outcome of a trust pre-flight check."""

    ALLOW = "ALLOW"
    DENY = "DENY"
    LOG_ONLY = "LOG_ONLY"


@dataclass(frozen=True)
class ToolFingerprint:
    """Pinned identity for an approved tool.

    The key for lookup is (server_id, NFKC-canonicalized name).
    """

    server_id: str
    name: str
    schema_hash: str
    description_hash: str
    first_seen: float
    approved_by: str


@dataclass(frozen=True)
class TrustConfig:
    """Parsed YAML configuration for the trust subsystem."""

    mode: TrustMode = TrustMode.DISABLED
    ledger_path: Path = field(default_factory=lambda: _DEFAULT_LEDGER_PATH)
    on_mismatch: TrustVerdict = TrustVerdict.DENY
    on_unknown: TrustVerdict = TrustVerdict.DENY
    auto_approve: bool = False
    detect_nfkc: bool = True
    detect_confusables: bool = True


@dataclass(frozen=True)
class TrustResult:
    """Outcome of TrustManager.check()."""

    verdict: TrustVerdict
    reason: str = ""
    message: str = ""

    @classmethod
    def ok(cls) -> TrustResult:
        """Build an ALLOW result with no reason."""
        return cls(verdict=TrustVerdict.ALLOW)

    @classmethod
    def deny(cls, reason: str, message: str = "") -> TrustResult:
        """Build a DENY result with a short machine-readable reason and optional message."""
        return cls(verdict=TrustVerdict.DENY, reason=reason, message=message)

    @classmethod
    def log_only(cls, reason: str, message: str = "") -> TrustResult:
        """Build a LOG_ONLY result; used in WARN mode to surface issues without blocking."""
        return cls(verdict=TrustVerdict.LOG_ONLY, reason=reason, message=message)


def canonical_schema_hash(schema: dict[str, Any]) -> str:
    """SHA-256 over a canonical JSON serialization (sorted keys, no whitespace).

    Tool schemas must be JSON-native. Non-JSON-serializable values raise
    TypeError rather than being silently coerced — a collision in coerced
    strings would undermine fingerprint integrity.
    """
    payload = json.dumps(schema, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
