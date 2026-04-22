# Tool Fingerprint Pinning Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Pin each tool's identity (server, name, schema, description) at first approval and refuse invocations whose identity has drifted or whose name shadows an approved one via Unicode tricks.

**Architecture:** New `policyforge/trust/` subpackage with four modules (models, shadowing, ledger, manager). `PolicyEngine` gets an optional `trust_manager` parameter; when present, a pre-flight check runs before the existing rule loop. The approvals ledger is a project-local `./.policyforge/approvals.jsonl` HMAC+hash-chained JSONL that mirrors the patterns in `policyforge/audit.py`. YAML loader gets a new top-level `tool_trust:` block.

**Tech Stack:** Python 3.10+, PyYAML (existing dep), stdlib `hashlib`/`hmac`/`unicodedata`, pytest + pytest-asyncio.

**Spec reference:** `docs/superpowers/specs/2026-04-22-agent-security-suite-design.md` §4 and §3 (ship order: this feature first).

---

## File Structure

**Create:**
- `policyforge/trust/__init__.py` — public re-exports
- `policyforge/trust/models.py` — `ToolFingerprint`, `TrustConfig`, `TrustVerdict` enum, `TrustResult`
- `policyforge/trust/shadowing.py` — NFKC canonicalization + handcrafted homoglyph map + `canonicalize()` / `shadows()`
- `policyforge/trust/ledger.py` — `LedgerWriter` / `LedgerReader` (single-file JSONL, HMAC+chain)
- `policyforge/trust/manager.py` — `TrustManager` orchestrator
- `policyforge/policies/tool_trust_example.yaml` — annotated example
- `tests/test_trust_models.py`
- `tests/test_trust_shadowing.py`
- `tests/test_trust_ledger.py`
- `tests/test_trust_manager.py`
- `tests/test_engine_trust_integration.py`

**Modify:**
- `policyforge/engine.py` — wire optional `trust_manager` into `PolicyEngine.__init__` + pre-flight in `evaluate()`
- `policyforge/loader.py` — recognize and parse top-level `tool_trust:` block into a `TrustConfig`
- `policyforge/__init__.py` — export new public names (`TrustManager`, `TrustConfig`, `ToolFingerprint`)

**No changes to:** `models.py`, `audit.py`, `decorators.py`, `sync/`, `policies/default.yaml`, `policies/hospitality_pii.yaml` — this feature is additive and backwards compatible.

---

## Task 1: `ToolFingerprint` and config models

**Files:**
- Create: `policyforge/trust/models.py`
- Test: `tests/test_trust_models.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_trust_models.py`:

```python
"""Tests for trust data models."""

import hashlib
import json

import pytest

from policyforge.trust.models import (
    ToolFingerprint,
    TrustConfig,
    TrustMode,
    TrustResult,
    TrustVerdict,
    canonical_schema_hash,
)


class TestToolFingerprint:
    def test_frozen_dataclass(self):
        fp = ToolFingerprint(
            server_id="mcp://github",
            name="create_issue",
            schema_hash="a" * 64,
            description_hash="b" * 64,
            first_seen=1700000000.0,
            approved_by="operator",
        )
        with pytest.raises(AttributeError):
            fp.name = "other"  # type: ignore[misc]

    def test_equality_on_all_fields(self):
        a = ToolFingerprint("s", "n", "x" * 64, "y" * 64, 1.0, "op")
        b = ToolFingerprint("s", "n", "x" * 64, "y" * 64, 1.0, "op")
        assert a == b


class TestCanonicalSchemaHash:
    def test_stable_across_key_order(self):
        schema_a = {"type": "object", "properties": {"a": 1, "b": 2}}
        schema_b = {"properties": {"b": 2, "a": 1}, "type": "object"}
        assert canonical_schema_hash(schema_a) == canonical_schema_hash(schema_b)

    def test_differs_on_value_change(self):
        h1 = canonical_schema_hash({"x": 1})
        h2 = canonical_schema_hash({"x": 2})
        assert h1 != h2

    def test_is_sha256_hex(self):
        h = canonical_schema_hash({"x": 1})
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)

    def test_matches_manual_computation(self):
        payload = json.dumps({"x": 1}, sort_keys=True, separators=(",", ":"))
        expected = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        assert canonical_schema_hash({"x": 1}) == expected


class TestTrustConfig:
    def test_defaults(self):
        cfg = TrustConfig()
        assert cfg.mode == TrustMode.DISABLED
        assert cfg.on_mismatch == TrustVerdict.DENY
        assert cfg.on_unknown == TrustVerdict.DENY
        assert cfg.auto_approve is False
        assert cfg.detect_nfkc is True
        assert cfg.detect_confusables is True

    def test_ledger_path_default(self):
        cfg = TrustConfig()
        assert str(cfg.ledger_path).endswith(".policyforge/approvals.jsonl") or str(
            cfg.ledger_path
        ).endswith(".policyforge\\approvals.jsonl")


class TestTrustResult:
    def test_ok_result(self):
        r = TrustResult.ok()
        assert r.verdict == TrustVerdict.ALLOW
        assert r.reason == ""

    def test_deny_result(self):
        r = TrustResult.deny("fingerprint_drift", "schema hash changed")
        assert r.verdict == TrustVerdict.DENY
        assert r.reason == "fingerprint_drift"
        assert r.message == "schema hash changed"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_trust_models.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'policyforge.trust'`

- [ ] **Step 3: Create the package**

Create `policyforge/trust/__init__.py`:

```python
"""Tool fingerprint pinning and trust management."""

from policyforge.trust.models import (
    ToolFingerprint,
    TrustConfig,
    TrustMode,
    TrustResult,
    TrustVerdict,
    canonical_schema_hash,
)

__all__ = [
    "ToolFingerprint",
    "TrustConfig",
    "TrustMode",
    "TrustResult",
    "TrustVerdict",
    "canonical_schema_hash",
]
```

- [ ] **Step 4: Implement models**

Create `policyforge/trust/models.py`:

```python
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
        return cls(verdict=TrustVerdict.ALLOW)

    @classmethod
    def deny(cls, reason: str, message: str = "") -> TrustResult:
        return cls(verdict=TrustVerdict.DENY, reason=reason, message=message)

    @classmethod
    def log_only(cls, reason: str, message: str = "") -> TrustResult:
        return cls(verdict=TrustVerdict.LOG_ONLY, reason=reason, message=message)


def canonical_schema_hash(schema: dict[str, Any]) -> str:
    """SHA-256 over a canonical JSON serialization (sorted keys, no whitespace)."""
    payload = json.dumps(schema, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
```

- [ ] **Step 5: Run tests**

Run: `pytest tests/test_trust_models.py -v`
Expected: PASS (all 10 tests)

- [ ] **Step 6: Commit**

```bash
git add policyforge/trust/__init__.py policyforge/trust/models.py tests/test_trust_models.py
git commit -m "feat(trust): add ToolFingerprint and TrustConfig models"
```

---

## Task 2: Shadowing detection (NFKC + homoglyphs)

**Files:**
- Create: `policyforge/trust/shadowing.py`
- Test: `tests/test_trust_shadowing.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_trust_shadowing.py`:

```python
"""Tests for Unicode shadowing detection."""

from policyforge.trust.shadowing import canonicalize, shadows


class TestCanonicalize:
    def test_nfkc_composes_decomposed_forms(self):
        # "é" as U+00E9 vs "e" + U+0301 (combining acute)
        composed = "fil\u00e9"
        decomposed = "file\u0301"
        assert canonicalize(composed) == canonicalize(decomposed)

    def test_compatibility_fold(self):
        # Fullwidth "A" (U+FF21) should fold to ASCII "A" under NFKC
        assert canonicalize("\uff21") == canonicalize("A")

    def test_homoglyph_cyrillic_a_folds_to_latin_a(self):
        # U+0430 CYRILLIC SMALL LETTER A vs U+0061 LATIN SMALL LETTER A
        assert canonicalize("\u0430pi") == canonicalize("api")

    def test_homoglyph_cyrillic_o_folds(self):
        # U+043E CYRILLIC SMALL LETTER O vs U+006F LATIN SMALL LETTER O
        assert canonicalize("f\u043eo") == canonicalize("foo")

    def test_homoglyph_greek_o_folds(self):
        # U+03BF GREEK SMALL LETTER OMICRON vs U+006F
        assert canonicalize("f\u03bfo") == canonicalize("foo")

    def test_case_is_preserved_when_detect_case_false(self):
        # By default, we fold to lowercase for comparison
        assert canonicalize("Foo") == canonicalize("foo")

    def test_non_homoglyph_chars_unchanged(self):
        assert canonicalize("plain_name") == "plain_name"


class TestShadows:
    def test_same_name_does_not_shadow_itself(self):
        # Two *equal* names aren't a shadowing pair
        assert shadows("send_email", "send_email") is False

    def test_cyrillic_homoglyph_shadows(self):
        # Cyrillic "ѕ" (U+0455) vs Latin "s"
        assert shadows("\u0455end_email", "send_email") is True

    def test_different_names_do_not_shadow(self):
        assert shadows("send_email", "read_file") is False

    def test_nfkc_collision_shadows(self):
        assert shadows("fil\u00e9", "file\u0301") is True

    def test_fullwidth_shadows_ascii(self):
        assert shadows("\uff41pi", "api") is True
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_trust_shadowing.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'policyforge.trust.shadowing'`

- [ ] **Step 3: Implement shadowing**

Create `policyforge/trust/shadowing.py`:

```python
"""Unicode shadowing detection for tool names.

``canonicalize`` folds a name through:
  1. NFKC normalization (handles decomposed forms + fullwidth + ligatures).
  2. A minimum-viable homoglyph map (Cyrillic/Greek -> Latin for the most
     commonly-confused letters).
  3. ASCII-lowercasing (case-insensitive comparison).

``shadows(a, b)`` returns True when two *distinct* raw names canonicalize
to the same value.  Equal raw names do not count as shadowing.
"""

from __future__ import annotations

import unicodedata

# Handcrafted homoglyph map — Latin targets for commonly-abused lookalikes.
# Documented as minimum-viable; a full ICU confusables table can replace
# this later without changing the public API.
_HOMOGLYPHS: dict[str, str] = {
    # Cyrillic lowercase -> Latin lowercase
    "\u0430": "a",  # а
    "\u0435": "e",  # е
    "\u043e": "o",  # о
    "\u0440": "p",  # р
    "\u0441": "c",  # с
    "\u0443": "y",  # у
    "\u0445": "x",  # х
    "\u0455": "s",  # ѕ
    "\u0456": "i",  # і
    "\u0458": "j",  # ј
    "\u04cf": "l",  # ӏ
    # Cyrillic uppercase -> Latin uppercase (folded later to lower)
    "\u0410": "A",
    "\u0415": "E",
    "\u041e": "O",
    "\u0420": "P",
    "\u0421": "C",
    "\u0425": "X",
    # Greek lowercase -> Latin lowercase
    "\u03bf": "o",  # ο
    "\u03b1": "a",  # α
    "\u03c1": "p",  # ρ
    "\u03c5": "u",  # υ
    "\u03bd": "v",  # ν
    # Greek uppercase
    "\u0391": "A",
    "\u0395": "E",
    "\u039f": "O",
    "\u03a1": "P",
}


def _fold_homoglyphs(text: str) -> str:
    return "".join(_HOMOGLYPHS.get(ch, ch) for ch in text)


def canonicalize(name: str) -> str:
    """Fold a name to a canonical form for shadowing comparison.

    NFKC -> homoglyph fold -> ASCII-lowercase.
    """
    nfkc = unicodedata.normalize("NFKC", name)
    folded = _fold_homoglyphs(nfkc)
    return folded.lower()


def shadows(a: str, b: str) -> bool:
    """Return True if two *distinct* raw names canonicalize to the same form."""
    if a == b:
        return False
    return canonicalize(a) == canonicalize(b)
```

- [ ] **Step 4: Run tests**

Run: `pytest tests/test_trust_shadowing.py -v`
Expected: PASS (12 tests)

- [ ] **Step 5: Commit**

```bash
git add policyforge/trust/shadowing.py tests/test_trust_shadowing.py
git commit -m "feat(trust): add NFKC + homoglyph shadowing detection"
```

---

## Task 3: HMAC-chained approvals ledger

**Files:**
- Create: `policyforge/trust/ledger.py`
- Test: `tests/test_trust_ledger.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_trust_ledger.py`:

```python
"""Tests for the approvals ledger."""

import json
from pathlib import Path

import pytest

from policyforge.trust.ledger import LedgerReader, LedgerWriter
from policyforge.trust.models import ToolFingerprint


@pytest.fixture
def ledger_path(tmp_path: Path) -> Path:
    return tmp_path / "approvals.jsonl"


@pytest.fixture
def writer(ledger_path: Path) -> LedgerWriter:
    return LedgerWriter(path=ledger_path, hmac_key="test-ledger-key")


@pytest.fixture
def fp() -> ToolFingerprint:
    return ToolFingerprint(
        server_id="mcp://github",
        name="create_issue",
        schema_hash="a" * 64,
        description_hash="b" * 64,
        first_seen=1700000000.0,
        approved_by="operator",
    )


class TestLedgerWriter:
    def test_creates_file_on_first_append(self, writer, fp, ledger_path):
        writer.append(fp)
        assert ledger_path.exists()

    def test_first_entry_has_empty_chain_prev(self, writer, fp, ledger_path):
        writer.append(fp)
        line = ledger_path.read_text(encoding="utf-8").strip()
        record = json.loads(line)
        assert record["chain_prev"] == ""

    def test_second_entry_chains_to_first(self, writer, ledger_path):
        fp1 = ToolFingerprint("s", "a", "x" * 64, "y" * 64, 1.0, "op")
        fp2 = ToolFingerprint("s", "b", "x" * 64, "y" * 64, 2.0, "op")
        writer.append(fp1)
        writer.append(fp2)
        lines = ledger_path.read_text(encoding="utf-8").strip().split("\n")
        first = json.loads(lines[0])
        second = json.loads(lines[1])
        assert second["chain_prev"] == first["hmac"]

    def test_entry_has_integrity_hash(self, writer, fp, ledger_path):
        writer.append(fp)
        record = json.loads(ledger_path.read_text(encoding="utf-8").strip())
        assert "hmac" in record
        assert len(record["hmac"]) == 64

    def test_requires_hmac_key(self, ledger_path):
        with pytest.raises(RuntimeError, match="HMAC key"):
            LedgerWriter(path=ledger_path, hmac_key=None)

    def test_reads_hmac_from_env(self, ledger_path, monkeypatch):
        monkeypatch.setenv("POLICYFORGE_HMAC_KEY", "from-env")
        writer = LedgerWriter(path=ledger_path)
        # Should not raise
        writer.append(
            ToolFingerprint("s", "n", "x" * 64, "y" * 64, 1.0, "op")
        )


class TestLedgerReader:
    def test_empty_file_returns_empty_map(self, ledger_path):
        ledger_path.touch()
        reader = LedgerReader(path=ledger_path, hmac_key="test-ledger-key")
        assert reader.load() == {}

    def test_missing_file_returns_empty_map(self, tmp_path):
        reader = LedgerReader(path=tmp_path / "nope.jsonl", hmac_key="k")
        assert reader.load() == {}

    def test_loads_single_entry_keyed_by_server_and_nfkc_name(
        self, writer, fp, ledger_path
    ):
        writer.append(fp)
        reader = LedgerReader(path=ledger_path, hmac_key="test-ledger-key")
        loaded = reader.load()
        assert (fp.server_id, "create_issue") in loaded
        assert loaded[(fp.server_id, "create_issue")] == fp

    def test_normalizes_key_via_nfkc(self, writer, ledger_path):
        fp = ToolFingerprint(
            "mcp://x", "fil\u00e9", "x" * 64, "y" * 64, 1.0, "op"
        )
        writer.append(fp)
        reader = LedgerReader(path=ledger_path, hmac_key="test-ledger-key")
        loaded = reader.load()
        # Key uses NFKC-normalized name
        assert ("mcp://x", "file\u0301") not in loaded  # raw decomposed form absent
        assert ("mcp://x", "fil\u00e9") in loaded

    def test_later_entry_wins_for_same_key(self, writer, ledger_path):
        fp1 = ToolFingerprint("s", "n", "a" * 64, "b" * 64, 1.0, "op1")
        fp2 = ToolFingerprint("s", "n", "c" * 64, "d" * 64, 2.0, "op2")
        writer.append(fp1)
        writer.append(fp2)
        reader = LedgerReader(path=ledger_path, hmac_key="test-ledger-key")
        loaded = reader.load()
        assert loaded[("s", "n")].schema_hash == "c" * 64

    def test_tampered_entry_raises(self, writer, fp, ledger_path):
        writer.append(fp)
        # Flip one byte in schema_hash
        text = ledger_path.read_text(encoding="utf-8")
        tampered = text.replace("a" * 64, "z" + "a" * 63)
        ledger_path.write_text(tampered, encoding="utf-8")
        reader = LedgerReader(path=ledger_path, hmac_key="test-ledger-key")
        with pytest.raises(ValueError, match="tamper"):
            reader.load()

    def test_broken_chain_raises(self, writer, ledger_path):
        fp1 = ToolFingerprint("s", "a", "x" * 64, "y" * 64, 1.0, "op")
        fp2 = ToolFingerprint("s", "b", "x" * 64, "y" * 64, 2.0, "op")
        writer.append(fp1)
        writer.append(fp2)
        # Corrupt chain_prev on second record
        lines = ledger_path.read_text(encoding="utf-8").strip().split("\n")
        second = json.loads(lines[1])
        second["chain_prev"] = "0" * 64
        lines[1] = json.dumps(second, separators=(",", ":"))
        ledger_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        reader = LedgerReader(path=ledger_path, hmac_key="test-ledger-key")
        with pytest.raises(ValueError, match="chain"):
            reader.load()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_trust_ledger.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'policyforge.trust.ledger'`

- [ ] **Step 3: Implement the ledger**

Create `policyforge/trust/ledger.py`:

```python
"""HMAC-signed, hash-chained single-file JSONL ledger for tool fingerprints."""

from __future__ import annotations

import hashlib
import hmac as _hmac
import json
import os
import threading
import unicodedata
from pathlib import Path
from typing import Any

from policyforge.trust.models import ToolFingerprint

_ENV_HMAC_KEY = "POLICYFORGE_HMAC_KEY"


def _entry_payload(record: dict[str, Any]) -> str:
    """Canonical payload over which the HMAC is computed."""
    return (
        f"{record['server_id']}|{record['name']}|{record['schema_hash']}|"
        f"{record['description_hash']}|{record['first_seen']}|{record['approved_by']}|"
        f"{record['chain_prev']}"
    )


def _sign(payload: str, key: bytes) -> str:
    return _hmac.new(key, payload.encode("utf-8"), hashlib.sha256).hexdigest()


def _nfkc(name: str) -> str:
    return unicodedata.normalize("NFKC", name)


class LedgerWriter:
    """Append-only writer for the approvals ledger."""

    def __init__(self, path: Path, hmac_key: str | bytes | None = None) -> None:
        raw = hmac_key or os.environ.get(_ENV_HMAC_KEY)
        if not raw:
            raise RuntimeError(
                f"Ledger HMAC key required. Pass hmac_key= or set {_ENV_HMAC_KEY}."
            )
        self._key = raw.encode("utf-8") if isinstance(raw, str) else raw
        self._path = Path(path)
        self._lock = threading.Lock()
        self._last_hash = self._recover_last_hash()

    def _recover_last_hash(self) -> str:
        if not self._path.exists():
            return ""
        last = ""
        with self._path.open(encoding="utf-8") as fh:
            for line in fh:
                stripped = line.strip()
                if stripped:
                    last = json.loads(stripped)["hmac"]
        return last

    def append(self, fp: ToolFingerprint) -> None:
        record = {
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
                fh.write(json.dumps(record, separators=(",", ":"), default=str) + "\n")
            self._last_hash = record["hmac"]


class LedgerReader:
    """Verifying reader for the approvals ledger."""

    def __init__(self, path: Path, hmac_key: str | bytes | None = None) -> None:
        raw = hmac_key or os.environ.get(_ENV_HMAC_KEY)
        if not raw:
            raise RuntimeError(
                f"Ledger HMAC key required. Pass hmac_key= or set {_ENV_HMAC_KEY}."
            )
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
                    raise ValueError(
                        f"Broken chain at line {line_num} in {self._path}"
                    )

                # HMAC check (strip hmac field before recomputing)
                stored = record["hmac"]
                payload_record = {k: record[k] for k in record if k != "hmac"}
                expected = _sign(_entry_payload(payload_record), self._key)
                if not _hmac.compare_digest(stored, expected):
                    raise ValueError(
                        f"Ledger entry tamper detected at line {line_num}"
                    )

                fp = ToolFingerprint(
                    server_id=record["server_id"],
                    name=record["name"],
                    schema_hash=record["schema_hash"],
                    description_hash=record["description_hash"],
                    first_seen=float(record["first_seen"]),
                    approved_by=record["approved_by"],
                )
                out[(fp.server_id, _nfkc(fp.name))] = fp
                prev = stored

        return out
```

- [ ] **Step 4: Run tests**

Run: `pytest tests/test_trust_ledger.py -v`
Expected: PASS (13 tests)

- [ ] **Step 5: Commit**

```bash
git add policyforge/trust/ledger.py tests/test_trust_ledger.py
git commit -m "feat(trust): add HMAC-chained single-file approvals ledger"
```

---

## Task 4: `TrustManager` orchestrator

**Files:**
- Create: `policyforge/trust/manager.py`
- Test: `tests/test_trust_manager.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_trust_manager.py`:

```python
"""Tests for the TrustManager orchestrator."""

import time
from pathlib import Path

import pytest

from policyforge.trust.ledger import LedgerWriter
from policyforge.trust.manager import TrustManager
from policyforge.trust.models import (
    ToolFingerprint,
    TrustConfig,
    TrustMode,
    TrustVerdict,
)


@pytest.fixture
def ledger_path(tmp_path: Path) -> Path:
    return tmp_path / "approvals.jsonl"


def _pin(ledger_path: Path, name: str = "create_issue") -> ToolFingerprint:
    fp = ToolFingerprint(
        server_id="mcp://github",
        name=name,
        schema_hash="a" * 64,
        description_hash="b" * 64,
        first_seen=1700000000.0,
        approved_by="operator",
    )
    LedgerWriter(path=ledger_path, hmac_key="k").append(fp)
    return fp


class TestTrustManagerDisabled:
    def test_disabled_mode_always_allows(self, ledger_path):
        cfg = TrustConfig(mode=TrustMode.DISABLED, ledger_path=ledger_path)
        tm = TrustManager(cfg, hmac_key="k")
        result = tm.check(
            tool_name="anything",
            tool_meta={"server_id": "mcp://x", "schema_hash": "q" * 64,
                       "description_hash": "w" * 64},
        )
        assert result.verdict == TrustVerdict.ALLOW


class TestTrustManagerEnforce:
    def test_unknown_tool_denied(self, ledger_path):
        ledger_path.touch()
        cfg = TrustConfig(mode=TrustMode.ENFORCE, ledger_path=ledger_path)
        tm = TrustManager(cfg, hmac_key="k")
        result = tm.check(
            tool_name="unseen",
            tool_meta={"server_id": "mcp://x", "schema_hash": "s" * 64,
                       "description_hash": "d" * 64},
        )
        assert result.verdict == TrustVerdict.DENY
        assert result.reason == "tool_unknown"

    def test_exact_match_allowed(self, ledger_path):
        pinned = _pin(ledger_path)
        cfg = TrustConfig(mode=TrustMode.ENFORCE, ledger_path=ledger_path)
        tm = TrustManager(cfg, hmac_key="k")
        result = tm.check(
            tool_name=pinned.name,
            tool_meta={
                "server_id": pinned.server_id,
                "schema_hash": pinned.schema_hash,
                "description_hash": pinned.description_hash,
            },
        )
        assert result.verdict == TrustVerdict.ALLOW

    def test_schema_drift_denied(self, ledger_path):
        pinned = _pin(ledger_path)
        cfg = TrustConfig(mode=TrustMode.ENFORCE, ledger_path=ledger_path)
        tm = TrustManager(cfg, hmac_key="k")
        result = tm.check(
            tool_name=pinned.name,
            tool_meta={
                "server_id": pinned.server_id,
                "schema_hash": "f" * 64,  # drift
                "description_hash": pinned.description_hash,
            },
        )
        assert result.verdict == TrustVerdict.DENY
        assert result.reason == "fingerprint_drift"

    def test_description_drift_denied(self, ledger_path):
        pinned = _pin(ledger_path)
        cfg = TrustConfig(mode=TrustMode.ENFORCE, ledger_path=ledger_path)
        tm = TrustManager(cfg, hmac_key="k")
        result = tm.check(
            tool_name=pinned.name,
            tool_meta={
                "server_id": pinned.server_id,
                "schema_hash": pinned.schema_hash,
                "description_hash": "f" * 64,
            },
        )
        assert result.verdict == TrustVerdict.DENY
        assert result.reason == "fingerprint_drift"

    def test_shadow_detection_denied(self, ledger_path):
        _pin(ledger_path, name="send_email")
        cfg = TrustConfig(mode=TrustMode.ENFORCE, ledger_path=ledger_path)
        tm = TrustManager(cfg, hmac_key="k")
        # Cyrillic 's' shadowing Latin 's'
        result = tm.check(
            tool_name="\u0455end_email",
            tool_meta={
                "server_id": "mcp://github",
                "schema_hash": "a" * 64,
                "description_hash": "b" * 64,
            },
        )
        assert result.verdict == TrustVerdict.DENY
        assert result.reason == "tool_shadow_detected"

    def test_auto_approve_records_and_allows(self, ledger_path):
        cfg = TrustConfig(
            mode=TrustMode.ENFORCE,
            ledger_path=ledger_path,
            auto_approve=True,
        )
        tm = TrustManager(cfg, hmac_key="k", approved_by="test-op", now=lambda: 42.0)
        result = tm.check(
            tool_name="new_tool",
            tool_meta={
                "server_id": "mcp://x",
                "schema_hash": "s" * 64,
                "description_hash": "d" * 64,
            },
        )
        assert result.verdict == TrustVerdict.ALLOW
        # Second call with same fingerprint is still allowed
        result2 = tm.check(
            tool_name="new_tool",
            tool_meta={
                "server_id": "mcp://x",
                "schema_hash": "s" * 64,
                "description_hash": "d" * 64,
            },
        )
        assert result2.verdict == TrustVerdict.ALLOW


class TestTrustManagerWarn:
    def test_warn_mode_returns_log_only_on_drift(self, ledger_path):
        pinned = _pin(ledger_path)
        cfg = TrustConfig(
            mode=TrustMode.WARN,
            ledger_path=ledger_path,
            on_mismatch=TrustVerdict.LOG_ONLY,
        )
        tm = TrustManager(cfg, hmac_key="k")
        result = tm.check(
            tool_name=pinned.name,
            tool_meta={
                "server_id": pinned.server_id,
                "schema_hash": "f" * 64,
                "description_hash": pinned.description_hash,
            },
        )
        assert result.verdict == TrustVerdict.LOG_ONLY


class TestTrustManagerMissingMeta:
    def test_missing_tool_meta_denies_in_enforce(self, ledger_path):
        ledger_path.touch()
        cfg = TrustConfig(mode=TrustMode.ENFORCE, ledger_path=ledger_path)
        tm = TrustManager(cfg, hmac_key="k")
        result = tm.check(tool_name="x", tool_meta=None)
        assert result.verdict == TrustVerdict.DENY
        assert result.reason == "tool_meta_missing"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_trust_manager.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'policyforge.trust.manager'`

- [ ] **Step 3: Implement TrustManager**

Create `policyforge/trust/manager.py`:

```python
"""Orchestrates fingerprint pinning and shadowing detection."""

from __future__ import annotations

import time
import unicodedata
from typing import Any, Callable

from policyforge.trust.ledger import LedgerReader, LedgerWriter
from policyforge.trust.models import (
    ToolFingerprint,
    TrustConfig,
    TrustMode,
    TrustResult,
    TrustVerdict,
)
from policyforge.trust.shadowing import canonicalize


def _nfkc(name: str) -> str:
    return unicodedata.normalize("NFKC", name)


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
        self._config = config
        self._approved_by = approved_by
        self._now = now
        if config.mode != TrustMode.DISABLED:
            self._writer = LedgerWriter(path=config.ledger_path, hmac_key=hmac_key)
            self._reader = LedgerReader(path=config.ledger_path, hmac_key=hmac_key)
            self._approved = self._reader.load()
        else:
            self._writer = None  # type: ignore[assignment]
            self._reader = None  # type: ignore[assignment]
            self._approved = {}

    def _reload(self) -> None:
        if self._reader is not None:
            self._approved = self._reader.load()

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
        key = (server_id, _nfkc(tool_name))

        # 1. Shadowing check — compare against every approved name for this server.
        if self._config.detect_confusables or self._config.detect_nfkc:
            incoming_canon = canonicalize(tool_name)
            for s_id, stored_name in self._approved:
                if s_id != server_id:
                    continue
                if stored_name == _nfkc(tool_name):
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
                    name=_nfkc(tool_name),
                    schema_hash=schema_hash,
                    description_hash=description_hash,
                    first_seen=self._now(),
                    approved_by=self._approved_by,
                )
                if self._writer is not None:
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
        if (
            pinned.schema_hash != schema_hash
            or pinned.description_hash != description_hash
        ):
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
```

- [ ] **Step 4: Run tests**

Run: `pytest tests/test_trust_manager.py -v`
Expected: PASS (9 tests)

- [ ] **Step 5: Update package exports**

Edit `policyforge/trust/__init__.py` — add `TrustManager` to imports and `__all__`:

```python
"""Tool fingerprint pinning and trust management."""

from policyforge.trust.manager import TrustManager
from policyforge.trust.models import (
    ToolFingerprint,
    TrustConfig,
    TrustMode,
    TrustResult,
    TrustVerdict,
    canonical_schema_hash,
)

__all__ = [
    "ToolFingerprint",
    "TrustConfig",
    "TrustManager",
    "TrustMode",
    "TrustResult",
    "TrustVerdict",
    "canonical_schema_hash",
]
```

- [ ] **Step 6: Commit**

```bash
git add policyforge/trust/__init__.py policyforge/trust/manager.py tests/test_trust_manager.py
git commit -m "feat(trust): add TrustManager orchestrating shadowing + ledger"
```

---

## Task 5: Loader support for `tool_trust:` block

**Files:**
- Modify: `policyforge/loader.py`
- Test: `tests/test_loader.py` (extend)

- [ ] **Step 1: Write the failing test**

Append to `tests/test_loader.py` (do not overwrite existing tests):

```python
# --- Tool trust block ---

from pathlib import Path

from policyforge.loader import PolicyLoader, load_trust_config
from policyforge.trust.models import TrustMode, TrustVerdict


class TestLoadTrustConfig:
    def test_none_returns_disabled_default(self):
        cfg = load_trust_config(None)
        assert cfg.mode == TrustMode.DISABLED

    def test_parses_full_block(self, tmp_path: Path):
        raw = {
            "mode": "enforce",
            "ledger_path": str(tmp_path / "approvals.jsonl"),
            "on_mismatch": "DENY",
            "on_unknown": "LOG_ONLY",
            "auto_approve": True,
            "detect_shadowing": {"nfkc": True, "confusables": False},
        }
        cfg = load_trust_config(raw)
        assert cfg.mode == TrustMode.ENFORCE
        assert cfg.ledger_path == tmp_path / "approvals.jsonl"
        assert cfg.on_mismatch == TrustVerdict.DENY
        assert cfg.on_unknown == TrustVerdict.LOG_ONLY
        assert cfg.auto_approve is True
        assert cfg.detect_nfkc is True
        assert cfg.detect_confusables is False

    def test_unknown_mode_rejected(self):
        import pytest

        from policyforge.loader import PolicyValidationError

        with pytest.raises(PolicyValidationError, match="mode"):
            load_trust_config({"mode": "bogus"})

    def test_unknown_top_level_key_rejected(self):
        import pytest

        from policyforge.loader import PolicyValidationError

        with pytest.raises(PolicyValidationError, match="unknown"):
            load_trust_config({"mode": "enforce", "mystery_key": 1})


class TestLoaderYamlWithTrustBlock:
    def test_load_file_surfaces_trust_config(self, tmp_path: Path):
        policy_yaml = tmp_path / "p.yaml"
        policy_yaml.write_text(
            """
tool_trust:
  mode: enforce
  ledger_path: approvals.jsonl
  on_mismatch: DENY
policies:
  - name: demo
    rules:
      - name: allow_all
        conditions:
          - field: tool_name
            operator: eq
            value: anything
        verdict: ALLOW
""",
            encoding="utf-8",
        )
        loader = PolicyLoader()
        policies = loader.load_file(policy_yaml)
        assert len(policies) == 1
        assert loader.trust_config is not None
        assert loader.trust_config.mode == TrustMode.ENFORCE
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_loader.py -v -k "Trust or trust"`
Expected: FAIL — `ImportError: cannot import name 'load_trust_config'`

- [ ] **Step 3: Add loader support**

Edit `policyforge/loader.py`. Two changes.

**(a)** Add this block below the existing `_validate_policy` function and before the `# Parsing helpers` banner:

```python
# --------------------------------------------------------------------------- #
# Trust config (tool_trust: top-level block)
# --------------------------------------------------------------------------- #

from policyforge.trust.models import TrustConfig, TrustMode, TrustVerdict  # noqa: E402

_TRUST_ALLOWED_KEYS = {
    "mode",
    "ledger_path",
    "on_mismatch",
    "on_unknown",
    "auto_approve",
    "detect_shadowing",
}
_SHADOW_ALLOWED_KEYS = {"nfkc", "confusables"}


def load_trust_config(raw: dict[str, Any] | None) -> TrustConfig:
    """Parse a `tool_trust:` YAML block into a TrustConfig.

    ``raw=None`` returns the default (disabled) config.
    """
    if raw is None:
        return TrustConfig()
    if not isinstance(raw, dict):
        raise PolicyValidationError("tool_trust block must be a mapping.")

    unknown = raw.keys() - _TRUST_ALLOWED_KEYS
    if unknown:
        raise PolicyValidationError(f"tool_trust has unknown keys: {unknown}")

    try:
        mode = TrustMode(str(raw.get("mode", "disabled")).lower())
    except ValueError as exc:
        raise PolicyValidationError(f"tool_trust has invalid mode: {exc}") from exc

    try:
        on_mismatch = TrustVerdict(str(raw.get("on_mismatch", "DENY")).upper())
        on_unknown = TrustVerdict(str(raw.get("on_unknown", "DENY")).upper())
    except ValueError as exc:
        raise PolicyValidationError(f"tool_trust has invalid verdict: {exc}") from exc

    ledger_path_raw = raw.get("ledger_path")
    if ledger_path_raw is None:
        ledger_path = TrustConfig().ledger_path
    else:
        ledger_path = Path(str(ledger_path_raw))

    shadow = raw.get("detect_shadowing") or {}
    if not isinstance(shadow, dict):
        raise PolicyValidationError("detect_shadowing must be a mapping.")
    unknown_shadow = shadow.keys() - _SHADOW_ALLOWED_KEYS
    if unknown_shadow:
        raise PolicyValidationError(
            f"detect_shadowing has unknown keys: {unknown_shadow}"
        )

    return TrustConfig(
        mode=mode,
        ledger_path=ledger_path,
        on_mismatch=on_mismatch,
        on_unknown=on_unknown,
        auto_approve=bool(raw.get("auto_approve", False)),
        detect_nfkc=bool(shadow.get("nfkc", True)),
        detect_confusables=bool(shadow.get("confusables", True)),
    )
```

**(b)** Modify `PolicyLoader.load_file` to extract and remember a `tool_trust:` block. Replace the whole `PolicyLoader` class with:

```python
class PolicyLoader:
    """Load and validate policies from YAML files or directories."""

    def __init__(self) -> None:
        self.trust_config: TrustConfig | None = None

    def load_file(self, path: str | Path) -> list[Policy]:
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Policy file not found: {path}")
        if path.suffix not in (".yaml", ".yml"):
            raise PolicyValidationError(f"Expected .yaml/.yml file, got: {path.suffix}")

        text = path.read_text(encoding="utf-8")
        docs: list[dict[str, Any]] = []

        for doc in yaml.safe_load_all(text):
            if doc is None:
                continue
            if isinstance(doc, dict) and "tool_trust" in doc:
                self.trust_config = load_trust_config(doc.get("tool_trust"))
            if isinstance(doc, dict) and "policies" in doc:
                if not isinstance(doc["policies"], list):
                    raise PolicyValidationError(
                        f"Top-level 'policies' in {path} must be declared as a list."
                    )
                docs.extend(doc["policies"])
            elif isinstance(doc, list):
                docs.extend(doc)
            elif isinstance(doc, dict) and "policies" not in doc and "tool_trust" not in doc:
                docs.append(doc)

        policies: list[Policy] = []
        for raw in docs:
            _validate_policy(raw, str(path))
            policies.append(_parse_policy(raw))
            logger.info(
                "Loaded policy '%s' v%s from %s",
                policies[-1].name,
                policies[-1].version,
                path,
            )

        return policies

    def load_directory(self, path: str | Path) -> list[Policy]:
        path = Path(path)
        if not path.is_dir():
            raise NotADirectoryError(f"Policy directory not found: {path}")

        policies: list[Policy] = []
        for yaml_file in sorted(path.rglob("*.y*ml")):
            if yaml_file.suffix in (".yaml", ".yml"):
                try:
                    policies.extend(self.load_file(yaml_file))
                except (PolicyValidationError, yaml.YAMLError, ValueError) as exc:
                    logger.error("Skipping invalid policy file %s: %s", yaml_file, exc)

        logger.info("Loaded %d policies from %s", len(policies), path)
        return policies
```

- [ ] **Step 4: Run tests**

Run: `pytest tests/test_loader.py -v`
Expected: PASS for all loader tests (existing + the 5 new ones).

- [ ] **Step 5: Verify no regressions**

Run: `pytest -v`
Expected: PASS across the whole suite.

- [ ] **Step 6: Commit**

```bash
git add policyforge/loader.py tests/test_loader.py
git commit -m "feat(loader): parse tool_trust YAML block into TrustConfig"
```

---

## Task 6: Wire `TrustManager` into `PolicyEngine`

**Files:**
- Modify: `policyforge/engine.py`
- Test: `tests/test_engine_trust_integration.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_engine_trust_integration.py`:

```python
"""Integration tests: PolicyEngine + TrustManager pre-flight."""

from pathlib import Path

import pytest

from policyforge.engine import PolicyEngine
from policyforge.models import Verdict
from policyforge.trust.ledger import LedgerWriter
from policyforge.trust.manager import TrustManager
from policyforge.trust.models import (
    ToolFingerprint,
    TrustConfig,
    TrustMode,
    TrustVerdict,
)


@pytest.fixture
def policy_file(tmp_path: Path) -> Path:
    f = tmp_path / "allow_all.yaml"
    f.write_text(
        """
name: allow_all
default_verdict: ALLOW
rules:
  - name: permissive
    conditions:
      - field: tool_name
        operator: regex
        value: ".*"
    verdict: ALLOW
""",
        encoding="utf-8",
    )
    return f


@pytest.fixture
def ledger_path(tmp_path: Path) -> Path:
    return tmp_path / "approvals.jsonl"


def _pin(ledger_path: Path, name: str = "create_issue") -> ToolFingerprint:
    fp = ToolFingerprint(
        server_id="mcp://github",
        name=name,
        schema_hash="a" * 64,
        description_hash="b" * 64,
        first_seen=1.0,
        approved_by="operator",
    )
    LedgerWriter(path=ledger_path, hmac_key="k").append(fp)
    return fp


class TestBackwardsCompat:
    def test_engine_without_trust_manager_behaves_identically(self, policy_file):
        engine = PolicyEngine(policy_paths=[policy_file])
        decision = engine.evaluate(tool_name="anything", args={})
        assert decision.verdict == Verdict.ALLOW


class TestTrustPreflight:
    def test_unknown_tool_denied_before_rules(self, policy_file, ledger_path):
        ledger_path.touch()
        tm = TrustManager(
            TrustConfig(mode=TrustMode.ENFORCE, ledger_path=ledger_path),
            hmac_key="k",
        )
        engine = PolicyEngine(policy_paths=[policy_file], trust_manager=tm)
        decision = engine.evaluate(
            tool_name="unseen",
            args={},
            context={"tool": {"server_id": "mcp://x",
                              "schema_hash": "s" * 64,
                              "description_hash": "d" * 64}},
        )
        assert decision.verdict == Verdict.DENY
        assert decision.matched_rule == "tool_unknown"

    def test_drift_denied_before_rules(self, policy_file, ledger_path):
        pinned = _pin(ledger_path)
        tm = TrustManager(
            TrustConfig(mode=TrustMode.ENFORCE, ledger_path=ledger_path),
            hmac_key="k",
        )
        engine = PolicyEngine(policy_paths=[policy_file], trust_manager=tm)
        decision = engine.evaluate(
            tool_name=pinned.name,
            args={},
            context={"tool": {"server_id": pinned.server_id,
                              "schema_hash": "q" * 64,
                              "description_hash": pinned.description_hash}},
        )
        assert decision.verdict == Verdict.DENY
        assert decision.matched_rule == "fingerprint_drift"

    def test_pinned_match_falls_through_to_rules(self, policy_file, ledger_path):
        pinned = _pin(ledger_path)
        tm = TrustManager(
            TrustConfig(mode=TrustMode.ENFORCE, ledger_path=ledger_path),
            hmac_key="k",
        )
        engine = PolicyEngine(policy_paths=[policy_file], trust_manager=tm)
        decision = engine.evaluate(
            tool_name=pinned.name,
            args={},
            context={"tool": {"server_id": pinned.server_id,
                              "schema_hash": pinned.schema_hash,
                              "description_hash": pinned.description_hash}},
        )
        assert decision.verdict == Verdict.ALLOW
        assert decision.matched_rule == "permissive"


class TestTrustAudit:
    def test_trust_denial_emits_audit_event(
        self, policy_file, ledger_path, tmp_path, monkeypatch
    ):
        monkeypatch.setenv("POLICYFORGE_HMAC_KEY", "k")
        from policyforge.audit import AuditLogger

        audit = AuditLogger(log_dir=tmp_path / "audit")
        tm = TrustManager(
            TrustConfig(mode=TrustMode.ENFORCE, ledger_path=ledger_path),
            hmac_key="k",
        )
        ledger_path.touch()
        engine = PolicyEngine(
            policy_paths=[policy_file], trust_manager=tm, audit_logger=audit
        )
        engine.evaluate(
            tool_name="unseen",
            args={},
            context={"tool": {"server_id": "mcp://x",
                              "schema_hash": "s" * 64,
                              "description_hash": "d" * 64}},
        )
        # At least one audit record with verdict DENY and rule "tool_unknown"
        files = list((tmp_path / "audit").glob("*.jsonl"))
        assert files, "no audit log file written"
        content = files[0].read_text(encoding="utf-8")
        assert "tool_unknown" in content
        assert "DENY" in content
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_engine_trust_integration.py -v`
Expected: FAIL — `TypeError: PolicyEngine.__init__() got an unexpected keyword argument 'trust_manager'`

- [ ] **Step 3: Modify `PolicyEngine`**

Edit `policyforge/engine.py`. Two changes.

**(a)** At the top of the file, add the import:

```python
from policyforge.trust.manager import TrustManager
from policyforge.trust.models import TrustVerdict
```

**(b)** Replace the `PolicyEngine.__init__` signature and add a pre-flight helper. Update `__init__`:

```python
    def __init__(
        self,
        policy_paths: list[str | Path] | None = None,
        audit_logger: AuditLogger | None = None,
        agent_id: str = "default",
        trust_manager: TrustManager | None = None,
    ) -> None:
        self._loader = PolicyLoader()
        self._policies: list[Policy] = []
        self._audit = audit_logger
        self._agent_id = agent_id
        self._trust = trust_manager

        if policy_paths:
            for p in policy_paths:
                self.load(p)
```

**(c)** Add a `_preflight_trust` method on the class (place it directly above `_run_evaluation`):

```python
    def _preflight_trust(
        self, tool_name: str, context: dict[str, Any]
    ) -> Decision | None:
        """Run the trust manager before rule evaluation. Return a DENY/LOG_ONLY
        decision to short-circuit, or None to continue."""
        if self._trust is None:
            return None
        result = self._trust.check(
            tool_name=tool_name,
            tool_meta=context.get("tool"),
        )
        if result.verdict == TrustVerdict.ALLOW:
            return None
        verdict = (
            Verdict.DENY if result.verdict == TrustVerdict.DENY else Verdict.LOG_ONLY
        )
        return Decision(
            verdict=verdict,
            matched_rule=result.reason,
            policy_name="tool_trust",
            message=result.message,
        )
```

**(d)** Modify `evaluate()` to call pre-flight. Insert the block **immediately after** `start = time.perf_counter()` and **before** `decision = self._run_evaluation(eval_context)`:

```python
        trust_decision = self._preflight_trust(tool_name, eval_context)
        if trust_decision is not None:
            decision = trust_decision
        else:
            decision = self._run_evaluation(eval_context)
```

Remove the original `decision = self._run_evaluation(eval_context)` line — it's replaced by the branch above.

- [ ] **Step 4: Run tests**

Run: `pytest tests/test_engine_trust_integration.py -v`
Expected: PASS (5 tests).

- [ ] **Step 5: Run full suite for regressions**

Run: `pytest -v`
Expected: all existing tests still pass; engine's backwards compat is preserved (first test of this task validates it).

- [ ] **Step 6: Commit**

```bash
git add policyforge/engine.py tests/test_engine_trust_integration.py
git commit -m "feat(engine): wire TrustManager pre-flight into PolicyEngine"
```

---

## Task 7: Public exports and example YAML

**Files:**
- Modify: `policyforge/__init__.py`
- Create: `policyforge/policies/tool_trust_example.yaml`

- [ ] **Step 1: Inspect current exports**

Run: `cat policyforge/__init__.py`

- [ ] **Step 2: Add new exports**

Edit `policyforge/__init__.py` and append `TrustManager`, `TrustConfig`, `ToolFingerprint`, `TrustMode`, `TrustVerdict` to the imports and `__all__` list (follow the existing import style — if the file uses `from policyforge.X import Y`, match it).

If the file has no `__all__`, add:

```python
from policyforge.trust import (
    ToolFingerprint,
    TrustConfig,
    TrustManager,
    TrustMode,
    TrustVerdict,
)
```

and include those names in `__all__` alongside the existing exports.

- [ ] **Step 3: Create the example YAML**

Create `policyforge/policies/tool_trust_example.yaml`:

```yaml
# Example: enable tool fingerprint pinning.
#
# With this block in place, PolicyEngine will refuse tool calls whose
# (server_id, name, schema_hash, description_hash) drifts from an
# entry in the approvals ledger, or whose name visually shadows an
# approved one via Unicode tricks (Cyrillic/Greek lookalikes, NFKC
# collisions).
#
# auto_approve is documented as dev-only.  In production, pin
# fingerprints deliberately via tooling and leave auto_approve: false.

tool_trust:
  mode: enforce                     # enforce | warn | disabled
  ledger_path: .policyforge/approvals.jsonl
  on_mismatch: DENY
  on_unknown: DENY
  auto_approve: false               # DEV ONLY — silently pins any unseen tool
  detect_shadowing:
    nfkc: true
    confusables: true

policies:
  - name: example
    description: Trivial pass-through policy that demonstrates the trust block.
    default_verdict: ALLOW
    rules:
      - name: allow_all
        conditions:
          - field: tool_name
            operator: regex
            value: ".*"
        verdict: ALLOW
```

- [ ] **Step 4: Smoke test the example loads**

Run:

```bash
python -c "from policyforge.loader import PolicyLoader; L = PolicyLoader(); L.load_file('policyforge/policies/tool_trust_example.yaml'); print(L.trust_config)"
```

Expected: prints a `TrustConfig(mode=<TrustMode.ENFORCE: 'enforce'>, ...)` with the fields from the YAML.

- [ ] **Step 5: Commit**

```bash
git add policyforge/__init__.py policyforge/policies/tool_trust_example.yaml
git commit -m "feat(trust): expose public API and add example YAML"
```

---

## Task 8: Lint, type-check, coverage gate

- [ ] **Step 1: Run ruff**

Run: `ruff check policyforge tests`
Expected: clean. Fix any findings (typically unused imports or long lines).

- [ ] **Step 2: Run black**

Run: `black --check policyforge tests`
Expected: clean. If it fails, run `black policyforge tests` and commit the formatting.

- [ ] **Step 3: Run mypy strict**

Run: `mypy policyforge`
Expected: clean. Common fixes: annotate the `self._writer` / `self._reader` Optional properly, add return-type annotations on the helper functions.

- [ ] **Step 4: Check coverage**

Run: `pytest --cov=policyforge --cov-branch --cov-report=term-missing`
Expected: branch coverage ≥ 90% (the gate CI enforces — `ec8291e Enforce 90% branch coverage gate in CI`). If below, add tests for the missing branches in `manager.py` (most likely the "warn + on_mismatch=LOG_ONLY" edge paths) or in `ledger.py` (the recover-last-hash-from-existing-file path).

- [ ] **Step 5: Commit any lint/type fixes**

```bash
git add -u
git commit -m "chore(trust): satisfy lint, type-check, coverage gate"
```

---

## Task 9: Update README threat-model section

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Add a section**

Open `README.md`, locate a reasonable position (after an existing "Features" or "Overview" section), and insert:

```markdown
## Threat Model

PolicyForge gates agent tool calls against three attack classes, each
addressed by a dedicated subsystem.  This release ships the first.

### Tool fingerprint pinning (this release)

Defends against MCP tool poisoning, rug-pull (tool definitions changing
after approval), typosquatting, and cross-server name shadowing.

Every call's `(server_id, name, schema_hash, description_hash)` is
compared against a project-local, HMAC-chained approvals ledger at
`.policyforge/approvals.jsonl`.  Drift or Unicode shadowing
(Cyrillic/Greek homoglyphs, NFKC collisions) short-circuits the
evaluation with `DENY`.

See `policyforge/policies/tool_trust_example.yaml` for configuration.

### Provenance-tagged args (next release)

Defends indirect prompt injection and confused-deputy attacks by
letting rules deny based on the *origin* of an argument (user, web,
rag, tool output) rather than its content.

### Lethal-trifecta detector (future)

Defends exfiltration chains (read private data → ingest untrusted
content → post externally) by maintaining per-session capability
state and denying the call that would close the trifecta.
```

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "docs: add threat-model section covering fingerprint pinning"
```

---

## Self-Review

Before handing off for execution, the plan was checked against the spec:

**Spec coverage:**
- §4.1 Purpose → Tasks 4, 6.
- §4.2 Attack coverage → Tasks 2 (shadowing), 4 (drift + unknown), Task 9 docs.
- §4.3 Data model → Task 1.
- §4.4 Ledger → Task 3.
- §4.5 YAML shape → Task 5 (loader) + Task 7 (example).
- §4.6 Evaluation flow → Task 6.
- §4.7 Module layout → every task.
- §4.8 Confusables → Task 2.
- §4.9 Testing → all tasks (tests written first every step).
- §7.1 Backwards compatibility → Task 6, first test.
- §7.3 Audit → Task 6, `TestTrustAudit`.
- §7.5 Testing strategy (90% branch coverage) → Task 8.
- §7.6 Documentation → Tasks 7, 9.

No spec section is unaddressed.

**Placeholder scan:** No TBDs, no "similar to", no "appropriate error handling". Every code block is complete.

**Type consistency:** `TrustManager.check()` signature matches between Task 4's implementation and Task 6's engine wiring. `ToolFingerprint` fields match between Task 1 and their uses in Tasks 3, 4, 6. `TrustResult.verdict` is `TrustVerdict`, not `Verdict`, throughout.
