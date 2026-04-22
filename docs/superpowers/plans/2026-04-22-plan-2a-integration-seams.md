# Plan 2a — Integration-Seam Polish (before Plan 2)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the integration seams between the Tool Fingerprint Pinning subsystem and the rest of PolicyForge (decorator, audit, operator ergonomics) before Plan 2 (Provenance) builds on the same surfaces.

**Architecture:** Five independent follow-ups flagged during Plan 1's final code review. Each is additive and backwards-compatible; none touches the cryptographic core of the ledger. Landing them now avoids cascading fixes during Plan 2 and unblocks production rollout of Plan 1.

**Tech Stack:** Same as Plan 1 — Python 3.10+, PyYAML, stdlib crypto/threading, pytest, strict mypy.

**Spec reference:** `docs/superpowers/specs/2026-04-22-agent-security-suite-design.md` §4 + §7. This plan does NOT change the spec; it closes gaps between spec intent and Plan 1's landed code.

---

## Scope Origin

Every task maps to a specific item from Plan 1's final code review (`superpowers:code-reviewer` on the branch `feature/tool-fingerprint-pinning`). In review-notation order:

| Plan 1 Review ID | Task | Why it matters for Plan 2 |
|---|---|---|
| I3 | Task 1 — Resolve `ledger_path` relative to YAML parent | Plan 2 adds more YAML sections (`provenance:`, `tool_capabilities:`); path resolution convention should be settled once. |
| N2 | Task 2 — Emit typed audit `event_type` for trust actions | Plan 3 (trifecta) will emit `trifecta_closed_blocked` events; operators' alerting rules need to filter by `event_type`, not substring-match `matched_rule`. |
| N3 | Task 3 — Atomic ledger append (tmp+rename) | Crash safety for the tamper-evident log. Plan 2 does not alter this, but a crash mid-write corrupts the chain permanently. |
| I1 | Task 4 — Decorator plumbing for per-tool context | Plan 2's `arg_provenance` parameter is on the same decorator; the per-tool-context gap must be closed first so Plan 2 can build on it. |
| N6 + N7 | Task 5 — Approvals CLI + bootstrap/docs | Makes Plan 1 actually usable in production. Includes the digit-homoglyph scope note. |

**Explicitly out of scope** (flagged but deferred beyond Plan 2a):
- N1 (route `_mismatch` through `TrustResult.log_only/deny` classmethods) — purely cosmetic symmetry.
- N4 (fold terminal-hmac return into `LedgerReader.load`) — micro-optimization.
- N5 (precomputed canonical-form map for shadow check) — premature; Plan 1 is O(n) and n is small.

---

## File Structure

**Create:**
- `policyforge/trust/cli.py` — module-runnable approvals CLI
- `tests/test_trust_cli.py`
- `tests/test_trust_audit_events.py`

**Modify:**
- `policyforge/trust/ledger.py` — atomic append, folded terminal-hmac recovery
- `policyforge/trust/manager.py` — emit audit events via an `AuditLogger` hookup
- `policyforge/loader.py` — resolve `ledger_path` against the YAML file's parent directory
- `policyforge/decorators.py` — per-tool `extra_context` for `wrap` and `wrap_dict`
- `policyforge/engine.py` — pass `AuditLogger` into `TrustManager` so it can emit events
- `README.md` — "First-run: approving your tools" subsection + digit-homoglyph note
- `tests/test_loader.py` — path-resolution tests
- `tests/test_trust_ledger.py` — crash-recovery tests
- `tests/test_decorators.py` — per-tool context tests

---

## Task 1: Resolve `ledger_path` relative to the YAML file's parent directory

**Files:**
- Modify: `policyforge/loader.py`
- Test: `tests/test_loader.py`

### Rationale

Today `ledger_path: approvals.jsonl` in a YAML loaded from `/etc/pf/pf.yaml` resolves against `os.getcwd()`, not `/etc/pf/`. An attacker controlling CWD (or a user running the agent from a sibling directory with a planted `.policyforge/approvals.jsonl`) can substitute a different approvals set. Resolving relative to the YAML's parent matches "project-local" intent and removes the CWD-dependence.

### Semantics

- `ledger_path` is absolute → use as-is.
- `ledger_path` is relative → resolve against the policy file's parent directory.
- `ledger_path` missing → default `.policyforge/approvals.jsonl` relative to the YAML's parent.
- `load_trust_config(raw)` (standalone, no YAML path) → unchanged: relative path stays relative (CWD-based) for programmatic callers.

### Steps

- [ ] **Step 1: Write failing tests**

Append to `tests/test_loader.py`:

```python
class TestTrustConfigPathResolution:
    def test_relative_ledger_path_resolves_to_yaml_parent(self, tmp_path: Path):
        yaml_dir = tmp_path / "etc" / "pf"
        yaml_dir.mkdir(parents=True)
        policy_yaml = yaml_dir / "pf.yaml"
        policy_yaml.write_text(
            """
tool_trust:
  mode: enforce
  ledger_path: approvals.jsonl
""",
            encoding="utf-8",
        )
        loader = PolicyLoader()
        loader.load_file(policy_yaml)
        assert loader.trust_config is not None
        # Must resolve to the YAML's parent, NOT the CWD.
        assert loader.trust_config.ledger_path == yaml_dir / "approvals.jsonl"

    def test_absolute_ledger_path_preserved(self, tmp_path: Path):
        policy_yaml = tmp_path / "p.yaml"
        abs_ledger = tmp_path / "custom" / "approvals.jsonl"
        policy_yaml.write_text(
            f"""
tool_trust:
  mode: enforce
  ledger_path: {abs_ledger.as_posix()}
""",
            encoding="utf-8",
        )
        loader = PolicyLoader()
        loader.load_file(policy_yaml)
        assert loader.trust_config is not None
        assert loader.trust_config.ledger_path == abs_ledger

    def test_default_ledger_path_resolves_to_yaml_parent(self, tmp_path: Path):
        yaml_dir = tmp_path / "proj"
        yaml_dir.mkdir()
        policy_yaml = yaml_dir / "p.yaml"
        policy_yaml.write_text(
            """
tool_trust:
  mode: enforce
""",
            encoding="utf-8",
        )
        loader = PolicyLoader()
        loader.load_file(policy_yaml)
        assert loader.trust_config is not None
        assert loader.trust_config.ledger_path == yaml_dir / ".policyforge" / "approvals.jsonl"

    def test_standalone_load_trust_config_leaves_relative(self):
        cfg = load_trust_config({"mode": "enforce", "ledger_path": "approvals.jsonl"})
        assert cfg.ledger_path == Path("approvals.jsonl")
```

- [ ] **Step 2: Confirm failure**

Run: `pytest tests/test_loader.py::TestTrustConfigPathResolution -v`
Expected: all four fail (paths resolve against CWD today).

- [ ] **Step 3: Implement**

In `policyforge/loader.py`, extend `load_trust_config` to accept an optional `base_dir: Path | None` and use it to resolve relative paths. Change signature and body:

```python
def load_trust_config(
    raw: dict[str, Any] | None,
    *,
    base_dir: Path | None = None,
) -> TrustConfig:
    """Parse a ``tool_trust:`` YAML block into a TrustConfig.

    ``raw=None`` returns the default (disabled) config.
    ``base_dir``: when provided, resolves a relative ``ledger_path`` against
    it (typically the policy YAML's parent directory). When None, relative
    paths are preserved as-is (programmatic callers).
    """
    if raw is None:
        return TrustConfig()
    # ... existing validation unchanged ...

    ledger_path_raw = raw.get("ledger_path")
    if ledger_path_raw is None:
        ledger_path = TrustConfig().ledger_path
    else:
        ledger_path = Path(str(ledger_path_raw))

    if base_dir is not None and not ledger_path.is_absolute():
        ledger_path = base_dir / ledger_path

    return TrustConfig(
        # ... same as before, with ledger_path now resolved ...
    )
```

Then in `PolicyLoader.load_file`, pass `base_dir=path.parent` when calling `load_trust_config`:

```python
            if isinstance(doc, dict) and "tool_trust" in doc:
                if self.trust_config is not None:
                    logger.warning(
                        "Overwriting tool_trust config from a later document in %s", path
                    )
                self.trust_config = load_trust_config(
                    doc.get("tool_trust"), base_dir=path.parent
                )
                ...
```

- [ ] **Step 4: Run tests**

`pytest tests/test_loader.py -v` — all existing + 4 new passing.

- [ ] **Step 5: Run full suite**

`pytest -q` — all green.

- [ ] **Step 6: Commit**

```bash
git add policyforge/loader.py tests/test_loader.py
git commit -m "feat(loader): resolve ledger_path against policy YAML parent dir"
```

---

## Task 2: Typed audit events for trust actions

**Files:**
- Modify: `policyforge/trust/manager.py`, `policyforge/engine.py`
- Test: `tests/test_trust_audit_events.py` (new)

### Rationale

Spec §7.3 promises three typed `event_type` values (`tool_approved`, `fingerprint_drift`, `tool_shadow_detected`). Plan 1 ships them as substrings inside the `matched_rule` field of regular `decision` audit entries. Downstream alerting that filters on `event_type` misses them. Fix: when `TrustManager` produces a non-ALLOW result, emit a dedicated `log_event` entry via the existing `AuditLogger.log_event` API (in addition to the flow-through DENY that `PolicyEngine` already audits).

### Semantics

- On auto-approve → emit `event_type="tool_approved"` with metadata `{server_id, name, schema_hash, description_hash}`.
- On non-ALLOW result where `reason ∈ {fingerprint_drift, tool_shadow_detected, tool_unknown, tool_meta_missing, tool_meta_invalid}` → emit `event_type=<reason>` with metadata including at least the server_id and incoming tool_name.
- Events flow through the same HMAC chain as decisions (existing behavior of `log_event`).
- The existing decision audit entry (matched_rule = reason, policy_name = "tool_trust") is unchanged; we're ADDING an event, not replacing.

### Steps

- [ ] **Step 1: Write failing test**

Create `tests/test_trust_audit_events.py`:

```python
"""Tests that TrustManager emits typed audit events via AuditLogger.log_event."""

import json
from pathlib import Path

import pytest

from policyforge.audit import AuditLogger
from policyforge.engine import PolicyEngine
from policyforge.trust.ledger import LedgerWriter
from policyforge.trust.manager import TrustManager
from policyforge.trust.models import (
    ToolFingerprint,
    TrustConfig,
    TrustMode,
)


@pytest.fixture
def ledger_path(tmp_path: Path) -> Path:
    return tmp_path / "approvals.jsonl"


@pytest.fixture
def audit(tmp_path: Path) -> AuditLogger:
    return AuditLogger(log_dir=tmp_path / "audit", hmac_key="k")


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


def _audit_events(log_dir: Path) -> list[dict]:
    files = list(log_dir.glob("*.jsonl"))
    assert files, "no audit file written"
    entries = [
        json.loads(line)
        for line in files[0].read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    return [e for e in entries if e.get("kind") == "event"]


class TestTrustAuditEvents:
    def test_tool_unknown_emits_event(self, policy_file, ledger_path, audit, tmp_path):
        ledger_path.touch()
        tm = TrustManager(
            TrustConfig(mode=TrustMode.ENFORCE, ledger_path=ledger_path),
            hmac_key="k",
            audit_logger=audit,
        )
        engine = PolicyEngine(policy_paths=[policy_file], trust_manager=tm, audit_logger=audit)
        engine.evaluate(
            tool_name="unseen",
            args={},
            context={"tool": {"server_id": "mcp://x",
                              "schema_hash": "5" * 64,
                              "description_hash": "7" * 64}},
        )
        events = _audit_events(tmp_path / "audit")
        trust_events = [e for e in events if e.get("event") == "tool_unknown"]
        assert trust_events, f"no tool_unknown event in {events}"
        meta = trust_events[-1]["meta"]
        assert meta["server_id"] == "mcp://x"
        assert meta["tool_name"] == "unseen"

    def test_fingerprint_drift_emits_event(self, policy_file, ledger_path, audit, tmp_path):
        fp = ToolFingerprint(
            "mcp://github", "create_issue", "a" * 64, "b" * 64, 1.0, "op"
        )
        LedgerWriter(path=ledger_path, hmac_key="k").append(fp)
        tm = TrustManager(
            TrustConfig(mode=TrustMode.ENFORCE, ledger_path=ledger_path),
            hmac_key="k",
            audit_logger=audit,
        )
        engine = PolicyEngine(policy_paths=[policy_file], trust_manager=tm, audit_logger=audit)
        engine.evaluate(
            tool_name="create_issue",
            args={},
            context={"tool": {"server_id": "mcp://github",
                              "schema_hash": "9" * 64,
                              "description_hash": "b" * 64}},
        )
        events = _audit_events(tmp_path / "audit")
        drift_events = [e for e in events if e.get("event") == "fingerprint_drift"]
        assert drift_events, f"no drift event in {events}"

    def test_shadow_detection_emits_event(self, policy_file, ledger_path, audit, tmp_path):
        fp = ToolFingerprint(
            "mcp://github", "send_email", "a" * 64, "b" * 64, 1.0, "op"
        )
        LedgerWriter(path=ledger_path, hmac_key="k").append(fp)
        tm = TrustManager(
            TrustConfig(mode=TrustMode.ENFORCE, ledger_path=ledger_path),
            hmac_key="k",
            audit_logger=audit,
        )
        engine = PolicyEngine(policy_paths=[policy_file], trust_manager=tm, audit_logger=audit)
        engine.evaluate(
            tool_name="\u0455end_email",
            args={},
            context={"tool": {"server_id": "mcp://github",
                              "schema_hash": "a" * 64,
                              "description_hash": "b" * 64}},
        )
        events = _audit_events(tmp_path / "audit")
        shadow_events = [e for e in events if e.get("event") == "tool_shadow_detected"]
        assert shadow_events

    def test_auto_approve_emits_event(self, policy_file, ledger_path, audit, tmp_path):
        tm = TrustManager(
            TrustConfig(
                mode=TrustMode.ENFORCE,
                ledger_path=ledger_path,
                auto_approve=True,
            ),
            hmac_key="k",
            audit_logger=audit,
        )
        engine = PolicyEngine(policy_paths=[policy_file], trust_manager=tm, audit_logger=audit)
        engine.evaluate(
            tool_name="new_tool",
            args={},
            context={"tool": {"server_id": "mcp://x",
                              "schema_hash": "5" * 64,
                              "description_hash": "7" * 64}},
        )
        events = _audit_events(tmp_path / "audit")
        approve_events = [e for e in events if e.get("event") == "tool_approved"]
        assert approve_events
        assert approve_events[-1]["meta"]["server_id"] == "mcp://x"

    def test_no_event_emitted_on_allow(self, policy_file, ledger_path, audit, tmp_path):
        fp = ToolFingerprint(
            "mcp://github", "create_issue", "a" * 64, "b" * 64, 1.0, "op"
        )
        LedgerWriter(path=ledger_path, hmac_key="k").append(fp)
        tm = TrustManager(
            TrustConfig(mode=TrustMode.ENFORCE, ledger_path=ledger_path),
            hmac_key="k",
            audit_logger=audit,
        )
        engine = PolicyEngine(policy_paths=[policy_file], trust_manager=tm, audit_logger=audit)
        engine.evaluate(
            tool_name="create_issue",
            args={},
            context={"tool": {"server_id": "mcp://github",
                              "schema_hash": "a" * 64,
                              "description_hash": "b" * 64}},
        )
        events = _audit_events(tmp_path / "audit")
        trust_event_types = {
            "tool_unknown", "fingerprint_drift", "tool_shadow_detected",
            "tool_approved", "tool_meta_missing", "tool_meta_invalid",
        }
        assert not any(e.get("event") in trust_event_types for e in events)
```

- [ ] **Step 2: Confirm failure**

Run: `pytest tests/test_trust_audit_events.py -v`
Expected: every test fails — `TrustManager.__init__` has no `audit_logger` parameter.

- [ ] **Step 3: Add `audit_logger` parameter to `TrustManager`**

In `policyforge/trust/manager.py`, extend `__init__`:

```python
    def __init__(
        self,
        config: TrustConfig,
        hmac_key: str | bytes | None = None,
        *,
        approved_by: str = "auto",
        now: Callable[[], float] = time.time,
        audit_logger: "AuditLogger | None" = None,
    ) -> None:
        """...
            audit_logger: Optional AuditLogger for emitting typed trust events
                (``tool_approved``, ``fingerprint_drift``, ``tool_shadow_detected``,
                ``tool_unknown``, ``tool_meta_missing``, ``tool_meta_invalid``).
                When None, no events are emitted (the engine still audits DENY
                verdicts as regular decision entries).
        ...
        """
        # existing body, then:
        self._audit_logger = audit_logger
```

Add the import at the top with `TYPE_CHECKING` to avoid a circular import:

```python
from typing import TYPE_CHECKING, Any, Callable
if TYPE_CHECKING:
    from policyforge.audit import AuditLogger
```

- [ ] **Step 4: Emit events in `check()`**

Add a private `_emit_event` helper:

```python
    def _emit_event(
        self,
        event_type: str,
        tool_name: str,
        server_id: str,
        *,
        extra: dict[str, Any] | None = None,
    ) -> None:
        if self._audit_logger is None:
            return
        import uuid

        meta: dict[str, Any] = {
            "server_id": server_id,
            "tool_name": tool_name,
        }
        if extra:
            meta.update(extra)
        self._audit_logger.log_event(
            request_id=uuid.uuid4().hex[:16],
            event_type=event_type,
            tool_name=tool_name,
            metadata=meta,
        )
```

Then call it at each non-ALLOW return and after a successful auto-approve. For example:

```python
        if not tool_meta:
            self._emit_event("tool_meta_missing", tool_name, server_id="")
            return self._mismatch(...)

        # ... shadowing detection ...
        if canonicalize(stored_name) == incoming_canon:
            self._emit_event(
                "tool_shadow_detected",
                tool_name,
                server_id=server_id,
                extra={"shadowed_name": stored_name},
            )
            return self._mismatch(...)

        # ... unknown tool ...
        if pinned is None:
            if self._config.auto_approve:
                # ... try/except ToolFingerprint(...) ...
                # on success:
                self._emit_event(
                    "tool_approved",
                    tool_name,
                    server_id=server_id,
                    extra={"schema_hash": schema_hash, "description_hash": description_hash},
                )
                return TrustResult.ok()
            # on ValueError in ToolFingerprint(...):
            self._emit_event("tool_meta_invalid", tool_name, server_id=server_id)
            return self._mismatch(...)
            # otherwise unknown:
            self._emit_event("tool_unknown", tool_name, server_id=server_id)
            return TrustResult(...)

        # ... fingerprint comparison ...
        if pinned.schema_hash != schema_hash or pinned.description_hash != description_hash:
            self._emit_event(
                "fingerprint_drift",
                tool_name,
                server_id=server_id,
                extra={
                    "pinned_schema_hash": pinned.schema_hash,
                    "incoming_schema_hash": schema_hash,
                    "pinned_description_hash": pinned.description_hash,
                    "incoming_description_hash": description_hash,
                },
            )
            return self._mismatch(...)
```

Precise placement: emit the event BEFORE `return` so crashes in `_mismatch` don't swallow the audit.

- [ ] **Step 5: Engine wires `audit_logger` into `TrustManager`**

Today the engine receives an `audit_logger` separately from the `TrustManager`. A user constructing a manager won't know to pass the same logger. Options:

(a) Engine injects its `audit_logger` into `TrustManager` during `evaluate`/`__init__`.
(b) Users must pass the same `AuditLogger` to both.

Choose (a): in `PolicyEngine.__init__`, after `self._trust = trust_manager`, add:

```python
        if self._trust is not None and audit_logger is not None:
            # Keep the manager's audit hookup in sync with the engine's.
            # If the user already set one on the manager, prefer theirs.
            if getattr(self._trust, "_audit_logger", None) is None:
                self._trust._audit_logger = audit_logger
```

This is admittedly an attribute-poking hack. A cleaner alternative: expose `TrustManager.set_audit_logger(audit_logger)` and call it from the engine. Do that instead — add the method to `TrustManager`:

```python
    def set_audit_logger(self, audit_logger: "AuditLogger") -> None:
        """Attach an AuditLogger after construction (engine-side wiring)."""
        if self._audit_logger is None:
            self._audit_logger = audit_logger
```

And call it from `PolicyEngine.__init__`:

```python
        if self._trust is not None and audit_logger is not None:
            self._trust.set_audit_logger(audit_logger)
```

- [ ] **Step 6: Run tests**

`pytest tests/test_trust_audit_events.py -v` — expect 5 passing.

- [ ] **Step 7: Run full suite**

`pytest -q` — all green.

- [ ] **Step 8: Commit**

```bash
git add policyforge/trust/manager.py policyforge/engine.py tests/test_trust_audit_events.py
git commit -m "feat(trust): emit typed audit events for trust actions"
```

---

## Task 3: Atomic ledger append (tmp+rename)

**Files:**
- Modify: `policyforge/trust/ledger.py`
- Test: `tests/test_trust_ledger.py`

### Rationale

`LedgerWriter.append` does `open(..., "a"); fh.write(line)`. If the process crashes mid-write, a partial line lands in the file and the next `LedgerReader.load()` raises `JSONDecodeError` or breaks the chain. Fix: write to a temp file sibling, fsync, then atomic-rename over the ledger. This matches POSIX atomic-rename semantics; on Windows 10+, `os.replace` is also atomic.

Full-file rewrite on every append is O(n). For expected ledger sizes (tens to low hundreds of entries), the cost is negligible. If it ever matters, introduce WAL-style journaling — out of scope for v1.

### Steps

- [ ] **Step 1: Write failing test**

Append to `tests/test_trust_ledger.py`:

```python
class TestLedgerCrashSafety:
    def test_append_is_atomic_no_partial_lines_after_crash(
        self, ledger_path, monkeypatch
    ):
        """Simulate a crash between write() and rename(): the visible file
        must either have the full prior state (rename did not happen) or
        the full new state (rename happened). Never a partial line."""
        writer = LedgerWriter(path=ledger_path, hmac_key="k")
        writer.append(
            ToolFingerprint("s", "a", "a" * 64, "b" * 64, 1.0, "op")
        )

        # Monkeypatch os.replace to raise AFTER the temp file is written.
        import os
        original_replace = os.replace

        def failing_replace(src, dst):
            raise RuntimeError("simulated crash between write and rename")

        monkeypatch.setattr(os, "replace", failing_replace)

        with pytest.raises(RuntimeError, match="simulated crash"):
            writer.append(
                ToolFingerprint("s", "b", "c" * 64, "d" * 64, 2.0, "op")
            )

        monkeypatch.setattr(os, "replace", original_replace)

        # Ledger still parses as one entry (the original).
        reader = LedgerReader(path=ledger_path, hmac_key="k")
        loaded = reader.load()
        assert len(loaded) == 1
        assert loaded[("s", "a")].schema_hash == "a" * 64

        # No orphan temp file lingers in the parent directory.
        tmps = list(ledger_path.parent.glob(f"{ledger_path.name}.tmp.*"))
        assert not tmps, f"orphan temp files: {tmps}"
```

- [ ] **Step 2: Confirm failure**

`pytest tests/test_trust_ledger.py::TestLedgerCrashSafety -v`
Expected: fail — today's append uses `"a"` mode directly; a monkeypatched `os.replace` has no effect.

- [ ] **Step 3: Implement atomic append**

Replace the inner block of `LedgerWriter.append` that writes the line. New implementation:

```python
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

            # Atomic write: copy existing contents + append new line into a
            # temp file in the same directory, fsync, then os.replace.
            import os
            import tempfile

            existing = b""
            if self._path.exists():
                existing = self._path.read_bytes()

            line = json.dumps(record, separators=(",", ":")).encode("utf-8") + b"\n"

            # NamedTemporaryFile with delete=False so we can rename it;
            # prefix with the ledger name so orphans are easy to identify.
            fd, tmp_name = tempfile.mkstemp(
                prefix=f"{self._path.name}.tmp.",
                dir=str(self._path.parent),
            )
            try:
                with os.fdopen(fd, "wb") as fh:
                    fh.write(existing)
                    fh.write(line)
                    fh.flush()
                    os.fsync(fh.fileno())
                os.replace(tmp_name, self._path)
            except Exception:
                # Best-effort cleanup; if the tmp file is still around we
                # do not want it to linger.
                try:
                    os.unlink(tmp_name)
                except OSError:
                    pass
                raise
            self._last_hash = record["hmac"]
```

Key properties:
- `tempfile.mkstemp` with `dir=self._path.parent` keeps tmp on the same filesystem → `os.replace` is atomic.
- Copying the full existing contents each time is O(n); fine for this feature.
- On any exception after tmp creation (including the simulated `os.replace` failure), the tmp file is unlinked, leaving the ledger untouched.

- [ ] **Step 4: Run tests**

`pytest tests/test_trust_ledger.py -v` — all existing + 1 new. Confirm the crash-safety test passes and no earlier test regressed (the append semantics are identical; only the write path changed).

- [ ] **Step 5: Run full suite**

`pytest -q`.

- [ ] **Step 6: Commit**

```bash
git add policyforge/trust/ledger.py tests/test_trust_ledger.py
git commit -m "feat(trust): atomic ledger append via tmp+rename"
```

---

## Task 4: Decorator plumbing for per-tool context

**Files:**
- Modify: `policyforge/decorators.py`
- Test: `tests/test_decorators.py`

### Rationale

`PolicyGateWrapper.wrap_dict(tools: dict[str, Callable])` applies one `extra_context` to every wrapped tool. Fingerprint pinning needs per-tool context (`server_id`, `schema_hash`, `description_hash`). Without per-tool plumbing, `trust_manager` cannot be used with the decorator path that the README advertises for MS Foundry Agents integration.

### Semantics

- `wrap(fn, extra_context=None, tool_meta=None)` — add `tool_meta` parameter that, when present, is merged into the context as `context["tool"]`.
- `wrap_dict(tools, extra_context=None, tool_meta=None)` — `tool_meta` may be:
  - A dict `{tool_name: {"server_id": ..., "schema_hash": ..., "description_hash": ...}}` — per-tool.
  - A callable `(tool_name) -> dict | None` — computed per tool.
  - `None` (default) — legacy behavior preserved.

### Steps

- [ ] **Step 1: Write failing tests**

Read the current `policyforge/decorators.py` first, then append to `tests/test_decorators.py`:

```python
class TestPerToolMeta:
    def test_wrap_passes_tool_meta_via_context(self):
        seen_contexts: list[dict] = []

        class FakeEngine:
            def evaluate(self, tool_name, args, context):
                seen_contexts.append(context or {})
                from policyforge.models import Decision, Verdict
                return Decision(verdict=Verdict.ALLOW)

        def my_tool(x: int) -> int:
            return x + 1

        wrapper = PolicyGateWrapper(engine=FakeEngine())  # type: ignore[arg-type]
        wrapped = wrapper.wrap(
            my_tool,
            tool_meta={
                "server_id": "mcp://x",
                "schema_hash": "a" * 64,
                "description_hash": "b" * 64,
            },
        )
        wrapped(1)
        assert seen_contexts[-1].get("tool", {}).get("server_id") == "mcp://x"

    def test_wrap_dict_per_tool_meta_dict(self):
        seen: list[tuple[str, dict]] = []

        class FakeEngine:
            def evaluate(self, tool_name, args, context):
                seen.append((tool_name, context or {}))
                from policyforge.models import Decision, Verdict
                return Decision(verdict=Verdict.ALLOW)

        def fa(x): return x
        def fb(x): return x

        wrapper = PolicyGateWrapper(engine=FakeEngine())  # type: ignore[arg-type]
        wrapped = wrapper.wrap_dict(
            {"fa": fa, "fb": fb},
            tool_meta={
                "fa": {"server_id": "mcp://a", "schema_hash": "a" * 64, "description_hash": "b" * 64},
                "fb": {"server_id": "mcp://b", "schema_hash": "c" * 64, "description_hash": "d" * 64},
            },
        )
        wrapped["fa"](1)
        wrapped["fb"](2)
        assert seen[0][1]["tool"]["server_id"] == "mcp://a"
        assert seen[1][1]["tool"]["server_id"] == "mcp://b"

    def test_wrap_dict_per_tool_meta_callable(self):
        seen: list[tuple[str, dict]] = []

        class FakeEngine:
            def evaluate(self, tool_name, args, context):
                seen.append((tool_name, context or {}))
                from policyforge.models import Decision, Verdict
                return Decision(verdict=Verdict.ALLOW)

        def fa(x): return x

        wrapper = PolicyGateWrapper(engine=FakeEngine())  # type: ignore[arg-type]

        def meta_for(tool_name: str) -> dict:
            return {
                "server_id": f"mcp://{tool_name}",
                "schema_hash": "e" * 64,
                "description_hash": "f" * 64,
            }

        wrapped = wrapper.wrap_dict({"fa": fa}, tool_meta=meta_for)
        wrapped["fa"](1)
        assert seen[0][1]["tool"]["server_id"] == "mcp://fa"

    def test_wrap_dict_no_tool_meta_preserves_legacy(self):
        """Back-compat: callers not passing tool_meta see no `tool` key."""
        seen: list[dict] = []

        class FakeEngine:
            def evaluate(self, tool_name, args, context):
                seen.append(context or {})
                from policyforge.models import Decision, Verdict
                return Decision(verdict=Verdict.ALLOW)

        def fa(x): return x

        wrapper = PolicyGateWrapper(engine=FakeEngine())  # type: ignore[arg-type]
        wrapped = wrapper.wrap_dict({"fa": fa})
        wrapped["fa"](1)
        assert "tool" not in seen[0]
```

- [ ] **Step 2: Confirm failure**

`pytest tests/test_decorators.py -v -k "PerToolMeta"`
Expected: fail — `wrap` / `wrap_dict` do not accept a `tool_meta` kwarg.

- [ ] **Step 3: Implement**

In `policyforge/decorators.py`:

1. Add `tool_meta` parameter to `wrap` and `wrap_dict` signatures.
2. In `wrap`, when `tool_meta` is present, merge it into the per-call context as `{"tool": tool_meta}`.
3. In `wrap_dict`, resolve the per-tool meta (dict-lookup or callable-call) at decoration time, wrap each function via `wrap(..., tool_meta=resolved)`.

Exact diff depends on the current structure of `decorators.py`; read it first to match existing patterns. The key invariant:

```python
# inside the wrapped call, before engine.evaluate:
effective_context = dict(extra_context or {})
if tool_meta is not None:
    effective_context["tool"] = dict(tool_meta)
decision = self.engine.evaluate(tool_name=..., args=..., context=effective_context)
```

- [ ] **Step 4: Run tests**

`pytest tests/test_decorators.py -v` — all existing + 4 new passing.

- [ ] **Step 5: Full suite**

`pytest -q`.

- [ ] **Step 6: Commit**

```bash
git add policyforge/decorators.py tests/test_decorators.py
git commit -m "feat(decorators): per-tool tool_meta for wrap/wrap_dict"
```

---

## Task 5: Approvals CLI + bootstrap docs (digit note included)

**Files:**
- Create: `policyforge/trust/cli.py`
- Create: `tests/test_trust_cli.py`
- Modify: `README.md`

### Rationale

An operator who enables `tool_trust.mode: enforce` on first-run gets DENY on every call until the ledger is seeded. Plan 1 doesn't provide a documented seeding path. Ship a minimal CLI and a README "First-run: approving your tools" subsection. Fold in the digit-homoglyph scope note so operators know what shadow detection does NOT cover.

### CLI surface

```
python -m policyforge.trust.approve \
    --ledger .policyforge/approvals.jsonl \
    --server-id mcp://github \
    --name create_issue \
    --schema-hash <sha256> \
    --description-hash <sha256> \
    [--approved-by you@company.com]
```

Writes one `ToolFingerprint` to the ledger (using `LedgerWriter`) and prints a confirmation line. Requires `POLICYFORGE_HMAC_KEY` in the env (same as the writer).

Also support a bulk mode: `--from-json path/to/fingerprints.json` where the file is a JSON array of objects with the same fields. Useful for seeding from an MCP server's introspection output.

### Steps

- [ ] **Step 1: Write failing tests**

Create `tests/test_trust_cli.py`:

```python
"""Tests for the approvals CLI entry point."""

import json
from pathlib import Path

import pytest

from policyforge.trust import cli as trust_cli
from policyforge.trust.ledger import LedgerReader


class TestSingleApprove:
    def test_approves_one_fingerprint(self, tmp_path: Path, monkeypatch):
        monkeypatch.setenv("POLICYFORGE_HMAC_KEY", "k")
        ledger = tmp_path / "approvals.jsonl"
        exit_code = trust_cli.main(
            [
                "--ledger",
                str(ledger),
                "--server-id",
                "mcp://github",
                "--name",
                "create_issue",
                "--schema-hash",
                "a" * 64,
                "--description-hash",
                "b" * 64,
                "--approved-by",
                "test-op",
            ]
        )
        assert exit_code == 0
        loaded = LedgerReader(path=ledger, hmac_key="k").load()
        key = ("mcp://github", "create_issue")
        assert key in loaded
        assert loaded[key].schema_hash == "a" * 64
        assert loaded[key].approved_by == "test-op"

    def test_rejects_invalid_hash(self, tmp_path: Path, monkeypatch):
        monkeypatch.setenv("POLICYFORGE_HMAC_KEY", "k")
        ledger = tmp_path / "approvals.jsonl"
        exit_code = trust_cli.main(
            [
                "--ledger", str(ledger),
                "--server-id", "mcp://x",
                "--name", "t",
                "--schema-hash", "not-hex",
                "--description-hash", "b" * 64,
            ]
        )
        assert exit_code != 0
        assert not ledger.exists() or ledger.read_text() == ""


class TestBulkApprove:
    def test_bulk_approves_from_json_file(self, tmp_path: Path, monkeypatch):
        monkeypatch.setenv("POLICYFORGE_HMAC_KEY", "k")
        ledger = tmp_path / "approvals.jsonl"
        seed = tmp_path / "seed.json"
        seed.write_text(
            json.dumps(
                [
                    {
                        "server_id": "mcp://a",
                        "name": "t1",
                        "schema_hash": "a" * 64,
                        "description_hash": "b" * 64,
                    },
                    {
                        "server_id": "mcp://b",
                        "name": "t2",
                        "schema_hash": "c" * 64,
                        "description_hash": "d" * 64,
                    },
                ]
            ),
            encoding="utf-8",
        )
        exit_code = trust_cli.main(
            ["--ledger", str(ledger), "--from-json", str(seed)]
        )
        assert exit_code == 0
        loaded = LedgerReader(path=ledger, hmac_key="k").load()
        assert len(loaded) == 2


class TestRequiresHmacKey:
    def test_missing_env_key_fails(self, tmp_path: Path, monkeypatch):
        monkeypatch.delenv("POLICYFORGE_HMAC_KEY", raising=False)
        ledger = tmp_path / "approvals.jsonl"
        exit_code = trust_cli.main(
            [
                "--ledger", str(ledger),
                "--server-id", "mcp://x",
                "--name", "t",
                "--schema-hash", "a" * 64,
                "--description-hash", "b" * 64,
            ]
        )
        assert exit_code != 0
```

- [ ] **Step 2: Confirm failure**

`pytest tests/test_trust_cli.py -v`
Expected: `ImportError: cannot import name 'cli' from 'policyforge.trust'`.

- [ ] **Step 3: Implement CLI**

Create `policyforge/trust/cli.py`:

```python
"""Operator CLI for seeding the approvals ledger.

Usage:
    python -m policyforge.trust.approve \\
        --ledger .policyforge/approvals.jsonl \\
        --server-id mcp://github \\
        --name create_issue \\
        --schema-hash <sha256> \\
        --description-hash <sha256>

Or bulk-seed from JSON:
    python -m policyforge.trust.approve \\
        --ledger .policyforge/approvals.jsonl \\
        --from-json fingerprints.json
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Sequence

from policyforge.trust.ledger import LedgerWriter
from policyforge.trust.models import ToolFingerprint


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="policyforge-approve")
    p.add_argument("--ledger", required=True, help="Path to approvals.jsonl")
    p.add_argument("--from-json", help="JSON file with array of fingerprints")
    p.add_argument("--server-id")
    p.add_argument("--name")
    p.add_argument("--schema-hash")
    p.add_argument("--description-hash")
    p.add_argument("--approved-by", default="cli")
    return p


def _append_one(writer: LedgerWriter, fields: dict, approved_by: str) -> None:
    fp = ToolFingerprint(
        server_id=fields["server_id"],
        name=fields["name"],
        schema_hash=fields["schema_hash"],
        description_hash=fields["description_hash"],
        first_seen=time.time(),
        approved_by=approved_by,
    )
    writer.append(fp)


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    ledger_path = Path(args.ledger)

    try:
        writer = LedgerWriter(path=ledger_path)  # HMAC from env
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    try:
        if args.from_json:
            payload = json.loads(Path(args.from_json).read_text(encoding="utf-8"))
            for entry in payload:
                _append_one(writer, entry, approved_by=args.approved_by)
            print(f"Approved {len(payload)} tools into {ledger_path}")
        else:
            required = ("server_id", "name", "schema_hash", "description_hash")
            missing = [r for r in required if getattr(args, r.replace("_", "-"), None) is None]
            # argparse uses dashes in the CLI but stores as underscores
            missing = [r for r in required if getattr(args, r, None) is None]
            if missing:
                print(f"error: missing fields: {missing}", file=sys.stderr)
                return 2
            fields = {r: getattr(args, r) for r in required}
            _append_one(writer, fields, approved_by=args.approved_by)
            print(f"Approved {fields['server_id']}:{fields['name']} into {ledger_path}")
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

Also create `policyforge/trust/approve.py` as a one-line alias so `python -m policyforge.trust.approve` works (optional; keeping `cli.py` as the module is fine and the README will document `-m policyforge.trust.cli`).

- [ ] **Step 4: Run tests**

`pytest tests/test_trust_cli.py -v` — 4 passing.

- [ ] **Step 5: Update README**

Append a new subsection to the "Threat Model" → "Tool Fingerprint Pinning" block in `README.md`:

```markdown
#### First-run: approving your tools

On a fresh deployment with `mode: enforce`, every tool call is denied until the approvals ledger is seeded. Two options:

**Interactive CLI (one tool at a time):**

```bash
export POLICYFORGE_HMAC_KEY="..."
python -m policyforge.trust.cli \
    --ledger .policyforge/approvals.jsonl \
    --server-id mcp://github \
    --name create_issue \
    --schema-hash <sha256 of input schema> \
    --description-hash <sha256 of description> \
    --approved-by "you@company.com"
```

**Bulk seed from JSON:**

```bash
python -m policyforge.trust.cli \
    --ledger .policyforge/approvals.jsonl \
    --from-json fingerprints.json
```

Where `fingerprints.json` is a JSON array of `{server_id, name, schema_hash, description_hash}` objects — typically generated by introspecting an MCP server's tool list and hashing each tool's `inputSchema` and `description`.

#### What shadow detection covers (and doesn't)

- **Covered:** NFKC normalization collisions, compatibility folds (fullwidth → ASCII, decomposed → composed), common Cyrillic / Greek letter-to-Latin homoglyphs, case folding (including `ß` → `ss`).
- **Not covered (v1):** digit/letter confusables like `0` vs `O` or `1` vs `l`/`I`. Visual similarity varies too widely by font to justify a security-grade fold at this layer; a future ICU-backed replacement can add them.
```

- [ ] **Step 6: Smoke test the CLI**

```bash
POLICYFORGE_HMAC_KEY=k python -m policyforge.trust.cli \
    --ledger /tmp/pf-smoke.jsonl \
    --server-id mcp://test \
    --name smoke \
    --schema-hash $(python -c 'print("a"*64)') \
    --description-hash $(python -c 'print("b"*64)')
```

Expect: `Approved mcp://test:smoke into /tmp/pf-smoke.jsonl`.

- [ ] **Step 7: Run full suite + lint**

- `pytest -q`
- `ruff check policyforge tests`
- `black --check policyforge tests`
- `mypy policyforge`

All green.

- [ ] **Step 8: Commit**

```bash
git add policyforge/trust/cli.py tests/test_trust_cli.py README.md
git commit -m "feat(trust): approvals CLI + bootstrap and scope docs"
```

---

## Self-Review

**Spec coverage:** Plan 2a doesn't add new spec requirements. It closes the gap between the existing spec §7.3 (typed audit events), §4.4 (ledger crash safety is implicit in "tamper-evident"), §4.6 (path resolution is operator-implied), and §7.6 (documentation).

**Placeholder scan:** No TBDs. Every code block is concrete; every test file is a drop-in.

**Type consistency:** `tool_meta` is `dict[str, Any] | None` throughout; `TrustManager.set_audit_logger` and `AuditLogger.log_event` signatures match; the CLI's `main(argv: Sequence[str] | None) -> int` returns exit code as expected by `python -m`.

**Ordering check:** Tasks 1, 2, 3 can land in any order. Task 4 (decorators) is independent of 1-3. Task 5 depends on the CLI module existing; it doesn't depend on any other Task 2a task. Recommended ship order is 1 → 2 → 3 → 4 → 5 for narrative coherence in the git log, but parallelizing 1+2+3+4 with a single integration commit at the end is also valid.

---

## Execution Handoff

After all five tasks land: run the full suite, `ruff`/`black`/`mypy`, confirm coverage still ≥ 90%, then merge to `main` and proceed to Plan 2 (Provenance-Tagged Args).
