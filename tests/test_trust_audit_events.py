"""Tests that TrustManager emits typed audit events via AuditLogger.log_event."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from policyforge.audit import AuditLogger
from policyforge.engine import PolicyEngine
from policyforge.trust.ledger import LedgerWriter
from policyforge.trust.manager import TrustManager
from policyforge.trust.models import ToolFingerprint, TrustConfig, TrustMode


@pytest.fixture
def ledger_path(tmp_path: Path) -> Path:
    return tmp_path / "approvals.jsonl"


@pytest.fixture
def audit(tmp_path: Path) -> AuditLogger:
    return AuditLogger(log_dir=tmp_path / "audit", hmac_key="k")


@pytest.fixture
def policy_file(tmp_path: Path) -> Path:
    policy = tmp_path / "allow_all.yaml"
    policy.write_text(
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
    return policy


def _tool_meta(
    server_id: str = "mcp://x",
    schema_hash: str = "5" * 64,
    description_hash: str = "7" * 64,
) -> dict[str, str]:
    return {
        "server_id": server_id,
        "schema_hash": schema_hash,
        "description_hash": description_hash,
    }


def _audit_events(log_dir: Path) -> list[dict[str, object]]:
    files = list(log_dir.glob("*.jsonl"))
    assert files, "no audit file written"
    entries = [
        json.loads(line)
        for line in files[0].read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    return [entry for entry in entries if entry.get("kind") == "event"]


class TestTrustAuditEvents:
    def test_tool_unknown_emits_event(
        self,
        policy_file: Path,
        ledger_path: Path,
        audit: AuditLogger,
        tmp_path: Path,
    ):
        ledger_path.touch()
        tm = TrustManager(
            TrustConfig(mode=TrustMode.ENFORCE, ledger_path=ledger_path),
            hmac_key="k",
            audit_logger=audit,
        )
        engine = PolicyEngine(policy_paths=[policy_file], trust_manager=tm, audit_logger=audit)

        engine.evaluate("unseen", args={}, context={"tool": _tool_meta()})

        events = _audit_events(tmp_path / "audit")
        trust_events = [entry for entry in events if entry.get("event") == "tool_unknown"]
        assert trust_events, f"no tool_unknown event in {events}"
        meta = trust_events[-1]["meta"]
        assert isinstance(meta, dict)
        assert meta["server_id"] == "mcp://x"
        assert meta["tool_name"] == "unseen"

    def test_fingerprint_drift_emits_event(
        self,
        policy_file: Path,
        ledger_path: Path,
        audit: AuditLogger,
        tmp_path: Path,
    ):
        fp = ToolFingerprint("mcp://github", "create_issue", "a" * 64, "b" * 64, 1.0, "op")
        LedgerWriter(path=ledger_path, hmac_key="k").append(fp)
        tm = TrustManager(
            TrustConfig(mode=TrustMode.ENFORCE, ledger_path=ledger_path),
            hmac_key="k",
            audit_logger=audit,
        )
        engine = PolicyEngine(policy_paths=[policy_file], trust_manager=tm, audit_logger=audit)

        engine.evaluate(
            "create_issue",
            args={},
            context={
                "tool": _tool_meta(
                    server_id="mcp://github",
                    schema_hash="9" * 64,
                    description_hash="b" * 64,
                )
            },
        )

        events = _audit_events(tmp_path / "audit")
        drift_events = [entry for entry in events if entry.get("event") == "fingerprint_drift"]
        assert drift_events, f"no fingerprint_drift event in {events}"

    def test_shadow_detection_emits_event(
        self,
        policy_file: Path,
        ledger_path: Path,
        audit: AuditLogger,
        tmp_path: Path,
    ):
        fp = ToolFingerprint("mcp://github", "send_email", "a" * 64, "b" * 64, 1.0, "op")
        LedgerWriter(path=ledger_path, hmac_key="k").append(fp)
        tm = TrustManager(
            TrustConfig(mode=TrustMode.ENFORCE, ledger_path=ledger_path),
            hmac_key="k",
            audit_logger=audit,
        )
        engine = PolicyEngine(policy_paths=[policy_file], trust_manager=tm, audit_logger=audit)

        engine.evaluate(
            "\u0455end_email",
            args={},
            context={
                "tool": _tool_meta(
                    server_id="mcp://github",
                    schema_hash="a" * 64,
                    description_hash="b" * 64,
                )
            },
        )

        events = _audit_events(tmp_path / "audit")
        shadow_events = [entry for entry in events if entry.get("event") == "tool_shadow_detected"]
        assert shadow_events, f"no tool_shadow_detected event in {events}"

    def test_auto_approve_emits_event(
        self,
        policy_file: Path,
        ledger_path: Path,
        audit: AuditLogger,
        tmp_path: Path,
    ):
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

        engine.evaluate("new_tool", args={}, context={"tool": _tool_meta()})

        events = _audit_events(tmp_path / "audit")
        approve_events = [entry for entry in events if entry.get("event") == "tool_approved"]
        assert approve_events, f"no tool_approved event in {events}"
        meta = approve_events[-1]["meta"]
        assert isinstance(meta, dict)
        assert meta["server_id"] == "mcp://x"

    def test_no_event_emitted_on_allow(
        self,
        policy_file: Path,
        ledger_path: Path,
        audit: AuditLogger,
        tmp_path: Path,
    ):
        fp = ToolFingerprint("mcp://github", "create_issue", "a" * 64, "b" * 64, 1.0, "op")
        LedgerWriter(path=ledger_path, hmac_key="k").append(fp)
        tm = TrustManager(
            TrustConfig(mode=TrustMode.ENFORCE, ledger_path=ledger_path),
            hmac_key="k",
            audit_logger=audit,
        )
        engine = PolicyEngine(policy_paths=[policy_file], trust_manager=tm, audit_logger=audit)

        engine.evaluate(
            "create_issue",
            args={},
            context={
                "tool": _tool_meta(
                    server_id="mcp://github",
                    schema_hash="a" * 64,
                    description_hash="b" * 64,
                )
            },
        )

        events = _audit_events(tmp_path / "audit")
        trust_event_types = {
            "tool_unknown",
            "fingerprint_drift",
            "tool_shadow_detected",
            "tool_approved",
            "tool_meta_missing",
            "tool_meta_invalid",
        }
        assert not any(entry.get("event") in trust_event_types for entry in events)

    def test_engine_injects_audit_logger_into_trust_manager(
        self,
        policy_file: Path,
        ledger_path: Path,
        audit: AuditLogger,
        tmp_path: Path,
    ):
        ledger_path.touch()
        tm = TrustManager(
            TrustConfig(mode=TrustMode.ENFORCE, ledger_path=ledger_path),
            hmac_key="k",
        )
        engine = PolicyEngine(policy_paths=[policy_file], trust_manager=tm, audit_logger=audit)

        engine.evaluate("unseen", args={}, context={"tool": _tool_meta()})

        events = _audit_events(tmp_path / "audit")
        assert any(entry.get("event") == "tool_unknown" for entry in events)
