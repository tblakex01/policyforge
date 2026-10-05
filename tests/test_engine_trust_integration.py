"""Integration tests: PolicyEngine + TrustManager pre-flight."""

from pathlib import Path

import pytest

from policyforge.decorators import PolicyDeniedError, policy_gate
from policyforge.engine import PolicyEngine
from policyforge.models import Verdict
from policyforge.trust.ledger import LedgerWriter
from policyforge.trust.manager import TrustManager
from policyforge.trust.models import (
    ToolFingerprint,
    ToolMetadata,
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


def _tool_context(server_id: str, schema_hash: str, description_hash: str) -> dict[str, object]:
    return {
        "tool": ToolMetadata(
            server_id=server_id,
            schema_hash=schema_hash,
            description_hash=description_hash,
        )
    }


class TestBackwardsCompat:
    def test_engine_without_trust_manager_behaves_identically(self, policy_file):
        engine = PolicyEngine(policy_paths=[policy_file])
        decision = engine.evaluate(tool_name="anything", args={})
        assert decision.verdict == Verdict.ALLOW


class TestTrustPreflight:
    @pytest.fixture
    def deny_shell_policy(self, tmp_path: Path) -> Path:
        policy = tmp_path / "deny_shell.yaml"
        policy.write_text(
            """
name: deny-shell
default_verdict: ALLOW
rules:
  - name: no-shell
    conditions:
      - field: tool_name
        operator: eq
        value: run_shell
    verdict: DENY
""",
            encoding="utf-8",
        )
        return policy

    def test_unwired_warn_does_not_bypass_policy_deny(self, deny_shell_policy):
        policy = deny_shell_policy.read_text(encoding="utf-8")
        deny_shell_policy.write_text("tool_trust:\n  mode: warn\n" + policy, encoding="utf-8")
        engine = PolicyEngine(policy_paths=[deny_shell_policy])
        calls: list[str] = []

        @policy_gate(engine, tool_name="run_shell")
        def run_shell() -> None:
            calls.append("ran")

        with pytest.raises(PolicyDeniedError) as exc_info:
            run_shell()
        assert exc_info.value.decision.matched_rule == "no-shell"
        assert calls == []

    def test_wired_log_only_does_not_bypass_policy_deny(self, deny_shell_policy, ledger_path):
        tm = TrustManager(
            TrustConfig(
                mode=TrustMode.WARN,
                ledger_path=ledger_path,
                on_unknown=TrustVerdict.LOG_ONLY,
            ),
            hmac_key="k",
        )
        engine = PolicyEngine(policy_paths=[deny_shell_policy], trust_manager=tm)
        calls: list[str] = []

        @policy_gate(
            engine,
            tool_name="run_shell",
            extra_context=_tool_context("mcp://x", "5" * 64, "7" * 64),
        )
        def run_shell() -> None:
            calls.append("ran")

        with pytest.raises(PolicyDeniedError) as exc_info:
            run_shell()
        assert exc_info.value.decision.matched_rule == "no-shell"
        assert calls == []

    def test_unwired_warn_without_active_policy_still_denies(self, tmp_path):
        policy = tmp_path / "trust_only.yaml"
        policy.write_text("tool_trust:\n  mode: warn\n", encoding="utf-8")
        decision = PolicyEngine(policy_paths=[policy]).evaluate("run_shell")
        assert decision.verdict == Verdict.DENY

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
            context=_tool_context("mcp://x", "5" * 64, "7" * 64),
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
            context=_tool_context(pinned.server_id, "9" * 64, pinned.description_hash),
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
            context=_tool_context(pinned.server_id, pinned.schema_hash, pinned.description_hash),
        )
        assert decision.verdict == Verdict.ALLOW
        assert decision.matched_rule == "permissive"

    def test_warn_mode_log_only_flows_through_engine(self, policy_file, ledger_path):
        """WARN mode + on_mismatch=LOG_ONLY should produce a LOG_ONLY Decision at engine level."""
        ledger_path.touch()
        tm = TrustManager(
            TrustConfig(
                mode=TrustMode.WARN,
                ledger_path=ledger_path,
                on_mismatch=TrustVerdict.LOG_ONLY,
                on_unknown=TrustVerdict.LOG_ONLY,
            ),
            hmac_key="k",
        )
        engine = PolicyEngine(policy_paths=[policy_file], trust_manager=tm)
        decision = engine.evaluate(
            tool_name="unseen",
            args={},
            context=_tool_context("mcp://x", "5" * 64, "7" * 64),
        )
        assert decision.verdict == Verdict.LOG_ONLY
        assert decision.policy_name == "tool_trust"
        assert decision.matched_rule == "tool_unknown"

    def test_description_drift_denied_before_rules(self, policy_file, ledger_path):
        """Drift in description_hash alone should also DENY before rules."""
        pinned = _pin(ledger_path)
        tm = TrustManager(
            TrustConfig(mode=TrustMode.ENFORCE, ledger_path=ledger_path),
            hmac_key="k",
        )
        engine = PolicyEngine(policy_paths=[policy_file], trust_manager=tm)
        decision = engine.evaluate(
            tool_name=pinned.name,
            args={},
            context=_tool_context(pinned.server_id, pinned.schema_hash, "9" * 64),
        )
        assert decision.verdict == Verdict.DENY
        assert decision.matched_rule == "fingerprint_drift"

    def test_raw_dict_tool_metadata_denied_before_rules(self, policy_file, ledger_path):
        pinned = _pin(ledger_path)
        tm = TrustManager(
            TrustConfig(mode=TrustMode.ENFORCE, ledger_path=ledger_path),
            hmac_key="k",
        )
        engine = PolicyEngine(policy_paths=[policy_file], trust_manager=tm)

        decision = engine.evaluate(
            tool_name=pinned.name,
            args={},
            context={
                "tool": {
                    "server_id": pinned.server_id,
                    "schema_hash": pinned.schema_hash,
                    "description_hash": pinned.description_hash,
                }
            },
        )

        assert decision.verdict == Verdict.DENY
        assert decision.matched_rule == "tool_meta_untrusted"


class TestTrustConfigOrphanWarning:
    def test_orphaned_enforce_trust_config_denies_when_no_manager(self, tmp_path, caplog):
        import logging

        policy_yaml = tmp_path / "p.yaml"
        policy_yaml.write_text(
            """
tool_trust:
  mode: enforce
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
        with caplog.at_level(logging.WARNING, logger="policyforge.engine"):
            engine = PolicyEngine(policy_paths=[policy_yaml])
        assert any("no TrustManager was passed" in rec.message for rec in caplog.records)

        decision = engine.evaluate("anything", {})

        assert decision.verdict == Verdict.DENY
        assert decision.matched_rule == "tool_trust_unwired"

    def test_orphaned_trust_config_warns_only_once(self, tmp_path, caplog):
        import logging

        policy_yaml = tmp_path / "p.yaml"
        policy_yaml.write_text(
            """
tool_trust:
  mode: enforce
name: demo
default_verdict: ALLOW
""",
            encoding="utf-8",
        )

        with caplog.at_level(logging.WARNING, logger="policyforge.engine"):
            engine = PolicyEngine()
            engine.load(policy_yaml)
            engine.load(policy_yaml)

        warnings = [
            record for record in caplog.records if "no TrustManager was passed" in record.message
        ]
        assert len(warnings) == 1

    def test_no_warning_when_trust_manager_present(self, tmp_path, ledger_path, caplog):
        import logging

        policy_yaml = tmp_path / "p.yaml"
        policy_yaml.write_text(
            """
tool_trust:
  mode: enforce
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
        tm = TrustManager(
            TrustConfig(mode=TrustMode.ENFORCE, ledger_path=ledger_path),
            hmac_key="k",
        )
        with caplog.at_level(logging.WARNING, logger="policyforge.engine"):
            PolicyEngine(policy_paths=[policy_yaml], trust_manager=tm)
        assert not any("no TrustManager was passed" in rec.message for rec in caplog.records)

    def test_no_warning_when_trust_disabled_in_yaml(self, tmp_path, caplog):
        import logging

        policy_yaml = tmp_path / "p.yaml"
        policy_yaml.write_text(
            """
tool_trust:
  mode: disabled
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
        with caplog.at_level(logging.WARNING, logger="policyforge.engine"):
            PolicyEngine(policy_paths=[policy_yaml])
        assert not any("no TrustManager was passed" in rec.message for rec in caplog.records)


class TestTrustAudit:
    def test_trust_denial_emits_audit_event(self, policy_file, ledger_path, tmp_path, monkeypatch):
        monkeypatch.setenv("POLICYFORGE_HMAC_KEY", "k")
        from policyforge.audit import AuditLogger

        audit = AuditLogger(log_dir=tmp_path / "audit")
        tm = TrustManager(
            TrustConfig(mode=TrustMode.ENFORCE, ledger_path=ledger_path),
            hmac_key="k",
        )
        ledger_path.touch()
        engine = PolicyEngine(policy_paths=[policy_file], trust_manager=tm, audit_logger=audit)
        engine.evaluate(
            tool_name="unseen",
            args={},
            context=_tool_context("mcp://x", "5" * 64, "7" * 64),
        )
        files = list((tmp_path / "audit").glob("*.jsonl"))
        assert files, "no audit log file written"
        import json as _json

        lines = [
            _json.loads(line)
            for line in files[0].read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        assert lines, "audit log was empty"
        entry = lines[-1]
        assert entry["verdict"] == "DENY"
        assert entry["rule"] == "tool_unknown"
        assert entry["policy"] == "tool_trust"
        # HMAC chain integrity: the entry has a non-empty integrity hash,
        # and verify_log reports zero tampered records.
        assert entry["hmac"]
        valid, tampered = audit.verify_log(files[0])
        assert tampered == 0
        assert valid == len(lines)


class TestTrustPreflightErrors:
    def _engine(self, policy_file, ledger_path, tmp_path, monkeypatch):
        monkeypatch.setenv("POLICYFORGE_HMAC_KEY", "k")
        from policyforge.audit import AuditLogger

        ledger_path.touch()
        audit = AuditLogger(log_dir=tmp_path / "audit")
        tm = TrustManager(
            TrustConfig(mode=TrustMode.ENFORCE, ledger_path=ledger_path, auto_approve=True),
            hmac_key="k",
        )
        return (
            PolicyEngine(policy_paths=[policy_file], trust_manager=tm, audit_logger=audit),
            audit,
        )

    def test_ledger_write_failure_fails_closed_with_audit(
        self, policy_file, ledger_path, tmp_path, monkeypatch
    ):
        """An OSError from the approvals ledger must become a DENY, not an exception."""
        engine, audit = self._engine(policy_file, ledger_path, tmp_path, monkeypatch)

        def boom(self, fp):  # noqa: ARG001
            raise OSError("read-only file system")

        monkeypatch.setattr(LedgerWriter, "append", boom)

        decision = engine.evaluate(
            tool_name="new_tool",
            args={},
            context=_tool_context("mcp://x", "5" * 64, "7" * 64),
        )
        assert decision.verdict == Verdict.DENY
        assert decision.matched_rule == "tool_trust_error"
        assert decision.policy_name == "tool_trust"
        assert "read-only" not in decision.message

        audit_file = next((tmp_path / "audit").glob("*.jsonl"))
        last = audit_file.read_text(encoding="utf-8").splitlines()[-1]
        assert '"rule":"tool_trust_error"' in last
        assert audit.verify_log(audit_file) == (1, 0)

    def test_arbitrary_preflight_exception_fails_closed(
        self, policy_file, ledger_path, tmp_path, monkeypatch
    ):
        engine, _ = self._engine(policy_file, ledger_path, tmp_path, monkeypatch)

        def boom(self, **kwargs):  # noqa: ARG001
            raise RuntimeError("dictionary changed size during iteration")

        monkeypatch.setattr(TrustManager, "check", boom)

        decision = engine.evaluate(
            tool_name="t",
            args={},
            context=_tool_context("mcp://x", "5" * 64, "7" * 64),
        )
        assert decision.verdict == Verdict.DENY
        assert decision.matched_rule == "tool_trust_error"
