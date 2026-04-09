"""Tests for the audit logger."""

import json
import threading
import time
from pathlib import Path

import pytest

from policyforge.audit import AuditLogger
from policyforge.models import AuditEntry


@pytest.fixture
def audit(tmp_path):
    return AuditLogger(
        log_dir=tmp_path,
        hmac_key="test-audit-key",
        chain_hashes=True,
    )


class TestAuditLogger:
    def test_creates_log_file(self, audit):
        audit.log(
            request_id="req-001",
            tool_name="test_tool",
            agent_id="agent-1",
            args_hash="abc123",
            verdict="ALLOW",
        )
        log_files = list(audit._log_dir.glob("audit_*.jsonl"))
        assert len(log_files) == 1

    def test_log_entry_format(self, audit):
        audit.log(
            request_id="req-002",
            tool_name="web_search",
            agent_id="agent-1",
            args_hash="def456",
            verdict="DENY",
            matched_rule="block-shell",
            policy_name="default",
            message="Shell blocked",
            evaluation_ms=1.5,
        )
        log_file = list(audit._log_dir.glob("audit_*.jsonl"))[0]
        line = log_file.read_text().strip()
        record = json.loads(line)

        assert record["rid"] == "req-002"
        assert record["tool"] == "web_search"
        assert record["verdict"] == "DENY"
        assert record["rule"] == "block-shell"
        assert record["ms"] == 1.5
        assert "hmac" in record
        assert len(record["hmac"]) == 64  # SHA-256 hex

    def test_verify_untampered(self, audit):
        for i in range(5):
            audit.log(
                request_id=f"req-{i:03d}",
                tool_name="tool",
                agent_id="a",
                args_hash="h",
                verdict="ALLOW",
            )
        valid, tampered = audit.verify_log()
        assert valid == 5
        assert tampered == 0

    def test_detect_tampered_entry(self, audit):
        audit.log(
            request_id="req-001",
            tool_name="tool",
            agent_id="a",
            args_hash="h",
            verdict="ALLOW",
        )
        # Tamper with the log file
        log_file = list(audit._log_dir.glob("audit_*.jsonl"))[0]
        content = log_file.read_text()
        tampered = content.replace('"ALLOW"', '"DENY"')
        log_file.write_text(tampered)

        valid, tampered_count = audit.verify_log()
        assert tampered_count > 0

    def test_hash_chaining(self, audit):
        """Second entry should reference the first entry's hash."""
        audit.log(request_id="r1", tool_name="t", agent_id="a", args_hash="h", verdict="ALLOW")
        audit.log(request_id="r2", tool_name="t", agent_id="a", args_hash="h", verdict="ALLOW")

        log_file = list(audit._log_dir.glob("audit_*.jsonl"))[0]
        lines = log_file.read_text().strip().split("\n")
        first = json.loads(lines[0])
        second = json.loads(lines[1])

        assert second["chain_prev"] == first["hmac"]

    def test_concurrent_logging_preserves_hash_chain(self, audit, monkeypatch):
        """Concurrent writes should still produce a valid hash chain."""
        audit.log(request_id="seed", tool_name="t", agent_id="a", args_hash="h", verdict="ALLOW")

        original_write = audit._write
        first_concurrent_write_started = threading.Event()
        release_first_write = threading.Event()
        write_count = 0

        def blocking_write(entry):
            nonlocal write_count
            write_count += 1
            if write_count == 1:
                first_concurrent_write_started.set()
                assert release_first_write.wait(timeout=2)
            original_write(entry)

        monkeypatch.setattr(audit, "_write", blocking_write)

        thread_one = threading.Thread(
            target=audit.log,
            kwargs={
                "request_id": "r2",
                "tool_name": "t",
                "agent_id": "a",
                "args_hash": "h",
                "verdict": "ALLOW",
            },
        )
        thread_two = threading.Thread(
            target=audit.log,
            kwargs={
                "request_id": "r3",
                "tool_name": "t",
                "agent_id": "a",
                "args_hash": "h",
                "verdict": "ALLOW",
            },
        )

        thread_one.start()
        assert first_concurrent_write_started.wait(timeout=2)
        thread_two.start()
        time.sleep(0.05)
        release_first_write.set()

        thread_one.join(timeout=2)
        thread_two.join(timeout=2)

        assert not thread_one.is_alive()
        assert not thread_two.is_alive()

        valid, tampered = audit.verify_log()
        assert valid == 3
        assert tampered == 0

    def test_verify_log_counts_malformed_lines_as_tampered(self, audit):
        audit.log(request_id="r1", tool_name="t", agent_id="a", args_hash="h", verdict="ALLOW")
        log_file = list(audit._log_dir.glob("audit_*.jsonl"))[0]
        log_file.write_text(log_file.read_text() + '{"ts":')

        valid, tampered = audit.verify_log()

        assert valid == 1
        assert tampered == 1

    def test_log_event_writes_measurement_record(self, audit):
        audit.log_event(
            request_id="req-share",
            event_type="share_receipt_generated",
            tool_name="query_db",
            agent_id="agent-1",
            metadata={"verdict": "LOG_ONLY", "format": "markdown"},
        )

        log_file = list(audit._log_dir.glob("audit_*.jsonl"))[0]
        record = json.loads(log_file.read_text().strip())

        assert record["kind"] == "event"
        assert record["event"] == "share_receipt_generated"
        assert record["meta"]["format"] == "markdown"

    def test_log_event_serializes_non_json_metadata(self, audit):
        audit.log_event(
            request_id="req-typed-meta",
            event_type="share_receipt_generated",
            metadata={"path": Path("nested") / "policy.yaml"},
        )

        log_file = list(audit._log_dir.glob("audit_*.jsonl"))[0]
        record = json.loads(log_file.read_text().strip())

        assert record["meta"]["path"] == str(Path("nested") / "policy.yaml")

    def test_verify_log_accepts_legacy_decision_records(self, tmp_path):
        audit = AuditLogger(log_dir=tmp_path, hmac_key="test-audit-key")
        log_file = Path(audit._current_file)

        legacy_entry = AuditEntry(
            timestamp=123.0,
            request_id="legacy-1",
            tool_name="run_shell",
            agent_id="agent-1",
            args_hash="abc123",
            verdict="DENY",
            matched_rule="block-shell",
            policy_name="default",
            message="Shell blocked",
            evaluation_ms=1.25,
        )
        legacy_entry.integrity_hash = legacy_entry.compute_integrity(
            b"test-audit-key",
            include_event_fields=False,
        )
        record = {
            "ts": legacy_entry.timestamp,
            "rid": legacy_entry.request_id,
            "tool": legacy_entry.tool_name,
            "agent": legacy_entry.agent_id,
            "args_hash": legacy_entry.args_hash,
            "verdict": legacy_entry.verdict,
            "rule": legacy_entry.matched_rule,
            "policy": legacy_entry.policy_name,
            "msg": legacy_entry.message,
            "ms": legacy_entry.evaluation_ms,
            "hmac": legacy_entry.integrity_hash,
            "chain_prev": legacy_entry.chain_prev,
        }
        log_file.write_text(json.dumps(record) + "\n", encoding="utf-8")

        valid, tampered = audit.verify_log()

        assert valid == 1
        assert tampered == 0


class TestAuditRequiresKey:
    def test_no_key_raises(self, tmp_path, monkeypatch):
        monkeypatch.delenv("POLICYFORGE_HMAC_KEY", raising=False)
        with pytest.raises(RuntimeError, match="HMAC key required"):
            AuditLogger(log_dir=tmp_path)

    def test_env_key_works(self, tmp_path, monkeypatch):
        monkeypatch.setenv("POLICYFORGE_HMAC_KEY", "from-env")
        audit = AuditLogger(log_dir=tmp_path)
        audit.log(request_id="r", tool_name="t", agent_id="a", args_hash="h", verdict="ALLOW")
        valid, tampered = audit.verify_log()
        assert valid == 1
