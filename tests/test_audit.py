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


class TestLogRotation:
    def test_rotates_when_max_bytes_exceeded(self, tmp_path, monkeypatch):
        audit = AuditLogger(
            log_dir=tmp_path,
            hmac_key="test-key",
            max_file_bytes=200,  # very small to force rotation
            chain_hashes=False,
        )

        # _new_log_path uses second-level timestamps, so all calls within the
        # same second return the same filename.  Patch it with a counter so
        # each rotation produces a genuinely new file.
        counter = [0]
        original = audit._new_log_path

        def unique_log_path(self_ignored=None):
            counter[0] += 1
            base = original()
            return base.with_name(f"audit_{counter[0]:04d}.jsonl")

        monkeypatch.setattr(audit, "_new_log_path", unique_log_path)

        for i in range(20):
            audit.log(
                request_id=f"req-{i:03d}",
                tool_name="tool",
                agent_id="agent",
                args_hash="h" * 64,
                verdict="ALLOW",
                message="x" * 50,
            )
        log_files = sorted(tmp_path.glob("audit_*.jsonl"))
        assert len(log_files) > 1, "Expected log rotation to create multiple files"

        # Verify all entries are valid across files
        total_lines = 0
        for lf in log_files:
            for line in lf.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    json.loads(line)  # should parse
                    total_lines += 1
        assert total_lines == 20


class TestBrokenHashChain:
    def test_detects_broken_chain_prev(self, tmp_path):
        """Inserting a valid-HMAC entry with wrong chain_prev should be detected."""
        audit = AuditLogger(
            log_dir=tmp_path,
            hmac_key="chain-key",
            chain_hashes=True,
        )
        # Write two legitimate entries
        audit.log(request_id="r1", tool_name="t", agent_id="a", args_hash="h", verdict="ALLOW")
        audit.log(request_id="r2", tool_name="t", agent_id="a", args_hash="h", verdict="ALLOW")

        # Tamper: overwrite chain_prev on the second entry
        log_file = list(tmp_path.glob("audit_*.jsonl"))[0]
        lines = log_file.read_text(encoding="utf-8").strip().split("\n")
        second = json.loads(lines[1])
        second["chain_prev"] = "0" * 64  # wrong chain_prev
        # Re-sign with correct HMAC for the tampered chain_prev
        entry = AuditEntry(
            timestamp=second["ts"],
            request_id=second["rid"],
            tool_name=second["tool"],
            agent_id=second["agent"],
            args_hash=second["args_hash"],
            verdict=second["verdict"],
            matched_rule=second["rule"],
            policy_name=second["policy"],
            message=second["msg"],
            evaluation_ms=second["ms"],
            chain_prev="0" * 64,
        )
        entry.seal(b"chain-key")
        second["hmac"] = entry.integrity_hash
        second["chain_prev"] = "0" * 64
        lines[1] = json.dumps(second, separators=(",", ":"))
        log_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

        valid, tampered = audit.verify_log()
        # The HMAC is correct, but the chain is broken
        assert tampered >= 1

    def test_verify_log_skips_blank_lines(self, tmp_path):
        audit = AuditLogger(log_dir=tmp_path, hmac_key="key", chain_hashes=False)
        audit.log(request_id="r1", tool_name="t", agent_id="a", args_hash="h", verdict="ALLOW")

        log_file = list(tmp_path.glob("audit_*.jsonl"))[0]
        content = log_file.read_text(encoding="utf-8")
        log_file.write_text("\n\n" + content + "\n\n", encoding="utf-8")

        valid, tampered = audit.verify_log()
        assert valid == 1
        assert tampered == 0


class TestHmacKeyPrecedence:
    def test_constructor_key_overrides_env(self, tmp_path, monkeypatch):
        monkeypatch.setenv("POLICYFORGE_HMAC_KEY", "env-key")
        audit = AuditLogger(log_dir=tmp_path, hmac_key="constructor-key")
        audit.log(request_id="r", tool_name="t", agent_id="a", args_hash="h", verdict="ALLOW")

        # Verify with constructor key should succeed
        valid, tampered = audit.verify_log()
        assert valid == 1
        assert tampered == 0

        # Verify with env key should fail — proving constructor key was used
        audit_env = AuditLogger(log_dir=tmp_path / "other", hmac_key="env-key")
        audit_env._current_file = audit._current_file
        valid_env, tampered_env = audit_env.verify_log()
        assert tampered_env == 1


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
