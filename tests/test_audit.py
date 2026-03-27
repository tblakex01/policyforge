"""Tests for the audit logger."""

import json

import pytest

from policyforge.audit import AuditLogger


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
