"""Tests for core data models."""

import pytest

from policyforge.models import (
    AuditEntry,
    Condition,
    Decision,
    FailMode,
    MatchStrategy,
    Policy,
    PolicyRule,
    Verdict,
)


class TestCondition:
    def test_valid_operators(self):
        for op in ("eq", "neq", "in", "not_in", "contains", "regex", "gt", "lt", "gte", "lte"):
            c = Condition(field="tool_name", operator=op, value="test")
            assert c.operator == op

    def test_invalid_operator_raises(self):
        with pytest.raises(ValueError, match="Invalid operator"):
            Condition(field="x", operator="LIKE", value="y")

    def test_frozen(self):
        c = Condition(field="a", operator="eq", value="b")
        with pytest.raises(AttributeError):
            c.field = "changed"


class TestPolicyRule:
    def test_defaults(self):
        r = PolicyRule(
            name="test",
            conditions=(Condition("tool_name", "eq", "x"),),
        )
        assert r.verdict == Verdict.DENY
        assert r.match_strategy == MatchStrategy.ALL
        assert r.priority == 100


class TestPolicy:
    def test_fail_closed_default(self):
        p = Policy(name="test")
        assert p.default_verdict == Verdict.DENY
        assert p.fail_mode == FailMode.CLOSED

    def test_enabled_default(self):
        p = Policy(name="test")
        assert p.enabled is True


class TestDecision:
    def test_has_request_id(self):
        d = Decision(verdict=Verdict.ALLOW)
        assert len(d.request_id) == 16


class TestAuditEntry:
    def test_seal_and_verify(self):
        key = b"test-secret-key"
        entry = AuditEntry(
            request_id="abc123",
            tool_name="test_tool",
            agent_id="agent-1",
            verdict="ALLOW",
        )
        entry.seal(key)
        assert entry.integrity_hash != ""
        assert entry.verify(key) is True

    def test_tamper_detection(self):
        key = b"test-secret-key"
        entry = AuditEntry(
            request_id="abc123",
            tool_name="test_tool",
            verdict="ALLOW",
        )
        entry.seal(key)

        # Tamper with the verdict
        entry.verdict = "DENY"
        assert entry.verify(key) is False

    def test_wrong_key_fails(self):
        entry = AuditEntry(request_id="x", tool_name="t", verdict="ALLOW")
        entry.seal(b"key-one")
        assert entry.verify(b"key-two") is False

    def test_verify_uses_constant_time_compare(self, monkeypatch):
        key = b"test-secret-key"
        entry = AuditEntry(request_id="abc123", tool_name="test_tool", verdict="ALLOW")
        entry.seal(key)

        called = {"used": False}

        def fake_compare_digest(left: str, right: str) -> bool:
            called["used"] = True
            return left == right

        monkeypatch.setattr("policyforge.models.hmac.compare_digest", fake_compare_digest)

        assert entry.verify(key) is True
        assert called["used"] is True
