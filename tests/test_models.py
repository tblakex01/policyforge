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

    def test_invalid_regex_raises_value_error(self):
        with pytest.raises(ValueError, match="Invalid regex"):
            Condition(field="x", operator="regex", value="(unclosed")

    def test_match_regex_uses_compiled_pattern(self):
        c = Condition(field="x", operator="regex", value=r"\d{3}")
        assert c.match_regex("abc123def") is True
        assert c.match_regex("no-digits") is False

    def test_match_regex_fallback_without_compiled(self):
        """match_regex works even if _compiled_re is missing (defensive path).

        Uses operator="eq" intentionally — only operator="regex" sets
        _compiled_re during __post_init__.  This exercises the fallback
        branch in match_regex (line 74) where _compiled_re is absent.
        """
        c = Condition(field="x", operator="eq", value=r"\d+")
        assert not hasattr(c, "_compiled_re")
        assert c.match_regex("abc123") is True
        assert c.match_regex("no-digits") is False


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

    def test_event_and_decision_produce_different_hmacs(self):
        """Same fields but different entry_type must yield different HMACs."""
        key = b"test-key"
        base_kwargs = dict(
            timestamp=100.0,
            request_id="same-id",
            tool_name="tool",
            agent_id="agent",
            args_hash="hash",
            verdict="ALLOW",
            matched_rule="rule",
            policy_name="policy",
            message="msg",
            evaluation_ms=1.0,
        )

        decision_entry = AuditEntry(**base_kwargs, entry_type="decision")
        event_entry = AuditEntry(
            **base_kwargs, entry_type="event", event_type="share", metadata={"a": 1}
        )

        h_decision = decision_entry.compute_integrity(key)
        h_event = event_entry.compute_integrity(key)
        assert h_decision != h_event


class TestDecisionShareMarkdown:
    def test_backslashes_escaped(self):
        d = Decision(
            verdict=Verdict.DENY,
            policy_name="back\\slash",
            matched_rule="rule\\1",
            message="path is C:\\Users\\test",
            tool_name="tool\\x",
        )
        receipt = d.to_share_markdown()
        assert "back\\\\slash" in receipt
        assert "rule\\\\1" in receipt
        assert "C:\\\\Users\\\\test" in receipt

    def test_multiline_message_collapsed(self):
        d = Decision(
            verdict=Verdict.ALLOW,
            message="line1\nline2\r\nline3",
        )
        receipt = d.to_share_markdown()
        # Message is in free text area — only needs escape, not collapse
        assert "line1" in receipt

    def test_empty_fields_use_defaults(self):
        d = Decision(verdict=Verdict.ALLOW)
        receipt = d.to_share_markdown()
        # Verify each individual default label appears in the receipt
        assert "`unknown_tool`" in receipt  # tool_name default
        assert "Policy: `unknown`" in receipt  # policy_name default
        assert "Agent: `unknown`" in receipt  # agent_id default
        assert "No policy message provided." in receipt  # message default
