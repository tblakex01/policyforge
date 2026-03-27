"""Tests for the policy evaluation engine."""

import textwrap

import pytest

from policyforge.engine import PolicyEngine
from policyforge.models import Verdict


@pytest.fixture
def policy_dir(tmp_path):
    """Temp dir with a test policy."""
    (tmp_path / "test.yaml").write_text(
        textwrap.dedent(
            """\
        name: test-policy
        fail_mode: closed
        default_verdict: ALLOW
        rules:
          - name: block-shell
            priority: 10
            verdict: DENY
            message: "Shell blocked"
            match_strategy: any
            conditions:
              - field: tool_name
                operator: in
                value: ["run_shell", "bash", "exec"]

          - name: block-internal-urls
            priority: 20
            verdict: DENY
            message: "Internal URLs blocked"
            conditions:
              - field: tool_name
                operator: eq
                value: http_request
              - field: args.url
                operator: regex
                value: "https?://10\\\\."

          - name: log-queries
            priority: 50
            verdict: LOG_ONLY
            message: "DB query logged"
            conditions:
              - field: tool_name
                operator: eq
                value: query_db

          - name: block-big-delete
            priority: 30
            verdict: DENY
            message: "Bulk delete blocked"
            conditions:
              - field: tool_name
                operator: eq
                value: delete_records
              - field: args.count
                operator: gt
                value: 100
    """
        )
    )
    return tmp_path


@pytest.fixture
def engine(policy_dir):
    return PolicyEngine(policy_paths=[policy_dir])


class TestBasicEvaluation:
    def test_allow_safe_tool(self, engine):
        decision = engine.evaluate("web_search", {"query": "test"})
        assert decision.verdict == Verdict.ALLOW

    def test_deny_shell(self, engine):
        decision = engine.evaluate("run_shell", {"command": "ls"})
        assert decision.verdict == Verdict.DENY
        assert decision.matched_rule == "block-shell"

    def test_deny_bash(self, engine):
        decision = engine.evaluate("bash", {"cmd": "whoami"})
        assert decision.verdict == Verdict.DENY

    def test_log_only_query(self, engine):
        decision = engine.evaluate("query_db", {"sql": "SELECT 1"})
        assert decision.verdict == Verdict.LOG_ONLY
        assert decision.matched_rule == "log-queries"

    def test_has_timing(self, engine):
        decision = engine.evaluate("web_search", {})
        assert decision.evaluation_ms >= 0

    def test_has_request_id(self, engine):
        decision = engine.evaluate("web_search", {})
        assert len(decision.request_id) == 16


class TestConditionOperators:
    def test_regex_match(self, engine):
        decision = engine.evaluate(
            "http_request",
            {"url": "http://10.0.1.5/api"},
        )
        assert decision.verdict == Verdict.DENY
        assert decision.matched_rule == "block-internal-urls"

    def test_regex_no_match(self, engine):
        decision = engine.evaluate(
            "http_request",
            {"url": "https://api.example.com/v1"},
        )
        assert decision.verdict == Verdict.ALLOW

    def test_gt_operator(self, engine):
        decision = engine.evaluate("delete_records", {"count": 500})
        assert decision.verdict == Verdict.DENY
        assert decision.matched_rule == "block-big-delete"

    def test_gt_under_threshold(self, engine):
        decision = engine.evaluate("delete_records", {"count": 50})
        assert decision.verdict == Verdict.ALLOW


class TestFailClosed:
    def test_no_policies_denies(self):
        engine = PolicyEngine()  # no policies loaded
        decision = engine.evaluate("anything", {})
        assert decision.verdict == Verdict.DENY
        assert "No active policies" in decision.message

    def test_eval_error_denies_on_closed(self, tmp_path):
        """A condition that errors at evaluation time → fail-closed."""
        (tmp_path / "bad.yaml").write_text(
            textwrap.dedent(
                """\
            name: runtime-error-policy
            fail_mode: closed
            default_verdict: ALLOW
            rules:
              - name: bad-compare
                verdict: DENY
                conditions:
                  - field: args.value
                    operator: gt
                    value: 100
        """
            )
        )
        engine = PolicyEngine(policy_paths=[tmp_path])
        decision = engine.evaluate("test_tool", {"value": "not_a_number"})
        assert decision.verdict == Verdict.DENY
        assert "fail-closed" in decision.message.lower() or "error" in decision.message.lower()


class TestFailOpen:
    def test_fail_open_policy(self, tmp_path):
        """A condition that errors at evaluation time → fail-open."""
        (tmp_path / "open.yaml").write_text(
            textwrap.dedent(
                """\
            name: open-policy
            fail_mode: open
            default_verdict: DENY
            rules:
              - name: bad-compare
                verdict: DENY
                conditions:
                  - field: args.value
                    operator: gt
                    value: 100
        """
            )
        )
        engine = PolicyEngine(policy_paths=[tmp_path])
        decision = engine.evaluate("test_tool", {"value": "not_a_number"})
        assert decision.verdict == Verdict.ALLOW
        assert "fail-open" in decision.message.lower()


class TestDisabledPolicy:
    def test_disabled_policy_skipped(self, tmp_path):
        (tmp_path / "disabled.yaml").write_text(
            textwrap.dedent(
                """\
            name: disabled-policy
            enabled: false
            default_verdict: DENY
            rules:
              - name: deny-all
                verdict: DENY
                conditions:
                  - field: tool_name
                    operator: regex
                    value: ".*"
        """
            )
        )
        (tmp_path / "allow.yaml").write_text(
            textwrap.dedent(
                """\
            name: allow-policy
            default_verdict: ALLOW
            rules: []
        """
            )
        )
        engine = PolicyEngine(policy_paths=[tmp_path])
        # disabled-policy would deny, but it's skipped
        decision = engine.evaluate("anything", {})
        assert decision.verdict == Verdict.ALLOW


class TestReload:
    def test_reload_replaces_policies(self, tmp_path):
        (tmp_path / "v1.yaml").write_text(
            textwrap.dedent(
                """\
            name: v1
            default_verdict: DENY
            rules: []
        """
            )
        )
        engine = PolicyEngine(policy_paths=[tmp_path])
        assert engine.policies[0].name == "v1"

        # Replace with v2
        (tmp_path / "v1.yaml").write_text(
            textwrap.dedent(
                """\
            name: v2
            default_verdict: ALLOW
            rules: []
        """
            )
        )
        engine.reload([tmp_path])
        assert engine.policies[0].name == "v2"


class TestExtraContext:
    def test_context_available_in_evaluation(self, tmp_path):
        (tmp_path / "ctx.yaml").write_text(
            textwrap.dedent(
                """\
            name: env-policy
            default_verdict: ALLOW
            rules:
              - name: block-prod
                verdict: DENY
                message: "Blocked in production"
                conditions:
                  - field: environment
                    operator: eq
                    value: production
        """
            )
        )
        engine = PolicyEngine(policy_paths=[tmp_path])
        # With prod context
        decision = engine.evaluate("any_tool", {}, context={"environment": "production"})
        assert decision.verdict == Verdict.DENY

        # With staging context
        decision = engine.evaluate("any_tool", {}, context={"environment": "staging"})
        assert decision.verdict == Verdict.ALLOW
