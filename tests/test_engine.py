"""Tests for the policy evaluation engine."""

import json
import textwrap
from concurrent.futures import ThreadPoolExecutor

import pytest

from policyforge.audit import AuditLogger
from policyforge.engine import PolicyEngine, _hash_args
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

    def test_audit_uses_full_sha256_args_hash(self, tmp_path):
        (tmp_path / "policy.yaml").write_text(
            textwrap.dedent(
                """\
            name: audit-policy
            default_verdict: ALLOW
            rules: []
        """
            )
        )
        audit_dir = tmp_path / "audit"
        audit = AuditLogger(log_dir=audit_dir, hmac_key="test-audit-key")
        engine = PolicyEngine(policy_paths=[tmp_path], audit_logger=audit)

        engine.evaluate("web_search", {"query": "test"})

        log_file = next(audit_dir.glob("audit_*.jsonl"))
        record = json.loads(log_file.read_text(encoding="utf-8").strip())

        assert len(record["args_hash"]) == 64


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

    def test_neq_operator(self, tmp_path):
        (tmp_path / "neq.yaml").write_text(
            textwrap.dedent(
                """\
            name: neq-policy
            default_verdict: ALLOW
            rules:
              - name: deny-non-admin
                verdict: DENY
                conditions:
                  - field: args.role
                    operator: neq
                    value: admin
        """
            )
        )
        engine = PolicyEngine(policy_paths=[tmp_path])
        assert engine.evaluate("check", {"role": "guest"}).verdict == Verdict.DENY
        assert engine.evaluate("check", {"role": "admin"}).verdict == Verdict.ALLOW

    def test_not_in_operator(self, tmp_path):
        (tmp_path / "notin.yaml").write_text(
            textwrap.dedent(
                """\
            name: notin-policy
            default_verdict: ALLOW
            rules:
              - name: deny-unknown-env
                verdict: DENY
                conditions:
                  - field: args.env
                    operator: not_in
                    value: ["prod", "staging"]
        """
            )
        )
        engine = PolicyEngine(policy_paths=[tmp_path])
        assert engine.evaluate("deploy", {"env": "dev"}).verdict == Verdict.DENY
        assert engine.evaluate("deploy", {"env": "prod"}).verdict == Verdict.ALLOW

    def test_contains_operator(self, tmp_path):
        (tmp_path / "contains.yaml").write_text(
            textwrap.dedent(
                """\
            name: contains-policy
            default_verdict: ALLOW
            rules:
              - name: deny-admin-path
                verdict: DENY
                conditions:
                  - field: args.url
                    operator: contains
                    value: "/admin"
        """
            )
        )
        engine = PolicyEngine(policy_paths=[tmp_path])
        assert engine.evaluate("fetch", {"url": "/api/admin/users"}).verdict == Verdict.DENY
        assert engine.evaluate("fetch", {"url": "/api/public"}).verdict == Verdict.ALLOW

    def test_lt_operator(self, tmp_path):
        (tmp_path / "lt.yaml").write_text(
            textwrap.dedent(
                """\
            name: lt-policy
            default_verdict: ALLOW
            rules:
              - name: deny-low-priority
                verdict: DENY
                conditions:
                  - field: args.priority
                    operator: lt
                    value: 5
        """
            )
        )
        engine = PolicyEngine(policy_paths=[tmp_path])
        assert engine.evaluate("task", {"priority": 3}).verdict == Verdict.DENY
        assert engine.evaluate("task", {"priority": 5}).verdict == Verdict.ALLOW
        assert engine.evaluate("task", {"priority": 10}).verdict == Verdict.ALLOW

    def test_gte_operator(self, tmp_path):
        (tmp_path / "gte.yaml").write_text(
            textwrap.dedent(
                """\
            name: gte-policy
            default_verdict: ALLOW
            rules:
              - name: deny-high-risk
                verdict: DENY
                conditions:
                  - field: args.risk_score
                    operator: gte
                    value: 80
        """
            )
        )
        engine = PolicyEngine(policy_paths=[tmp_path])
        assert engine.evaluate("assess", {"risk_score": 80}).verdict == Verdict.DENY
        assert engine.evaluate("assess", {"risk_score": 95}).verdict == Verdict.DENY
        assert engine.evaluate("assess", {"risk_score": 79}).verdict == Verdict.ALLOW

    def test_lte_operator(self, tmp_path):
        (tmp_path / "lte.yaml").write_text(
            textwrap.dedent(
                """\
            name: lte-policy
            default_verdict: ALLOW
            rules:
              - name: deny-small-batch
                verdict: DENY
                conditions:
                  - field: args.batch_size
                    operator: lte
                    value: 10
        """
            )
        )
        engine = PolicyEngine(policy_paths=[tmp_path])
        assert engine.evaluate("process", {"batch_size": 5}).verdict == Verdict.DENY
        assert engine.evaluate("process", {"batch_size": 10}).verdict == Verdict.DENY
        assert engine.evaluate("process", {"batch_size": 11}).verdict == Verdict.ALLOW


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
        assert "not_a_number" not in decision.message

    def test_type_error_in_condition_denies_on_closed(self, tmp_path):
        """Type mismatches must trigger fail-closed instead of silently skipping."""
        (tmp_path / "bad_contains.yaml").write_text(
            textwrap.dedent(
                """\
            name: type-error-policy
            fail_mode: closed
            default_verdict: ALLOW
            rules:
              - name: expect-string
                verdict: DENY
                conditions:
                  - field: args.value
                    operator: contains
                    value: admin
        """
            )
        )
        engine = PolicyEngine(policy_paths=[tmp_path])
        decision = engine.evaluate("test_tool", {"value": 123})
        assert decision.verdict == Verdict.DENY
        assert "fail-closed" in decision.message.lower() or "error" in decision.message.lower()
        assert "123" not in decision.message


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
        assert "not_a_number" not in decision.message

    def test_fail_open_does_not_bypass_later_deny(self, tmp_path):
        (tmp_path / "aaa-open.yaml").write_text(
            textwrap.dedent(
                """\
            name: open-policy
            fail_mode: open
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
        (tmp_path / "zzz-deny.yaml").write_text(
            textwrap.dedent(
                """\
            name: deny-policy
            default_verdict: ALLOW
            rules:
              - name: block-test-tool
                verdict: DENY
                conditions:
                  - field: tool_name
                    operator: eq
                    value: test_tool
        """
            )
        )
        engine = PolicyEngine(policy_paths=[tmp_path])
        decision = engine.evaluate("test_tool", {"value": "not_a_number"})
        assert decision.verdict == Verdict.DENY
        assert decision.matched_rule == "block-test-tool"


class TestFailLog:
    def test_fail_log_does_not_bypass_later_deny(self, tmp_path):
        (tmp_path / "aaa-log.yaml").write_text(
            textwrap.dedent(
                """\
            name: log-policy
            fail_mode: log
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
        (tmp_path / "zzz-deny.yaml").write_text(
            textwrap.dedent(
                """\
            name: deny-policy
            default_verdict: ALLOW
            rules:
              - name: block-test-tool
                verdict: DENY
                conditions:
                  - field: tool_name
                    operator: eq
                    value: test_tool
        """
            )
        )
        engine = PolicyEngine(policy_paths=[tmp_path])
        decision = engine.evaluate("test_tool", {"value": "not_a_number"})
        assert decision.verdict == Verdict.DENY
        assert decision.matched_rule == "block-test-tool"


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


class TestRulePrecedence:
    def test_later_deny_overrides_earlier_allow(self, tmp_path):
        (tmp_path / "precedence.yaml").write_text(
            textwrap.dedent(
                """\
            name: precedence-policy
            default_verdict: DENY
            rules:
              - name: allow-delete
                priority: 10
                verdict: ALLOW
                conditions:
                  - field: tool_name
                    operator: eq
                    value: delete_records
              - name: deny-big-delete
                priority: 20
                verdict: DENY
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
        engine = PolicyEngine(policy_paths=[tmp_path])
        decision = engine.evaluate("delete_records", {"count": 500})

        assert decision.verdict == Verdict.DENY
        assert decision.matched_rule == "deny-big-delete"


class TestShareReceipt:
    def test_render_share_receipt_returns_sanitized_markdown(self, policy_dir, tmp_path):
        audit_dir = tmp_path / "audit"
        audit = AuditLogger(log_dir=audit_dir, hmac_key="test-audit-key")
        engine = PolicyEngine(
            policy_paths=[policy_dir],
            audit_logger=audit,
            agent_id="agent-share-test",
        )

        decision = engine.evaluate("run_shell", {"command": "rm -rf /tmp/demo"})
        receipt = engine.render_share_receipt(decision)

        assert decision.verdict == Verdict.DENY
        assert "PolicyForge Policy Receipt" in receipt
        assert "run_shell" in receipt
        assert "block-shell" in receipt
        assert decision.request_id in receipt
        assert "rm -rf /tmp/demo" not in receipt
        assert decision.args_hash in receipt

    def test_render_share_receipt_logs_share_event(self, policy_dir, tmp_path):
        audit_dir = tmp_path / "audit"
        audit = AuditLogger(log_dir=audit_dir, hmac_key="test-audit-key")
        engine = PolicyEngine(
            policy_paths=[policy_dir],
            audit_logger=audit,
            agent_id="agent-share-test",
        )

        decision = engine.evaluate("query_db", {"sql": "SELECT * FROM guests"})
        engine.render_share_receipt(decision)

        log_file = next(audit_dir.glob("audit_*.jsonl"))
        records = [
            json.loads(line)
            for line in log_file.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

        assert len(records) == 2
        assert records[1]["kind"] == "event"
        assert records[1]["event"] == "share_receipt_generated"
        assert records[1]["rid"] == decision.request_id
        assert records[1]["meta"]["verdict"] == "LOG_ONLY"

    def test_render_share_receipt_escapes_markdown_content(self, tmp_path):
        (tmp_path / "receipt.yaml").write_text(
            textwrap.dedent(
                """\
            name: "prod`policy"
            default_verdict: ALLOW
            rules:
              - name: "block`rule"
                verdict: DENY
                message: "Do not paste `raw` values"
                conditions:
                  - field: tool_name
                    operator: eq
                    value: "run`tool"
        """
            )
        )
        engine = PolicyEngine(policy_paths=[tmp_path], agent_id="agent`one")

        decision = engine.evaluate("run`tool", {"command": "rm -rf /tmp/demo"})
        receipt = engine.render_share_receipt(decision)

        # Inline fields: backticks can't be backslash-escaped inside a
        # CommonMark code span, so they're replaced with ``'``.
        assert "`run`tool`" not in receipt
        assert "run'tool" in receipt
        assert "prod'policy" in receipt
        # Free-text Reason section still uses backslash escaping — that
        # works outside of code spans.
        assert "Do not paste \\`raw\\` values" in receipt


class TestHashArgsFallback:
    def test_non_serializable_args_still_hash(self):
        """Args with non-JSON-serializable values fall back to str()."""
        result = _hash_args({"data": {1, 2, 3}})
        assert isinstance(result, str)
        assert len(result) == 64  # SHA-256 hex

    def test_deterministic_for_same_args(self):
        h1 = _hash_args({"a": 1, "b": "two"})
        h2 = _hash_args({"b": "two", "a": 1})
        assert h1 == h2


class TestLoadFilePath:
    def test_load_single_file(self, tmp_path):
        """engine.load() with a file path (not directory) should work."""
        policy_file = tmp_path / "single.yaml"
        policy_file.write_text(
            textwrap.dedent(
                """\
            name: single-file-policy
            default_verdict: ALLOW
            rules: []
        """
            )
        )
        engine = PolicyEngine()
        engine.load(policy_file)
        assert len(engine.policies) == 1
        assert engine.policies[0].name == "single-file-policy"

    def test_constructor_with_file_paths(self, tmp_path):
        policy_file = tmp_path / "direct.yaml"
        policy_file.write_text(
            textwrap.dedent(
                """\
            name: direct-policy
            default_verdict: DENY
            rules: []
        """
            )
        )
        engine = PolicyEngine(policy_paths=[policy_file])
        assert engine.policies[0].name == "direct-policy"


class TestAllowRulePrecedence:
    def test_explicit_allow_overrides_default_deny(self, tmp_path):
        """An explicit ALLOW rule in a policy prevents that policy's default DENY."""
        (tmp_path / "allow.yaml").write_text(
            textwrap.dedent(
                """\
            name: allow-policy
            default_verdict: DENY
            rules:
              - name: allow-read
                verdict: ALLOW
                message: "Read operations are safe"
                conditions:
                  - field: tool_name
                    operator: eq
                    value: read_file
        """
            )
        )
        engine = PolicyEngine(policy_paths=[tmp_path])
        # Without the ALLOW rule matching, default verdict would be DENY
        decision_unmatched = engine.evaluate("write_file", {})
        assert decision_unmatched.verdict == Verdict.DENY

        # With the ALLOW rule matching, tool should be allowed
        decision_matched = engine.evaluate("read_file", {})
        assert decision_matched.verdict == Verdict.ALLOW

    def test_log_only_overrides_allow_in_same_policy(self, tmp_path):
        (tmp_path / "mixed.yaml").write_text(
            textwrap.dedent(
                """\
            name: mixed-policy
            default_verdict: DENY
            rules:
              - name: allow-tool
                priority: 20
                verdict: ALLOW
                conditions:
                  - field: tool_name
                    operator: eq
                    value: query_db
              - name: log-tool
                priority: 10
                verdict: LOG_ONLY
                conditions:
                  - field: tool_name
                    operator: eq
                    value: query_db
        """
            )
        )
        engine = PolicyEngine(policy_paths=[tmp_path])
        decision = engine.evaluate("query_db", {})
        assert decision.verdict == Verdict.LOG_ONLY
        assert decision.matched_rule == "log-tool"


class TestMultiPolicyInteraction:
    def test_log_only_plus_allow_yields_log_only(self, tmp_path):
        (tmp_path / "aaa-log.yaml").write_text(
            textwrap.dedent(
                """\
            name: log-policy
            default_verdict: ALLOW
            rules:
              - name: log-search
                verdict: LOG_ONLY
                conditions:
                  - field: tool_name
                    operator: eq
                    value: web_search
        """
            )
        )
        (tmp_path / "zzz-allow.yaml").write_text(
            textwrap.dedent(
                """\
            name: allow-policy
            default_verdict: ALLOW
            rules: []
        """
            )
        )
        engine = PolicyEngine(policy_paths=[tmp_path])
        decision = engine.evaluate("web_search", {})
        assert decision.verdict == Verdict.LOG_ONLY

    def test_log_only_plus_deny_yields_deny(self, tmp_path):
        (tmp_path / "aaa-log.yaml").write_text(
            textwrap.dedent(
                """\
            name: log-policy
            default_verdict: ALLOW
            rules:
              - name: log-search
                verdict: LOG_ONLY
                conditions:
                  - field: tool_name
                    operator: eq
                    value: web_search
        """
            )
        )
        (tmp_path / "zzz-deny.yaml").write_text(
            textwrap.dedent(
                """\
            name: deny-policy
            default_verdict: ALLOW
            rules:
              - name: deny-search
                verdict: DENY
                conditions:
                  - field: tool_name
                    operator: eq
                    value: web_search
        """
            )
        )
        engine = PolicyEngine(policy_paths=[tmp_path])
        decision = engine.evaluate("web_search", {})
        assert decision.verdict == Verdict.DENY
        assert decision.matched_rule == "deny-search"

    def test_all_disabled_policies_fail_closed(self, tmp_path):
        (tmp_path / "d1.yaml").write_text(
            textwrap.dedent(
                """\
            name: disabled1
            enabled: false
            default_verdict: ALLOW
            rules: []
        """
            )
        )
        (tmp_path / "d2.yaml").write_text(
            textwrap.dedent(
                """\
            name: disabled2
            enabled: false
            default_verdict: ALLOW
            rules: []
        """
            )
        )
        engine = PolicyEngine(policy_paths=[tmp_path])
        decision = engine.evaluate("anything", {})
        assert decision.verdict == Verdict.DENY
        assert "No active policies" in decision.message

    def test_multiple_allow_rules_across_policies(self, tmp_path):
        for i in range(3):
            (tmp_path / f"policy{i}.yaml").write_text(
                textwrap.dedent(
                    f"""\
                name: policy-{i}
                default_verdict: ALLOW
                rules: []
            """
                )
            )
        engine = PolicyEngine(policy_paths=[tmp_path])
        decision = engine.evaluate("any_tool", {})
        assert decision.verdict == Verdict.ALLOW
        assert decision.policy_name == "aggregate"


class TestConcurrentEvaluate:
    def test_concurrent_evaluations_are_thread_safe(self, tmp_path):
        (tmp_path / "policy.yaml").write_text(
            textwrap.dedent(
                """\
            name: concurrent-policy
            default_verdict: ALLOW
            rules:
              - name: deny-shell
                verdict: DENY
                conditions:
                  - field: tool_name
                    operator: eq
                    value: run_shell
        """
            )
        )
        engine = PolicyEngine(policy_paths=[tmp_path])
        errors: list[str] = []

        def eval_safe(tool: str) -> None:
            try:
                d = engine.evaluate(tool, {"i": 1})
                expected = Verdict.DENY if tool == "run_shell" else Verdict.ALLOW
                if d.verdict != expected:
                    errors.append(f"{tool}: expected {expected}, got {d.verdict}")
            except Exception as exc:
                errors.append(f"{tool}: exception {exc}")

        with ThreadPoolExecutor(max_workers=8) as pool:
            tools = ["run_shell", "web_search", "read_file"] * 100
            list(pool.map(eval_safe, tools))

        assert errors == [], f"Concurrent eval errors: {errors}"


class TestFieldResolution:
    def test_non_dict_traversal_raises_key_error(self, tmp_path):
        """Traversing into a non-dict segment returns a safe ALLOW (missing field)."""
        (tmp_path / "deep.yaml").write_text(
            textwrap.dedent(
                """\
            name: deep-field-policy
            default_verdict: ALLOW
            rules:
              - name: check-nested
                verdict: DENY
                conditions:
                  - field: args.nested.value
                    operator: eq
                    value: bad
        """
            )
        )
        engine = PolicyEngine(policy_paths=[tmp_path])
        # args.nested is a string, not a dict — traversal should fail safely
        decision = engine.evaluate("tool", {"nested": "flat-string"})
        assert decision.verdict == Verdict.ALLOW
