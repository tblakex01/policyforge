"""Tests for the decorator and wrapper interfaces."""

import asyncio
import textwrap

import pytest

from policyforge.decorators import (
    PolicyDeniedError,
    PolicyGateWrapper,
    policy_gate,
)
from policyforge.engine import PolicyEngine
from policyforge.models import Verdict


@pytest.fixture
def engine(tmp_path):
    (tmp_path / "policy.yaml").write_text(
        textwrap.dedent(
            """\
        name: decorator-test
        default_verdict: ALLOW
        rules:
          - name: block-dangerous
            verdict: DENY
            message: "Dangerous tool blocked"
            match_strategy: any
            conditions:
              - field: tool_name
                operator: in
                value: ["dangerous_tool", "rm_rf"]
    """
        )
    )
    return PolicyEngine(policy_paths=[tmp_path])


class TestPolicyGateDecorator:
    def test_allows_safe_function(self, engine):
        @policy_gate(engine)
        def safe_tool(x: int) -> int:
            return x * 2

        assert safe_tool(x=5) == 10

    def test_denies_blocked_function(self, engine):
        @policy_gate(engine, tool_name="dangerous_tool")
        def do_danger(cmd: str) -> str:
            return "executed"

        with pytest.raises(PolicyDeniedError) as exc_info:
            do_danger(cmd="test")
        assert exc_info.value.decision.verdict == Verdict.DENY
        assert exc_info.value.decision.matched_rule == "block-dangerous"

    def test_preserves_function_name(self, engine):
        @policy_gate(engine)
        def my_func():
            pass

        assert my_func.__name__ == "my_func"

    def test_uses_explicit_tool_name(self, engine):
        @policy_gate(engine, tool_name="rm_rf")
        def innocent_name():
            return "never runs"

        with pytest.raises(PolicyDeniedError):
            innocent_name()

    def test_async_function_allowed(self, engine):
        @policy_gate(engine)
        async def async_safe(val: str) -> str:
            return f"got {val}"

        result = asyncio.run(async_safe(val="test"))
        assert result == "got test"

    def test_async_function_denied(self, engine):
        @policy_gate(engine, tool_name="dangerous_tool")
        async def async_danger() -> str:
            return "never"

        with pytest.raises(PolicyDeniedError):
            asyncio.run(async_danger())

    def test_default_arguments_are_available_to_policy(self, tmp_path):
        (tmp_path / "defaults.yaml").write_text(
            textwrap.dedent(
                """\
            name: defaults-test
            default_verdict: ALLOW
            rules:
              - name: block-large-default
                verdict: DENY
                conditions:
                  - field: tool_name
                    operator: eq
                    value: search
                  - field: args.max_results
                    operator: gt
                    value: 5
        """
            )
        )
        engine = PolicyEngine(policy_paths=[tmp_path])

        @policy_gate(engine, tool_name="search")
        def search(query: str, max_results: int = 10) -> str:
            return query

        with pytest.raises(PolicyDeniedError) as exc_info:
            search("test")

        assert exc_info.value.decision.matched_rule == "block-large-default"


class TestPolicyGateWrapper:
    def test_wrap_single(self, engine):
        def add(a: int, b: int) -> int:
            return a + b

        wrapper = PolicyGateWrapper(engine)
        safe_add = wrapper.wrap(add, tool_name="add")
        assert safe_add(a=2, b=3) == 5

    def test_wrap_dict(self, engine):
        tools = {
            "safe_op": lambda **kw: "ok",
            "dangerous_tool": lambda **kw: "should not run",
        }
        wrapper = PolicyGateWrapper(engine)
        safe_tools = wrapper.wrap_dict(tools)

        assert safe_tools["safe_op"]() == "ok"

        with pytest.raises(PolicyDeniedError):
            safe_tools["dangerous_tool"]()

    def test_extra_context_propagated(self, tmp_path):
        (tmp_path / "p.yaml").write_text(
            textwrap.dedent(
                """\
            name: ctx-test
            default_verdict: ALLOW
            rules:
              - name: block-prod
                verdict: DENY
                conditions:
                  - field: environment
                    operator: eq
                    value: production
        """
            )
        )
        engine = PolicyEngine(policy_paths=[tmp_path])
        wrapper = PolicyGateWrapper(engine, extra_context={"environment": "production"})

        safe_fn = wrapper.wrap(lambda: "x", tool_name="any")
        with pytest.raises(PolicyDeniedError):
            safe_fn()
