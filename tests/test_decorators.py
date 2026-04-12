"""Tests for the decorator and wrapper interfaces."""

import asyncio
import logging
import textwrap

import pytest

from policyforge.decorators import (
    PolicyDeniedError,
    PolicyGateWrapper,
    _bind_positional_args,
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


class TestLogOnlyThroughDecorator:
    def test_log_only_allows_execution_and_logs(self, tmp_path, caplog):
        (tmp_path / "log.yaml").write_text(
            textwrap.dedent(
                """\
            name: log-policy
            default_verdict: ALLOW
            rules:
              - name: log-everything
                verdict: LOG_ONLY
                message: "Logging tool call"
                conditions:
                  - field: tool_name
                    operator: eq
                    value: search
        """
            )
        )
        engine = PolicyEngine(policy_paths=[tmp_path])

        @policy_gate(engine, tool_name="search")
        def search(query: str) -> str:
            return f"results for {query}"

        with caplog.at_level(logging.INFO):
            result = search(query="test")

        assert result == "results for test"
        assert any("LOG_ONLY" in r.message for r in caplog.records)


class TestMethodBinding:
    def test_decorator_on_instance_method(self, tmp_path):
        (tmp_path / "p.yaml").write_text(
            textwrap.dedent(
                """\
            name: method-policy
            default_verdict: ALLOW
            rules:
              - name: block-admin
                verdict: DENY
                conditions:
                  - field: args.action
                    operator: eq
                    value: admin
        """
            )
        )
        engine = PolicyEngine(policy_paths=[tmp_path])

        class Service:
            @policy_gate(engine)
            def do_action(self, action: str) -> str:
                return f"did {action}"

        svc = Service()
        assert svc.do_action(action="read") == "did read"
        with pytest.raises(PolicyDeniedError):
            svc.do_action(action="admin")

    def test_positional_args_resolved_for_methods(self, tmp_path):
        (tmp_path / "p.yaml").write_text(
            textwrap.dedent(
                """\
            name: positional-policy
            default_verdict: ALLOW
            rules:
              - name: block-large
                verdict: DENY
                conditions:
                  - field: args.count
                    operator: gt
                    value: 100
        """
            )
        )
        engine = PolicyEngine(policy_paths=[tmp_path])

        class Worker:
            @policy_gate(engine)
            def process(self, count: int) -> int:
                return count

        w = Worker()
        assert w.process(5) == 5
        with pytest.raises(PolicyDeniedError):
            w.process(200)


class TestBindPositionalArgsFallback:
    def test_returns_kwargs_when_bind_fails(self):
        """When sig.bind raises TypeError, fall back to kwargs only."""
        import inspect

        def func(a: int) -> int:
            return a

        sig = inspect.signature(func)
        # Pass wrong number of positional args — bind should fail
        result = _bind_positional_args(sig, (1, 2, 3), {"extra": "kw"})
        assert result == {"extra": "kw"}

    def test_returns_kwargs_when_sig_is_none(self):
        result = _bind_positional_args(None, (1, 2), {"a": 1})
        assert result == {"a": 1}

    def test_returns_kwargs_when_no_positional_args(self):
        import inspect

        def func(a: int) -> int:
            return a

        sig = inspect.signature(func)
        result = _bind_positional_args(sig, (), {"a": 42})
        assert result == {"a": 42}


class TestSignatureFailureFallback:
    def test_wraps_builtin_without_crashing(self, engine):
        """Wrapping a C builtin (no inspectable signature) should still gate."""
        wrapped = policy_gate(engine, tool_name="safe_builtin")(len)
        assert wrapped([1, 2, 3]) == 3
