"""Tests for the decorator and wrapper interfaces."""

import asyncio
import logging
import textwrap

import pytest

from policyforge.decorators import (
    PolicyArgumentBindingError,
    PolicyDeniedError,
    PolicyGateWrapper,
    _bind_positional_args,
    policy_gate,
)
from policyforge.engine import PolicyEngine
from policyforge.models import Verdict


@pytest.fixture
def engine(tmp_path):
    (tmp_path / "policy.yaml").write_text(textwrap.dedent("""\
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
    """))
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
        (tmp_path / "defaults.yaml").write_text(textwrap.dedent("""\
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
        """))
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
        (tmp_path / "p.yaml").write_text(textwrap.dedent("""\
            name: ctx-test
            default_verdict: ALLOW
            rules:
              - name: block-prod
                verdict: DENY
                conditions:
                  - field: environment
                    operator: eq
                    value: production
        """))
        engine = PolicyEngine(policy_paths=[tmp_path])
        wrapper = PolicyGateWrapper(engine, extra_context={"environment": "production"})

        safe_fn = wrapper.wrap(lambda: "x", tool_name="any")
        with pytest.raises(PolicyDeniedError):
            safe_fn()


class TestLogOnlyThroughDecorator:
    def test_log_only_allows_execution_and_logs(self, tmp_path, caplog):
        (tmp_path / "log.yaml").write_text(textwrap.dedent("""\
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
        """))
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
        (tmp_path / "p.yaml").write_text(textwrap.dedent("""\
            name: method-policy
            default_verdict: ALLOW
            rules:
              - name: block-admin
                verdict: DENY
                conditions:
                  - field: args.action
                    operator: eq
                    value: admin
        """))
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
        (tmp_path / "p.yaml").write_text(textwrap.dedent("""\
            name: positional-policy
            default_verdict: ALLOW
            rules:
              - name: block-large
                verdict: DENY
                conditions:
                  - field: args.count
                    operator: gt
                    value: 100
        """))
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
    def test_raises_when_bind_fails(self):
        """Binding failures must fail closed instead of hiding positional args."""
        import inspect

        def func(a: int) -> int:
            return a

        sig = inspect.signature(func)
        with pytest.raises(PolicyArgumentBindingError):
            _bind_positional_args(sig, (1, 2, 3), {"extra": "kw"})

    def test_raises_when_sig_is_none_and_positional_args_present(self):
        with pytest.raises(PolicyArgumentBindingError):
            _bind_positional_args(None, (1, 2), {"a": 1})

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

    def test_uninspectable_callable_with_positional_args_denied(self, tmp_path, monkeypatch):
        (tmp_path / "p.yaml").write_text(textwrap.dedent("""\
            name: path-policy
            default_verdict: ALLOW
            rules:
              - name: block-sensitive-path
                verdict: DENY
                conditions:
                  - field: args.path
                    operator: eq
                    value: /etc/shadow
        """))
        engine = PolicyEngine(policy_paths=[tmp_path])

        def target(path: str) -> str:
            return f"executed:{path}"

        monkeypatch.setattr(
            "policyforge.decorators.inspect.signature",
            lambda _func: (_ for _ in ()).throw(ValueError("no signature")),
        )
        wrapped = policy_gate(engine, tool_name="read_file")(target)

        with pytest.raises(PolicyDeniedError) as exc_info:
            wrapped("/etc/shadow")

        assert exc_info.value.decision.verdict == Verdict.DENY
        assert exc_info.value.decision.matched_rule == "argument_binding_failed"

    @pytest.mark.asyncio
    async def test_uninspectable_async_callable_with_positional_args_denied(
        self, engine, monkeypatch
    ):
        async def target(value: str) -> str:
            return f"executed:{value}"

        monkeypatch.setattr(
            "policyforge.decorators.inspect.signature",
            lambda _func: (_ for _ in ()).throw(ValueError("no signature")),
        )
        wrapped = policy_gate(engine, tool_name="async_tool")(target)

        with pytest.raises(PolicyDeniedError) as exc_info:
            await wrapped("sensitive-value")

        assert exc_info.value.decision.verdict == Verdict.DENY
        assert exc_info.value.decision.matched_rule == "argument_binding_failed"


@pytest.fixture
def argument_engine(tmp_path):
    (tmp_path / "arguments.yaml").write_text(textwrap.dedent("""\
            name: argument-policy
            default_verdict: ALLOW
            rules:
              - name: block-large-count
                verdict: DENY
                conditions:
                  - field: args.count
                    operator: gt
                    value: 100
            """))
    return PolicyEngine(policy_paths=[tmp_path])


@pytest.fixture(params=["decorator", "wrapper", "dict"])
def gate(argument_engine, request):
    def wrap(func):
        if request.param == "decorator":
            return policy_gate(argument_engine, tool_name="count_tool")(func)
        wrapper = PolicyGateWrapper(argument_engine)
        if request.param == "wrapper":
            return wrapper.wrap(func, tool_name="count_tool")
        return wrapper.wrap_dict({"count_tool": func})["count_tool"]

    return wrap


class TestEffectiveArgumentSecurity:
    @pytest.mark.parametrize("call_form", ["omitted", "positional", "keyword"])
    def test_defaults_and_explicit_values_are_denied(self, gate, call_form):
        calls = []

        def tool(count=101):
            calls.append(count)
            return count

        protected = gate(tool)
        with pytest.raises(PolicyDeniedError):
            if call_form == "omitted":
                protected()
            elif call_form == "positional":
                protected(101)
            else:
                protected(count=101)
        assert calls == []
        assert protected(5) == 5
        assert protected(count=6) == 6
        assert calls == [5, 6]

    def test_keyword_only_defaults_are_denied(self, gate):
        calls = []

        def tool(*, count=101):
            calls.append(count)
            return count

        protected = gate(tool)
        with pytest.raises(PolicyDeniedError):
            protected()
        assert calls == []
        assert protected(count=5) == 5

    @pytest.mark.parametrize("with_positional", [False, True])
    def test_variadic_keywords_are_denied_in_both_call_forms(self, gate, with_positional):
        calls = []

        def tool(label="test", **extras):
            calls.append((label, extras))
            return label, extras

        protected = gate(tool)
        args = ("label",) if with_positional else ()
        with pytest.raises(PolicyDeniedError):
            protected(*args, count=101)
        assert calls == []
        assert protected(*args, count=5) == (args[0] if args else "test", {"count": 5})

    def test_async_defaults_and_variadic_keywords_are_denied(self, gate):
        calls = []

        async def default_tool(count=101):
            calls.append(count)
            return count

        async def variadic_tool(label="test", **extras):
            calls.append(extras["count"])
            return label, extras

        protected_default = gate(default_tool)
        protected_variadic = gate(variadic_tool)
        for call in (
            protected_default,
            lambda: protected_variadic(count=101),
            lambda: protected_variadic("label", count=101),
        ):
            with pytest.raises(PolicyDeniedError):
                asyncio.run(call())
        assert calls == []
        assert asyncio.run(protected_default(count=5)) == 5
        assert asyncio.run(protected_variadic(count=6)) == ("test", {"count": 6})

    def test_bound_method_and_callable_defaults_are_denied(self, gate):
        calls = []

        class Tool:
            def run(self, count=101):
                calls.append(count)
                return count

            def __call__(self, count=101):
                return self.run(count)

        tool = Tool()
        for func in (tool.run, tool):
            protected = gate(func)
            with pytest.raises(PolicyDeniedError):
                protected()
            assert protected(count=5) == 5
        assert calls == [5, 5]

    def test_keyword_cannot_mask_positional_only_default(self, gate):
        calls = []

        def tool(count=101, /, **extras):
            calls.append((count, extras))
            return count

        protected = gate(tool)
        with pytest.raises(PolicyDeniedError, match="collid"):
            protected(count=5)
        assert calls == []
        assert protected(5, label="safe") == 5

    def test_variadic_container_name_cannot_mask_keyword_value(self, gate):
        calls = []

        def tool(**extras):
            calls.append(extras)
            return extras

        protected = gate(tool)
        with pytest.raises(PolicyDeniedError, match="collid"):
            protected(extras=101)
        assert calls == []
        assert protected(count=5) == {"count": 5}

    def test_uninspectable_callable_is_rejected_without_execution(self, gate):
        calls = []

        class OpaqueTool:
            __signature__ = "unavailable"

            def __call__(self, count=101):
                calls.append(count)
                return count

        protected = gate(OpaqueTool())
        with pytest.raises(PolicyDeniedError, match="inspectable signature"):
            protected(count=5)
        assert calls == []

    def test_variadic_positional_names_cannot_hide_keywords(self, gate):
        calls = []

        def tool(*items, **extras):
            calls.append((items, extras))
            return items, extras

        protected = gate(tool)
        with pytest.raises(PolicyDeniedError, match="collid"):
            protected(5, items=101)
        assert calls == []
        assert protected(5, 6, count=5) == ((5, 6), {"count": 5})

    def test_partial_callable_defaults_are_denied(self, gate):
        from functools import partial

        calls = []

        def tool(label, count):
            calls.append((label, count))
            return label, count

        protected = gate(partial(tool, "label", count=101))
        with pytest.raises(PolicyDeniedError):
            protected()
        assert calls == []
        assert protected(count=5) == ("label", 5)

    @pytest.mark.parametrize("kind", ["positional", "nested", "method", "async"])
    def test_partial_positional_values_are_denied(self, gate, kind):
        from functools import partial

        calls = []

        def tool(count=5):
            calls.append(count)
            return count

        async def async_tool(count=5):
            return tool(count)

        class Tool:
            def run(self, count=5):
                return tool(count)

        func = async_tool if kind == "async" else Tool().run if kind == "method" else tool
        bound = partial(func, 101)
        if kind == "nested":
            bound = partial(bound)
        protected = gate(bound)
        with pytest.raises(PolicyDeniedError):
            if kind == "async":
                asyncio.run(protected())
            else:
                protected()
        assert calls == []
        safe = gate(partial(func, 5))
        assert (asyncio.run(safe()) if kind == "async" else safe()) == 5

    def test_partial_keyword_updates_and_overrides_are_evaluated(self, gate):
        from functools import partial

        calls = []

        def tool(count=5):
            calls.append(count)
            return count

        bound = partial(tool, count=5)
        protected = gate(bound)
        bound.keywords["count"] = 101
        with pytest.raises(PolicyDeniedError):
            protected()
        assert calls == []
        assert protected(count=6) == 6
        bound.keywords["count"] = 5
        assert protected() == 5
        assert calls == [6, 5]

    def test_inherited_partial_calls_keep_argument_checks(self, gate):
        from functools import partial

        calls = []

        class BoundTool(partial):
            pass

        def tool(count=5):
            calls.append(count)
            return count

        protected = gate(BoundTool(tool, 101))
        with pytest.raises(PolicyDeniedError):
            protected()
        assert calls == []
        assert gate(BoundTool(tool, 5))() == 5

    def test_custom_partial_invocation_requires_adapter(self, gate):
        from functools import partial

        calls = []

        class CustomTool(partial):
            def __call__(self, *args, **kwargs):
                calls.append("custom invocation")
                return super().__call__(*args, **kwargs)

        protected = gate(CustomTool(lambda count=5: count))
        with pytest.raises(PolicyDeniedError, match="inspectable adapter") as exc_info:
            protected()
        assert exc_info.value.decision.matched_rule == "argument_binding_failed"
        assert calls == []

    def test_partial_invocation_uses_evaluated_keyword_snapshot(
        self, gate, argument_engine, monkeypatch
    ):
        from functools import partial

        calls = []

        def tool(count=5):
            calls.append(count)
            return count

        bound = partial(tool, count=5)
        protected = gate(bound)
        evaluate = argument_engine.evaluate

        def mutate_partial_during_evaluation(**kwargs):
            bound.keywords["count"] = 101
            return evaluate(**kwargs)

        monkeypatch.setattr(argument_engine, "evaluate", mutate_partial_during_evaluation)
        assert protected() == 5
        assert bound.keywords["count"] == 101
        assert calls == [5]

    def test_async_callable_object_defaults_are_denied(self, gate):
        calls = []

        class Tool:
            async def __call__(self, count=101):
                calls.append(count)
                return count

        protected = gate(Tool())
        with pytest.raises(PolicyDeniedError):
            protected()
        assert calls == []
        assert asyncio.run(protected(count=5)) == 5

    def test_uninspectable_builtin_requires_adapter(self, gate):
        protected = gate(dict)
        with pytest.raises(PolicyDeniedError, match="inspectable signature"):
            protected(count=5)

    @pytest.mark.parametrize("args, kwargs", [((5, 6), {}), ((), {"unknown": 5})])
    def test_invalid_call_is_denied_without_execution(self, gate, args, kwargs):
        calls = []

        def tool(count=5):
            calls.append(count)

        protected = gate(tool)
        with pytest.raises(PolicyDeniedError):
            protected(*args, **kwargs)
        assert calls == []

    def test_nested_variadic_policy_paths_still_deny(self, tmp_path):
        (tmp_path / "nested.yaml").write_text(textwrap.dedent("""\
                name: nested-policy
                default_verdict: ALLOW
                rules:
                  - name: block-nested-count
                    verdict: DENY
                    conditions:
                      - field: args.extras.count
                        operator: gt
                        value: 100
                """))
        engine = PolicyEngine(policy_paths=[tmp_path])
        calls = []

        @policy_gate(engine)
        def tool(label="test", **extras):
            calls.append(extras)
            return label, extras

        with pytest.raises(PolicyDeniedError):
            tool(count=101)
        with pytest.raises(PolicyDeniedError):
            tool("label", count=101)
        assert calls == []
        assert tool(count=5) == ("test", {"count": 5})
