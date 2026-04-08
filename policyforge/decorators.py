"""Framework-agnostic decorator and wrapper for tool-call gating.

Works with any callable — plain functions, class methods, MS Foundry Agent
tools, LangChain tools, or anything that follows a call convention.
"""

from __future__ import annotations

import asyncio
import functools
import inspect
import logging
from collections.abc import Callable
from typing import Any, TypeVar

from policyforge.engine import PolicyEngine
from policyforge.models import Decision, Verdict

logger = logging.getLogger(__name__)

F = TypeVar("F", bound=Callable[..., Any])


class PolicyDeniedError(Exception):
    """Raised when a tool call is denied by the policy engine."""

    def __init__(self, decision: Decision) -> None:
        self.decision = decision
        super().__init__(
            f"Tool call denied by policy '{decision.policy_name}' "
            f"(rule: {decision.matched_rule}): {decision.message}"
        )


def _bind_positional_args(
    sig: inspect.Signature | None,
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
) -> dict[str, Any]:
    """Map positional args to their parameter names for policy evaluation."""
    if not args or sig is None:
        return kwargs
    try:
        bound = sig.bind(*args, **kwargs)
        bound.apply_defaults()
        return dict(bound.arguments)
    except (TypeError, ValueError):
        return kwargs


def policy_gate(
    engine: PolicyEngine,
    *,
    tool_name: str | None = None,
    extra_context: dict[str, Any] | None = None,
) -> Callable[[F], F]:
    """Decorator that gates a function behind policy evaluation.

    Usage:
        engine = PolicyEngine(policy_paths=["./policies"])

        @policy_gate(engine, tool_name="web_search")
        def web_search(query: str, max_results: int = 10) -> list[str]:
            ...

        # Async functions work too:
        @policy_gate(engine)
        async def fetch_url(url: str) -> str:
            ...

    Args:
        engine: The PolicyEngine instance to evaluate against.
        tool_name: Override the function name used in policy matching.
                   Defaults to the decorated function's __name__.
        extra_context: Static context merged into every evaluation
                       (e.g., {"environment": "production"}).
    """

    def decorator(func: F) -> F:
        resolved_name = tool_name or func.__name__
        try:
            cached_sig = inspect.signature(func)
        except (TypeError, ValueError):
            cached_sig = None

        if asyncio.iscoroutinefunction(func):

            @functools.wraps(func)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                decision = engine.evaluate(
                    tool_name=resolved_name,
                    args=_bind_positional_args(cached_sig, args, kwargs),
                    context=extra_context,
                )
                _enforce(decision, resolved_name)
                return await func(*args, **kwargs)

            return async_wrapper  # type: ignore[return-value]

        @functools.wraps(func)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            decision = engine.evaluate(
                tool_name=resolved_name,
                args=_bind_positional_args(cached_sig, args, kwargs),
                context=extra_context,
            )
            _enforce(decision, resolved_name)
            return func(*args, **kwargs)

        return sync_wrapper  # type: ignore[return-value]

    return decorator


def _enforce(decision: Decision, tool_name: str) -> None:
    """Raise or log based on the decision verdict."""
    if decision.verdict == Verdict.DENY:
        logger.warning(
            "DENIED tool=%s policy=%s rule=%s msg=%s (%.1fms)",
            tool_name,
            decision.policy_name,
            decision.matched_rule,
            decision.message,
            decision.evaluation_ms,
        )
        raise PolicyDeniedError(decision)

    if decision.verdict == Verdict.LOG_ONLY:
        logger.info(
            "LOG_ONLY tool=%s policy=%s rule=%s msg=%s (%.1fms)",
            tool_name,
            decision.policy_name,
            decision.matched_rule,
            decision.message,
            decision.evaluation_ms,
        )

    # ALLOW — proceed silently
    logger.debug("ALLOWED tool=%s (%.1fms)", tool_name, decision.evaluation_ms)


class PolicyGateWrapper:
    """Wrap any callable with policy gating — useful for framework tools.

    This is the non-decorator approach for when you're wrapping tools
    that aren't under your direct control (e.g., MS Foundry Agent functions,
    third-party tool registries).

    Usage:
        wrapper = PolicyGateWrapper(engine)

        # Wrap a single callable
        safe_search = wrapper.wrap(my_search_fn, tool_name="web_search")
        result = safe_search(query="test")

        # Wrap a dict of tools (common in agent frameworks)
        tools = {"search": search_fn, "read_file": read_fn}
        safe_tools = wrapper.wrap_dict(tools)
    """

    def __init__(
        self,
        engine: PolicyEngine,
        extra_context: dict[str, Any] | None = None,
    ) -> None:
        self._engine = engine
        self._extra_context = extra_context or {}

    def wrap(
        self,
        func: Callable[..., Any],
        tool_name: str | None = None,
    ) -> Callable[..., Any]:
        """Wrap a single callable with policy gating."""
        name = tool_name or getattr(func, "__name__", "unknown_tool")
        return policy_gate(
            self._engine,
            tool_name=name,
            extra_context=self._extra_context,
        )(func)

    def wrap_dict(self, tools: dict[str, Callable[..., Any]]) -> dict[str, Callable[..., Any]]:
        """Wrap every callable in a name→function mapping."""
        return {name: self.wrap(fn, tool_name=name) for name, fn in tools.items()}
