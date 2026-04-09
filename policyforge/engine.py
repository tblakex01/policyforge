"""Core policy evaluation engine — all decisions made locally, no network calls."""

from __future__ import annotations

import hashlib
import json
import logging
import time
from pathlib import Path
from typing import Any

from policyforge.audit import AuditLogger
from policyforge.loader import PolicyLoader
from policyforge.models import (
    Condition,
    Decision,
    FailMode,
    MatchStrategy,
    Policy,
    PolicyRule,
    Verdict,
)

logger = logging.getLogger(__name__)


def _resolve_field(context: dict[str, Any], dot_path: str) -> Any:
    """Resolve a dot-separated path against a nested dict.

    Example: _resolve_field({"args": {"url": "https://x"}}, "args.url")
             → "https://x"
    """
    current: Any = context
    for segment in dot_path.split("."):
        if isinstance(current, dict):
            if segment not in current:
                raise KeyError(f"Field '{dot_path}' not found at segment '{segment}'")
            current = current[segment]
        else:
            raise KeyError(
                f"Cannot traverse into non-dict at segment '{segment}' " f"in path '{dot_path}'"
            )
    return current


def _evaluate_condition(condition: Condition, context: dict[str, Any]) -> bool:
    """Evaluate a single condition against the tool-call context."""
    actual = _resolve_field(context, condition.field)
    expected = condition.value
    op = condition.operator

    if op == "eq":
        return bool(actual == expected)
    if op == "neq":
        return bool(actual != expected)
    if op == "in":
        return bool(actual in expected)
    if op == "not_in":
        return bool(actual not in expected)
    if op == "contains":
        return bool(expected in actual)
    if op == "regex":
        return condition.match_regex(str(actual))
    if op == "gt":
        return float(actual) > float(expected)
    if op == "lt":
        return float(actual) < float(expected)
    if op == "gte":
        return float(actual) >= float(expected)
    if op == "lte":
        return float(actual) <= float(expected)

    # Should never reach here due to Condition.__post_init__ validation
    raise ValueError(f"Unknown operator: {op}")


def _safe_eval_condition(condition: Condition, context: dict[str, Any]) -> bool:
    """Evaluate a condition, returning False only for missing fields."""
    try:
        return _evaluate_condition(condition, context)
    except KeyError:
        return False


def _evaluate_rule(rule: PolicyRule, context: dict[str, Any]) -> bool:
    """Return True if the rule's conditions match the context.

    A condition that references a missing field evaluates to False
    (the field doesn't exist, so it can't match).  This prevents
    rules from accidentally triggering on unrelated tool calls.
    """
    if not rule.conditions:
        return False

    if rule.match_strategy == MatchStrategy.ALL:
        return all(_safe_eval_condition(c, context) for c in rule.conditions)
    return any(_safe_eval_condition(c, context) for c in rule.conditions)


def _hash_args(args: dict[str, Any]) -> str:
    """SHA-256 hash of serialized args — audit-safe, no PII in logs."""
    try:
        serialized = json.dumps(args, sort_keys=True, default=str)
    except (TypeError, ValueError):
        serialized = str(args)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


class PolicyEngine:
    """Evaluate tool calls against locally-loaded YAML policies.

    All evaluation happens in-process with zero network calls.
    The engine is thread-safe for reads (policies are immutable once loaded).

    Args:
        policy_paths: Files or directories to load policies from.
        audit_logger: Optional AuditLogger for tamper-evident audit trails.
        agent_id: Identifier for the agent using this engine instance.
    """

    def __init__(
        self,
        policy_paths: list[str | Path] | None = None,
        audit_logger: AuditLogger | None = None,
        agent_id: str = "default",
    ) -> None:
        self._loader = PolicyLoader()
        self._policies: list[Policy] = []
        self._audit = audit_logger
        self._agent_id = agent_id

        if policy_paths:
            for p in policy_paths:
                self.load(p)

    @property
    def policies(self) -> list[Policy]:
        """Currently loaded policies (read-only view)."""
        return list(self._policies)

    def load(self, path: str | Path) -> None:
        """Load policies from a file or directory and append to the engine."""
        path = Path(path)
        if path.is_dir():
            self._policies.extend(self._loader.load_directory(path))
        else:
            self._policies.extend(self._loader.load_file(path))

    def reload(self, policy_paths: list[str | Path]) -> None:
        """Replace all policies with a fresh load from the given paths."""
        self._policies.clear()
        for p in policy_paths:
            self.load(p)
        logger.info("Reloaded %d policies", len(self._policies))

    def evaluate(
        self,
        tool_name: str,
        args: dict[str, Any] | None = None,
        context: dict[str, Any] | None = None,
    ) -> Decision:
        """Evaluate a tool call against all enabled policies.

        Args:
            tool_name: Name of the tool/function being invoked.
            args: Arguments the tool will receive.
            context: Additional context (caller identity, session, etc.).

        Returns:
            Decision with the final verdict, matched rule, and timing.

        The evaluation strategy:
            1. Iterate policies in load order.
            2. Within each policy, iterate rules sorted by priority.
            3. First matching DENY rule short-circuits with DENY.
            4. If no rule matches, use the policy's default_verdict.
            5. On any evaluation error, apply the policy's fail_mode.
        """
        args = args or {}
        args_hash = _hash_args(args)
        eval_context = {
            **(context or {}),
            "tool_name": tool_name,
            "args": args,
        }

        start = time.perf_counter()
        decision = self._run_evaluation(eval_context)
        elapsed_ms = (time.perf_counter() - start) * 1000
        decision = Decision(
            verdict=decision.verdict,
            matched_rule=decision.matched_rule,
            policy_name=decision.policy_name,
            message=decision.message,
            evaluation_ms=round(elapsed_ms, 3),
            request_id=decision.request_id,
            tool_name=tool_name,
            agent_id=self._agent_id,
            args_hash=args_hash,
        )

        # Audit trail
        if self._audit:
            self._audit.log(
                request_id=decision.request_id,
                tool_name=tool_name,
                agent_id=self._agent_id,
                args_hash=args_hash,
                verdict=decision.verdict.value,
                matched_rule=decision.matched_rule or "",
                policy_name=decision.policy_name or "",
                message=decision.message,
                evaluation_ms=decision.evaluation_ms,
            )

        return decision

    def render_share_receipt(self, decision: Decision) -> str:
        """Return a sanitized Markdown receipt and emit a share measurement event."""
        receipt = decision.to_share_markdown()

        if self._audit:
            self._audit.log_event(
                request_id=decision.request_id,
                event_type="share_receipt_generated",
                tool_name=decision.tool_name,
                agent_id=decision.agent_id or self._agent_id,
                metadata={
                    "format": "markdown",
                    "verdict": decision.verdict.value,
                    "policy_name": decision.policy_name or "",
                    "matched_rule": decision.matched_rule or "",
                },
            )

        return receipt

    def _run_evaluation(self, context: dict[str, Any]) -> Decision:
        """Inner evaluation loop — separated for clean error handling."""
        active_policies = [p for p in self._policies if p.enabled]

        if not active_policies:
            # No policies loaded → fail-closed by default
            return Decision(
                verdict=Verdict.DENY,
                message="No active policies loaded — fail-closed.",
            )

        allow_decision: Decision | None = None
        log_only_decision: Decision | None = None

        for policy in active_policies:
            try:
                decision = self._evaluate_policy(policy, context)
            except Exception as exc:
                decision = self._handle_eval_error(policy, exc)

            if decision.verdict == Verdict.DENY:
                return decision  # short-circuit on first DENY

            if decision.verdict == Verdict.LOG_ONLY and log_only_decision is None:
                log_only_decision = decision
                logger.warning(
                    "LOG_ONLY: policy=%s rule=%s tool=%s",
                    policy.name,
                    decision.matched_rule,
                    context.get("tool_name"),
                )
                continue

            if (
                decision.verdict == Verdict.ALLOW
                and allow_decision is None
                and "fail-open" in decision.message.lower()
            ):
                allow_decision = decision

        if log_only_decision is not None:
            return log_only_decision

        if allow_decision is not None:
            return allow_decision

        return Decision(
            verdict=Verdict.ALLOW,
            policy_name="aggregate",
            message="All policies passed.",
        )

    def _evaluate_policy(self, policy: Policy, context: dict[str, Any]) -> Decision:
        """Evaluate a single policy's rules against the context.

        Deny rules always win within a policy, even if a lower-priority
        allow or log-only rule also matches later in the rule list.
        """
        allow_decision: Decision | None = None
        log_only_decision: Decision | None = None

        for rule in policy.rules:
            if _evaluate_rule(rule, context):
                decision = Decision(
                    verdict=rule.verdict,
                    matched_rule=rule.name,
                    policy_name=policy.name,
                    message=rule.message,
                )
                if decision.verdict == Verdict.DENY:
                    return decision
                if decision.verdict == Verdict.LOG_ONLY and log_only_decision is None:
                    log_only_decision = decision
                elif decision.verdict == Verdict.ALLOW and allow_decision is None:
                    allow_decision = decision

        if log_only_decision is not None:
            return log_only_decision

        if allow_decision is not None:
            return allow_decision

        # No rule matched — use policy default
        return Decision(
            verdict=policy.default_verdict,
            policy_name=policy.name,
            message=f"No rule matched in '{policy.name}' — default verdict applied.",
        )

    def _handle_eval_error(self, policy: Policy, exc: Exception) -> Decision:
        """Apply the policy's fail_mode when evaluation throws."""
        logger.error("Policy '%s' evaluation error: %s", policy.name, exc, exc_info=True)

        if policy.fail_mode == FailMode.CLOSED:
            return Decision(
                verdict=Verdict.DENY,
                policy_name=policy.name,
                message="Evaluation error — fail-closed.",
            )
        if policy.fail_mode == FailMode.LOG:
            return Decision(
                verdict=Verdict.LOG_ONLY,
                policy_name=policy.name,
                message="Evaluation error — logging only.",
            )
        # FailMode.OPEN
        return Decision(
            verdict=Verdict.ALLOW,
            policy_name=policy.name,
            message="Evaluation error — fail-open.",
        )
