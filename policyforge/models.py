"""Core data models for the policy gating engine."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, ClassVar


class Verdict(str, Enum):
    """Outcome of a policy evaluation."""

    ALLOW = "ALLOW"
    DENY = "DENY"
    LOG_ONLY = "LOG_ONLY"


class FailMode(str, Enum):
    """Behavior when policy evaluation itself fails (e.g., rule error)."""

    CLOSED = "closed"  # deny on failure — secure default
    OPEN = "open"  # allow on failure — use only during rollout
    LOG = "log"  # allow but emit audit warning


class MatchStrategy(str, Enum):
    """How a rule's conditions are combined."""

    ALL = "all"  # every condition must match (AND)
    ANY = "any"  # at least one condition must match (OR)


@dataclass(frozen=True)
class Condition:
    """Single predicate within a rule.

    Attributes:
        field: Dot-path into the tool-call context (e.g., "tool_name", "args.url").
        operator: One of eq, neq, in, not_in, contains, regex, gt, lt, gte, lte.
        value: The reference value to compare against.
    """

    field: str
    operator: str
    value: Any

    _VALID_OPS: ClassVar[frozenset[str]] = frozenset(
        {"eq", "neq", "in", "not_in", "contains", "regex", "gt", "lt", "gte", "lte"}
    )

    def __post_init__(self) -> None:
        if self.operator not in self._VALID_OPS:
            raise ValueError(
                f"Invalid operator '{self.operator}'. Must be one of: {sorted(self._VALID_OPS)}"
            )
        if self.operator == "regex":
            try:
                compiled = re.compile(str(self.value))
            except re.error as exc:
                raise ValueError(f"Invalid regex pattern '{self.value}': {exc}") from exc
            object.__setattr__(self, "_compiled_re", compiled)

    def match_regex(self, actual: str) -> bool:
        """Test whether actual matches this condition's compiled regex pattern."""
        compiled = getattr(self, "_compiled_re", None)
        if compiled is not None:
            return bool(compiled.search(actual))
        return bool(re.search(str(self.value), actual))


@dataclass(frozen=True)
class PolicyRule:
    """A single evaluation rule inside a policy.

    Attributes:
        name: Human-readable rule identifier.
        conditions: Predicates to evaluate against the tool-call context.
        verdict: What to do when this rule matches.
        match_strategy: How to combine conditions (ALL=AND, ANY=OR).
        priority: Lower value = evaluated first. Ties broken by insertion order.
        message: Optional explanation surfaced to callers on DENY.
    """

    name: str
    conditions: tuple[Condition, ...]
    verdict: Verdict = Verdict.DENY
    match_strategy: MatchStrategy = MatchStrategy.ALL
    priority: int = 100
    message: str = ""


@dataclass(frozen=True)
class Policy:
    """Named collection of rules with a default verdict and fail mode.

    Attributes:
        name: Unique policy identifier.
        description: Human-readable summary.
        rules: Ordered sequence of rules, evaluated by priority then position.
        default_verdict: Verdict when no rule matches.
        fail_mode: Behavior when evaluation encounters an error.
        version: Semver string for tracking policy changes.
        enabled: Master switch — disabled policies are skipped entirely.
    """

    name: str
    description: str = ""
    rules: tuple[PolicyRule, ...] = ()
    default_verdict: Verdict = Verdict.DENY  # fail-closed
    fail_mode: FailMode = FailMode.CLOSED
    version: str = "1.0.0"
    enabled: bool = True


@dataclass(frozen=True)
class Decision:
    """Result of evaluating a tool call against loaded policies.

    Attributes:
        verdict: Final outcome.
        matched_rule: Name of the rule that produced the verdict, or None.
        policy_name: Name of the policy that produced the verdict, or None.
        message: Explanation (especially useful on DENY).
        evaluation_ms: Time spent evaluating in milliseconds.
        request_id: Unique ID for correlating audit entries.
    """

    verdict: Verdict
    matched_rule: str | None = None
    policy_name: str | None = None
    message: str = ""
    evaluation_ms: float = 0.0
    request_id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    tool_name: str = ""
    agent_id: str = ""
    args_hash: str = ""

    @staticmethod
    def _escape_markdown_inline(value: str) -> str:
        """Sanitize a value for embedding inside an inline code span.

        Backticks cannot be neutralized with backslash escapes inside a
        code span (CommonMark: backslash escapes don't apply there), so
        any embedded ``\u0060`` would close the span and let following
        characters render as markup. Replace them with ``'`` instead.
        """
        return " ".join(value.splitlines()).replace("\\", "\\\\").replace("`", "'")

    @staticmethod
    def _escape_markdown_text(value: str) -> str:
        """Escape Markdown control characters for freeform text fields."""
        return value.replace("\\", "\\\\").replace("`", "\\`")

    def to_share_markdown(self) -> str:
        """Render a sanitized Markdown receipt suitable for tickets or chat."""
        policy_name = self.policy_name or "unknown"
        matched_rule = self.matched_rule or "default"
        tool_name = self.tool_name or "unknown_tool"
        agent_id = self.agent_id or "unknown"
        message = self.message or "No policy message provided."

        return "\n".join(
            [
                "# PolicyForge Policy Receipt",
                "",
                f"- Verdict: `{self._escape_markdown_inline(self.verdict.value)}`",
                f"- Tool: `{self._escape_markdown_inline(tool_name)}`",
                f"- Policy: `{self._escape_markdown_inline(policy_name)}`",
                f"- Rule: `{self._escape_markdown_inline(matched_rule)}`",
                f"- Agent: `{self._escape_markdown_inline(agent_id)}`",
                f"- Request ID: `{self._escape_markdown_inline(self.request_id)}`",
                f"- Args Hash: `{self._escape_markdown_inline(self.args_hash)}`",
                f"- Evaluation: `{self.evaluation_ms:.3f} ms`",
                "",
                "## Reason",
                "",
                self._escape_markdown_text(message),
            ]
        )


@dataclass
class AuditEntry:
    """Immutable record of a policy evaluation for the audit trail.

    The integrity_hash is computed over all other fields so tampering
    with the log file is detectable.
    """

    timestamp: float = field(default_factory=time.time)
    request_id: str = ""
    tool_name: str = ""
    agent_id: str = ""
    args_hash: str = ""  # SHA-256 of serialized args (not the args themselves)
    verdict: str = ""
    matched_rule: str = ""
    policy_name: str = ""
    message: str = ""
    evaluation_ms: float = 0.0
    entry_type: str = "decision"
    event_type: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    integrity_hash: str = ""
    chain_prev: str = ""

    def _payload(self, include_event_fields: bool) -> str:
        """Build the canonical payload used for HMAC signing."""
        base = (
            f"{self.timestamp}|{self.request_id}|{self.tool_name}|"
            f"{self.agent_id}|{self.args_hash}|{self.verdict}|"
            f"{self.matched_rule}|{self.policy_name}|{self.message}|"
            f"{self.evaluation_ms}"
        )
        if not include_event_fields:
            return f"{base}|{self.chain_prev}"

        metadata = json.dumps(self.metadata, sort_keys=True, separators=(",", ":"), default=str)
        return f"{base}|{self.entry_type}|{self.event_type}|" f"{metadata}|{self.chain_prev}"

    def compute_integrity(
        self, hmac_key: bytes, *, include_event_fields: bool | None = None
    ) -> str:
        """Return HMAC-SHA256 over the audit payload for tamper detection."""
        import hmac as _hmac

        use_event_fields = (
            self.entry_type == "event" if include_event_fields is None else include_event_fields
        )
        payload = self._payload(include_event_fields=use_event_fields)
        return _hmac.new(hmac_key, payload.encode("utf-8"), hashlib.sha256).hexdigest()

    def seal(self, hmac_key: bytes) -> None:
        """Compute and set the integrity hash."""
        self.integrity_hash = self.compute_integrity(hmac_key)

    def verify(self, hmac_key: bytes, *, include_event_fields: bool | None = None) -> bool:
        """Return True if the stored hash matches a fresh computation."""
        return hmac.compare_digest(
            self.integrity_hash,
            self.compute_integrity(hmac_key, include_event_fields=include_event_fields),
        )
