"""YAML-based policy loader with schema validation."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

from policyforge.models import (
    Condition,
    FailMode,
    MatchStrategy,
    Policy,
    PolicyRule,
    Verdict,
)
from policyforge.trust.models import TrustConfig, TrustMode, TrustVerdict

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------- #
# Schema expectations (lightweight — no jsonschema dependency)
# --------------------------------------------------------------------------- #

_REQUIRED_POLICY_KEYS = {"name"}
_REQUIRED_RULE_KEYS = {"name", "conditions"}
_REQUIRED_CONDITION_KEYS = {"field", "operator", "value"}


class PolicyValidationError(Exception):
    """Raised when a YAML policy file fails schema validation."""


def _validate_condition(raw: dict[str, Any], rule_name: str) -> None:
    if not isinstance(raw, dict):
        raise PolicyValidationError(f"Condition in rule '{rule_name}' must be a mapping.")
    missing = _REQUIRED_CONDITION_KEYS - raw.keys()
    if missing:
        raise PolicyValidationError(f"Condition in rule '{rule_name}' missing keys: {missing}")


def _validate_rule(raw: dict[str, Any], policy_name: str) -> None:
    if not isinstance(raw, dict):
        raise PolicyValidationError(f"Rule in policy '{policy_name}' must be a mapping.")
    missing = _REQUIRED_RULE_KEYS - raw.keys()
    if missing:
        raise PolicyValidationError(f"Rule in policy '{policy_name}' missing keys: {missing}")
    if not isinstance(raw.get("conditions"), list) or len(raw["conditions"]) == 0:
        raise PolicyValidationError(
            f"Rule '{raw.get('name')}' in policy '{policy_name}' must have "
            "at least one condition."
        )
    for cond in raw["conditions"]:
        _validate_condition(cond, raw["name"])


def _validate_policy(raw: dict[str, Any], filepath: str) -> None:
    if not isinstance(raw, dict):
        raise PolicyValidationError(f"Policy in {filepath} is not a mapping.")
    missing = _REQUIRED_POLICY_KEYS - raw.keys()
    if missing:
        raise PolicyValidationError(f"Policy in {filepath} missing required keys: {missing}")
    if "rules" in raw and not isinstance(raw["rules"], list):
        raise PolicyValidationError(
            f"Policy '{raw['name']}' in {filepath} must declare rules as a list."
        )
    if "enabled" in raw and not isinstance(raw["enabled"], bool):
        raise PolicyValidationError(
            f"Policy '{raw['name']}' in {filepath} has invalid enabled value: expected boolean."
        )
    for rule in raw.get("rules", []):
        _validate_rule(rule, raw["name"])


# --------------------------------------------------------------------------- #
# Trust config (tool_trust: top-level block)
# --------------------------------------------------------------------------- #

_TRUST_ALLOWED_KEYS = {
    "mode",
    "ledger_path",
    "on_mismatch",
    "on_unknown",
    "auto_approve",
    "detect_shadowing",
}
_SHADOW_ALLOWED_KEYS = {"nfkc", "confusables"}


def load_trust_config(raw: dict[str, Any] | None) -> TrustConfig:
    """Parse a ``tool_trust:`` YAML block into a TrustConfig.

    ``raw=None`` returns the default (disabled) config.
    """
    if raw is None:
        return TrustConfig()
    if not isinstance(raw, dict):
        raise PolicyValidationError("tool_trust block must be a mapping.")

    unknown = raw.keys() - _TRUST_ALLOWED_KEYS
    if unknown:
        raise PolicyValidationError(f"tool_trust has unknown keys: {unknown}")

    try:
        mode = TrustMode(str(raw.get("mode", "disabled")).lower())
    except ValueError as exc:
        raise PolicyValidationError(f"tool_trust has invalid mode: {exc}") from exc

    try:
        on_mismatch = TrustVerdict(str(raw.get("on_mismatch", "DENY")).upper())
        on_unknown = TrustVerdict(str(raw.get("on_unknown", "DENY")).upper())
    except ValueError as exc:
        raise PolicyValidationError(f"tool_trust has invalid verdict: {exc}") from exc

    ledger_path_raw = raw.get("ledger_path")
    if ledger_path_raw is None:
        ledger_path = TrustConfig().ledger_path
    else:
        ledger_path = Path(str(ledger_path_raw))

    shadow = raw.get("detect_shadowing") or {}
    if not isinstance(shadow, dict):
        raise PolicyValidationError("detect_shadowing must be a mapping.")
    unknown_shadow = shadow.keys() - _SHADOW_ALLOWED_KEYS
    if unknown_shadow:
        raise PolicyValidationError(f"detect_shadowing has unknown keys: {unknown_shadow}")

    return TrustConfig(
        mode=mode,
        ledger_path=ledger_path,
        on_mismatch=on_mismatch,
        on_unknown=on_unknown,
        auto_approve=bool(raw.get("auto_approve", False)),
        detect_nfkc=bool(shadow.get("nfkc", True)),
        detect_confusables=bool(shadow.get("confusables", True)),
    )


# --------------------------------------------------------------------------- #
# Parsing helpers
# --------------------------------------------------------------------------- #


def _parse_condition(raw: dict[str, Any]) -> Condition:
    return Condition(
        field=str(raw["field"]),
        operator=str(raw["operator"]),
        value=raw["value"],
    )


def _parse_rule(raw: dict[str, Any]) -> PolicyRule:
    conditions = tuple(_parse_condition(c) for c in raw["conditions"])
    verdict_str = raw.get("verdict", "DENY").upper()
    match_str = raw.get("match_strategy", "all").lower()

    return PolicyRule(
        name=raw["name"],
        conditions=conditions,
        verdict=Verdict(verdict_str),
        match_strategy=MatchStrategy(match_str),
        priority=int(raw.get("priority", 100)),
        message=raw.get("message", ""),
    )


def _parse_policy(raw: dict[str, Any]) -> Policy:
    rules = tuple(
        sorted(
            (_parse_rule(r) for r in raw.get("rules", [])),
            key=lambda r: r.priority,
        )
    )
    default_str = raw.get("default_verdict", "DENY").upper()
    fail_str = raw.get("fail_mode", "closed").lower()

    return Policy(
        name=raw["name"],
        description=raw.get("description", ""),
        rules=rules,
        default_verdict=Verdict(default_str),
        fail_mode=FailMode(fail_str),
        version=str(raw.get("version", "1.0.0")),
        enabled=raw.get("enabled", True),
    )


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #


class PolicyLoader:
    """Load and validate policies from YAML files or directories."""

    def __init__(self) -> None:
        # `None` = no tool_trust block was present in any loaded YAML.
        # `TrustConfig(mode=DISABLED)` = explicitly configured but disabled.
        self.trust_config: TrustConfig | None = None

    def load_file(self, path: str | Path) -> list[Policy]:
        """Load one or more policies from a single YAML file.

        A file may contain either a single policy mapping or a list of
        policy mappings (via YAML multi-document ``---`` separators or a
        top-level ``policies`` key).  An optional ``tool_trust:`` top-level
        key is extracted and stored in ``self.trust_config``.
        """
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Policy file not found: {path}")
        if path.suffix not in (".yaml", ".yml"):
            raise PolicyValidationError(f"Expected .yaml/.yml file, got: {path.suffix}")

        text = path.read_text(encoding="utf-8")
        docs: list[dict[str, Any]] = []

        for doc in yaml.safe_load_all(text):
            if doc is None:
                continue
            if isinstance(doc, dict) and "tool_trust" in doc:
                if self.trust_config is not None:
                    logger.warning(
                        "Overwriting tool_trust config from a later document in %s", path
                    )
                self.trust_config = load_trust_config(doc.get("tool_trust"))
                # Peel off tool_trust and see if the remaining dict is a policy.
                remainder = {k: v for k, v in doc.items() if k != "tool_trust"}
                if not remainder:
                    continue
                doc = remainder
            if isinstance(doc, dict) and "policies" in doc:
                if not isinstance(doc["policies"], list):
                    raise PolicyValidationError(
                        f"Top-level 'policies' in {path} must be declared as a list."
                    )
                docs.extend(doc["policies"])
            elif isinstance(doc, list):
                docs.extend(doc)
            else:
                docs.append(doc)

        policies: list[Policy] = []
        for raw in docs:
            _validate_policy(raw, str(path))
            policies.append(_parse_policy(raw))
            logger.info(
                "Loaded policy '%s' v%s from %s",
                policies[-1].name,
                policies[-1].version,
                path,
            )

        return policies

    def load_directory(self, path: str | Path) -> list[Policy]:
        """Recursively load all .yaml/.yml files from a directory.

        Files are loaded in sorted order. If multiple files declare a
        ``tool_trust:`` block, the last file (alphabetical order) wins;
        a ``logger.warning`` is emitted when overwriting.
        """
        path = Path(path)
        if not path.is_dir():
            raise NotADirectoryError(f"Policy directory not found: {path}")

        policies: list[Policy] = []
        for yaml_file in sorted(path.rglob("*.y*ml")):
            if yaml_file.suffix in (".yaml", ".yml"):
                try:
                    policies.extend(self.load_file(yaml_file))
                except (PolicyValidationError, yaml.YAMLError, ValueError) as exc:
                    logger.error("Skipping invalid policy file %s: %s", yaml_file, exc)

        logger.info("Loaded %d policies from %s", len(policies), path)
        return policies
