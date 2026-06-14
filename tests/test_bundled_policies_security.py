"""Security assertions for bundled policy templates."""

from pathlib import Path

import policyforge
from policyforge.engine import PolicyEngine
from policyforge.models import Verdict


def _bundled_policy_path(filename: str) -> Path:
    return Path(policyforge.__file__).parent / "policies" / filename


class TestBundledDefaultPolicy:
    def test_denies_unknown_tools(self):
        engine = PolicyEngine(policy_paths=[_bundled_policy_path("default.yaml")])

        decision = engine.evaluate("unknown_tool", {})

        assert decision.verdict == Verdict.DENY

    def test_allows_explicit_demo_tools(self):
        engine = PolicyEngine(policy_paths=[_bundled_policy_path("default.yaml")])

        web_decision = engine.evaluate("web_search", {"query": "test"})
        read_decision = engine.evaluate("read_file", {"path": "/tmp/sandbox/data.txt"})

        assert web_decision.verdict == Verdict.ALLOW
        assert read_decision.verdict == Verdict.ALLOW
