"""Tests for the YAML policy loader."""

import textwrap
from pathlib import Path

import pytest

from policyforge.loader import PolicyLoader, PolicyValidationError, load_trust_config
from policyforge.models import FailMode, Verdict
from policyforge.trust.models import TrustMode, TrustVerdict


@pytest.fixture
def tmp_policy_dir(tmp_path):
    """Create a temp dir with a sample policy file."""
    policy_file = tmp_path / "test_policy.yaml"
    policy_file.write_text(
        textwrap.dedent(
            """\
        name: test-policy
        description: Test policy for unit tests
        version: "2.0.0"
        fail_mode: closed
        default_verdict: ALLOW
        rules:
          - name: block-shell
            priority: 10
            verdict: DENY
            message: "No shell"
            conditions:
              - field: tool_name
                operator: eq
                value: run_shell
          - name: log-queries
            priority: 50
            verdict: LOG_ONLY
            match_strategy: any
            conditions:
              - field: tool_name
                operator: eq
                value: query_db
    """
        )
    )
    return tmp_path


@pytest.fixture
def loader():
    return PolicyLoader()


class TestLoadFile:
    def test_loads_single_policy(self, loader, tmp_policy_dir):
        policies = loader.load_file(tmp_policy_dir / "test_policy.yaml")
        assert len(policies) == 1
        p = policies[0]
        assert p.name == "test-policy"
        assert p.version == "2.0.0"
        assert p.fail_mode == FailMode.CLOSED
        assert p.default_verdict == Verdict.ALLOW

    def test_rules_sorted_by_priority(self, loader, tmp_policy_dir):
        policies = loader.load_file(tmp_policy_dir / "test_policy.yaml")
        rules = policies[0].rules
        assert rules[0].name == "block-shell"
        assert rules[0].priority == 10
        assert rules[1].name == "log-queries"
        assert rules[1].priority == 50

    def test_file_not_found(self, loader):
        with pytest.raises(FileNotFoundError):
            loader.load_file("/nonexistent/policy.yaml")

    def test_wrong_extension(self, loader, tmp_path):
        bad = tmp_path / "policy.json"
        bad.write_text("{}")
        with pytest.raises(PolicyValidationError, match="Expected .yaml"):
            loader.load_file(bad)

    def test_missing_name_key(self, loader, tmp_path):
        bad = tmp_path / "bad.yaml"
        bad.write_text("description: no name field\nrules: []\n")
        with pytest.raises(PolicyValidationError, match="missing required keys"):
            loader.load_file(bad)

    def test_rule_missing_conditions(self, loader, tmp_path):
        bad = tmp_path / "bad.yaml"
        bad.write_text(
            textwrap.dedent(
                """\
            name: bad-policy
            rules:
              - name: bad-rule
        """
            )
        )
        with pytest.raises(PolicyValidationError, match="missing keys"):
            loader.load_file(bad)

    def test_empty_conditions_list(self, loader, tmp_path):
        bad = tmp_path / "bad.yaml"
        bad.write_text(
            textwrap.dedent(
                """\
            name: bad-policy
            rules:
              - name: bad-rule
                conditions: []
        """
            )
        )
        with pytest.raises(PolicyValidationError, match="at least one condition"):
            loader.load_file(bad)

    def test_policies_key_requires_list(self, loader, tmp_path):
        bad = tmp_path / "bad.yaml"
        bad.write_text(
            textwrap.dedent(
                """\
            policies:
              name: invalid
        """
            )
        )
        with pytest.raises(PolicyValidationError, match="policies"):
            loader.load_file(bad)

    def test_enabled_must_be_boolean(self, loader, tmp_path):
        bad = tmp_path / "bad.yaml"
        bad.write_text(
            textwrap.dedent(
                """\
            name: bad-policy
            enabled: "false"
            rules:
              - name: allow-any
                conditions:
                  - field: tool_name
                    operator: eq
                    value: test
        """
            )
        )
        with pytest.raises(PolicyValidationError, match="enabled"):
            loader.load_file(bad)


class TestValidationEdgeCases:
    def test_condition_not_a_mapping(self, loader, tmp_path):
        bad = tmp_path / "bad.yaml"
        bad.write_text(
            textwrap.dedent(
                """\
            name: bad-policy
            rules:
              - name: bad-rule
                conditions:
                  - "not a mapping"
        """
            )
        )
        with pytest.raises(PolicyValidationError, match="must be a mapping"):
            loader.load_file(bad)

    def test_rule_not_a_mapping(self, loader, tmp_path):
        bad = tmp_path / "bad.yaml"
        bad.write_text(
            textwrap.dedent(
                """\
            name: bad-policy
            rules:
              - "not a mapping"
        """
            )
        )
        with pytest.raises(PolicyValidationError, match="must be a mapping"):
            loader.load_file(bad)

    def test_policy_not_a_mapping(self, loader, tmp_path):
        bad = tmp_path / "bad.yaml"
        bad.write_text('"just a string"\n')
        with pytest.raises(PolicyValidationError, match="not a mapping"):
            loader.load_file(bad)

    def test_rules_key_not_a_list(self, loader, tmp_path):
        bad = tmp_path / "bad.yaml"
        bad.write_text(
            textwrap.dedent(
                """\
            name: bad-policy
            rules:
              name: should-be-a-list
        """
            )
        )
        with pytest.raises(PolicyValidationError, match="rules as a list"):
            loader.load_file(bad)

    def test_multi_doc_with_none_document(self, loader, tmp_path):
        """A YAML file with an empty document (None) should be skipped."""
        f = tmp_path / "nulldoc.yaml"
        f.write_text(
            textwrap.dedent(
                """\
            ---
            ---
            name: real-policy
            rules: []
        """
            )
        )
        policies = loader.load_file(f)
        assert len(policies) == 1
        assert policies[0].name == "real-policy"

    def test_top_level_list_of_policies(self, loader, tmp_path):
        """A YAML file with a top-level list of policy dicts."""
        f = tmp_path / "list.yaml"
        f.write_text(
            textwrap.dedent(
                """\
            - name: list-policy-a
              rules: []
            - name: list-policy-b
              rules: []
        """
            )
        )
        policies = loader.load_file(f)
        assert len(policies) == 2
        assert {p.name for p in policies} == {"list-policy-a", "list-policy-b"}


class TestBundledPolicies:
    def test_smoke_load_all_bundled_policies(self, loader):
        """Every YAML file shipped in policyforge/policies/ must parse cleanly."""
        import policyforge

        policies_dir = Path(policyforge.__file__).parent / "policies"
        assert policies_dir.is_dir(), f"Bundled policies directory not found: {policies_dir}"

        yamls = list(policies_dir.glob("*.yaml")) + list(policies_dir.glob("*.yml"))
        assert len(yamls) > 0, "No bundled policy files found"

        for yaml_file in yamls:
            policies = loader.load_file(yaml_file)
            assert len(policies) > 0, f"No policies parsed from {yaml_file.name}"
            for p in policies:
                assert p.name, f"Policy in {yaml_file.name} has empty name"


class TestLoadDirectory:
    def test_loads_all_yaml_files(self, loader, tmp_policy_dir):
        # Add a second policy
        (tmp_policy_dir / "second.yml").write_text(
            textwrap.dedent(
                """\
            name: second-policy
            rules:
              - name: r1
                conditions:
                  - field: tool_name
                    operator: eq
                    value: x
        """
            )
        )
        policies = loader.load_directory(tmp_policy_dir)
        assert len(policies) == 2
        names = {p.name for p in policies}
        assert names == {"test-policy", "second-policy"}

    def test_skips_invalid_files(self, loader, tmp_policy_dir):
        (tmp_policy_dir / "broken.yaml").write_text("not: valid: yaml: [")
        # Should not raise — just skip the broken file
        policies = loader.load_directory(tmp_policy_dir)
        assert len(policies) >= 1

    def test_not_a_directory(self, loader):
        with pytest.raises(NotADirectoryError):
            loader.load_directory("/nonexistent/dir")


class TestMultiDocumentYaml:
    def test_multi_document(self, loader, tmp_path):
        multi = tmp_path / "multi.yaml"
        multi.write_text(
            textwrap.dedent(
                """\
            name: policy-a
            rules:
              - name: r1
                conditions:
                  - field: tool_name
                    operator: eq
                    value: a
            ---
            name: policy-b
            rules:
              - name: r2
                conditions:
                  - field: tool_name
                    operator: eq
                    value: b
        """
            )
        )
        policies = loader.load_file(multi)
        assert len(policies) == 2
        assert policies[0].name == "policy-a"
        assert policies[1].name == "policy-b"


# --- Tool trust block ---


class TestLoadTrustConfig:
    def test_none_returns_disabled_default(self):
        cfg = load_trust_config(None)
        assert cfg.mode == TrustMode.DISABLED

    def test_parses_full_block(self, tmp_path: Path):
        raw = {
            "mode": "enforce",
            "ledger_path": str(tmp_path / "approvals.jsonl"),
            "on_mismatch": "DENY",
            "on_unknown": "LOG_ONLY",
            "auto_approve": True,
            "detect_shadowing": {"nfkc": True, "confusables": False},
        }
        cfg = load_trust_config(raw)
        assert cfg.mode == TrustMode.ENFORCE
        assert cfg.ledger_path == tmp_path / "approvals.jsonl"
        assert cfg.on_mismatch == TrustVerdict.DENY
        assert cfg.on_unknown == TrustVerdict.LOG_ONLY
        assert cfg.auto_approve is True
        assert cfg.detect_nfkc is True
        assert cfg.detect_confusables is False

    def test_unknown_mode_rejected(self):
        with pytest.raises(PolicyValidationError, match="mode"):
            load_trust_config({"mode": "bogus"})

    def test_unknown_top_level_key_rejected(self):
        with pytest.raises(PolicyValidationError, match="unknown"):
            load_trust_config({"mode": "enforce", "mystery_key": 1})


class TestLoaderYamlWithTrustBlock:
    def test_load_file_surfaces_trust_config(self, tmp_path: Path):
        policy_yaml = tmp_path / "p.yaml"
        policy_yaml.write_text(
            """
tool_trust:
  mode: enforce
  ledger_path: approvals.jsonl
  on_mismatch: DENY
policies:
  - name: demo
    rules:
      - name: allow_all
        conditions:
          - field: tool_name
            operator: eq
            value: anything
        verdict: ALLOW
""",
            encoding="utf-8",
        )
        loader = PolicyLoader()
        policies = loader.load_file(policy_yaml)
        assert len(policies) == 1
        assert loader.trust_config is not None
        assert loader.trust_config.mode == TrustMode.ENFORCE
