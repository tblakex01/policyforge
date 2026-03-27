"""Tests for the YAML policy loader."""

import textwrap

import pytest

from policyforge.loader import PolicyLoader, PolicyValidationError
from policyforge.models import FailMode, Verdict


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
