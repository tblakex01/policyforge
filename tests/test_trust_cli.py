"""Tests for the approvals CLI entry point."""

from __future__ import annotations

import json
from pathlib import Path

from policyforge.trust import cli as trust_cli
from policyforge.trust.ledger import LedgerReader


class TestSingleApprove:
    def test_approves_one_fingerprint(self, tmp_path: Path, monkeypatch):
        monkeypatch.setenv("POLICYFORGE_HMAC_KEY", "k")
        ledger = tmp_path / "approvals.jsonl"

        exit_code = trust_cli.main(
            [
                "--ledger",
                str(ledger),
                "--server-id",
                "mcp://github",
                "--name",
                "create_issue",
                "--schema-hash",
                "a" * 64,
                "--description-hash",
                "b" * 64,
                "--approved-by",
                "test-op",
            ]
        )

        assert exit_code == 0
        loaded = LedgerReader(path=ledger, hmac_key="k").load()
        key = ("mcp://github", "create_issue")
        assert key in loaded
        assert loaded[key].schema_hash == "a" * 64
        assert loaded[key].approved_by == "test-op"

    def test_rejects_invalid_hash(self, tmp_path: Path, monkeypatch):
        monkeypatch.setenv("POLICYFORGE_HMAC_KEY", "k")
        ledger = tmp_path / "approvals.jsonl"

        exit_code = trust_cli.main(
            [
                "--ledger",
                str(ledger),
                "--server-id",
                "mcp://x",
                "--name",
                "t",
                "--schema-hash",
                "not-hex",
                "--description-hash",
                "b" * 64,
            ]
        )

        assert exit_code != 0
        assert not ledger.exists() or ledger.read_text(encoding="utf-8") == ""


class TestBulkApprove:
    def test_bulk_approves_from_json_file(self, tmp_path: Path, monkeypatch):
        monkeypatch.setenv("POLICYFORGE_HMAC_KEY", "k")
        ledger = tmp_path / "approvals.jsonl"
        seed = tmp_path / "seed.json"
        seed.write_text(
            json.dumps(
                [
                    {
                        "server_id": "mcp://a",
                        "name": "t1",
                        "schema_hash": "a" * 64,
                        "description_hash": "b" * 64,
                    },
                    {
                        "server_id": "mcp://b",
                        "name": "t2",
                        "schema_hash": "c" * 64,
                        "description_hash": "d" * 64,
                    },
                ]
            ),
            encoding="utf-8",
        )

        exit_code = trust_cli.main(["--ledger", str(ledger), "--from-json", str(seed)])

        assert exit_code == 0
        loaded = LedgerReader(path=ledger, hmac_key="k").load()
        assert len(loaded) == 2


class TestRequiresHmacKey:
    def test_missing_env_key_fails(self, tmp_path: Path, monkeypatch):
        monkeypatch.delenv("POLICYFORGE_HMAC_KEY", raising=False)
        ledger = tmp_path / "approvals.jsonl"

        exit_code = trust_cli.main(
            [
                "--ledger",
                str(ledger),
                "--server-id",
                "mcp://x",
                "--name",
                "t",
                "--schema-hash",
                "a" * 64,
                "--description-hash",
                "b" * 64,
            ]
        )

        assert exit_code != 0
