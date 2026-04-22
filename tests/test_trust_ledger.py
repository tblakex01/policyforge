"""Tests for the approvals ledger."""

import json
from pathlib import Path

import pytest

from policyforge.trust.ledger import LedgerReader, LedgerWriter
from policyforge.trust.models import ToolFingerprint


@pytest.fixture
def ledger_path(tmp_path: Path) -> Path:
    return tmp_path / "approvals.jsonl"


@pytest.fixture
def writer(ledger_path: Path) -> LedgerWriter:
    return LedgerWriter(path=ledger_path, hmac_key="test-ledger-key")


@pytest.fixture
def fp() -> ToolFingerprint:
    return ToolFingerprint(
        server_id="mcp://github",
        name="create_issue",
        schema_hash="a" * 64,
        description_hash="b" * 64,
        first_seen=1700000000.0,
        approved_by="operator",
    )


class TestLedgerWriter:
    def test_creates_file_on_first_append(self, writer, fp, ledger_path):
        writer.append(fp)
        assert ledger_path.exists()

    def test_first_entry_has_empty_chain_prev(self, writer, fp, ledger_path):
        writer.append(fp)
        line = ledger_path.read_text(encoding="utf-8").strip()
        record = json.loads(line)
        assert record["chain_prev"] == ""

    def test_second_entry_chains_to_first(self, writer, ledger_path):
        fp1 = ToolFingerprint("s", "a", "e" * 64, "f" * 64, 1.0, "op")
        fp2 = ToolFingerprint("s", "b", "e" * 64, "f" * 64, 2.0, "op")
        writer.append(fp1)
        writer.append(fp2)
        lines = ledger_path.read_text(encoding="utf-8").strip().split("\n")
        first = json.loads(lines[0])
        second = json.loads(lines[1])
        assert second["chain_prev"] == first["hmac"]

    def test_entry_has_integrity_hash(self, writer, fp, ledger_path):
        writer.append(fp)
        record = json.loads(ledger_path.read_text(encoding="utf-8").strip())
        assert "hmac" in record
        assert len(record["hmac"]) == 64

    def test_requires_hmac_key(self, ledger_path):
        with pytest.raises(RuntimeError, match="HMAC key"):
            LedgerWriter(path=ledger_path, hmac_key=None)

    def test_reads_hmac_from_env(self, ledger_path, monkeypatch):
        monkeypatch.setenv("POLICYFORGE_HMAC_KEY", "from-env")
        writer = LedgerWriter(path=ledger_path)
        # Should not raise
        writer.append(ToolFingerprint("s", "n", "e" * 64, "f" * 64, 1.0, "op"))

    def test_reopening_continues_chain(self, ledger_path):
        """A second LedgerWriter on an existing file must chain to the last entry."""
        w1 = LedgerWriter(path=ledger_path, hmac_key="k")
        fp1 = ToolFingerprint("s", "a", "e" * 64, "f" * 64, 1.0, "op")
        w1.append(fp1)

        w2 = LedgerWriter(path=ledger_path, hmac_key="k")
        fp2 = ToolFingerprint("s", "b", "e" * 64, "f" * 64, 2.0, "op")
        w2.append(fp2)

        # Second entry's chain_prev should point at the first entry's hmac.
        lines = ledger_path.read_text(encoding="utf-8").strip().split("\n")
        first = json.loads(lines[0])
        second = json.loads(lines[1])
        assert second["chain_prev"] == first["hmac"]

    def test_writer_refuses_to_open_tampered_ledger(self, ledger_path):
        """Tamper in the existing file must fail the writer's init, not be silently accepted."""
        LedgerWriter(path=ledger_path, hmac_key="k").append(
            ToolFingerprint("s", "n", "a" * 64, "b" * 64, 1.0, "op")
        )
        # Corrupt the schema_hash.
        text = ledger_path.read_text(encoding="utf-8")
        ledger_path.write_text(text.replace("a" * 64, "z" * 64), encoding="utf-8")
        with pytest.raises(ValueError, match="tamper"):
            LedgerWriter(path=ledger_path, hmac_key="k")


class TestLedgerReader:
    def test_empty_file_returns_empty_map(self, ledger_path):
        ledger_path.touch()
        reader = LedgerReader(path=ledger_path, hmac_key="test-ledger-key")
        assert reader.load() == {}

    def test_missing_file_returns_empty_map(self, tmp_path):
        reader = LedgerReader(path=tmp_path / "nope.jsonl", hmac_key="k")
        assert reader.load() == {}

    def test_loads_single_entry_keyed_by_server_and_nfkc_name(self, writer, fp, ledger_path):
        writer.append(fp)
        reader = LedgerReader(path=ledger_path, hmac_key="test-ledger-key")
        loaded = reader.load()
        assert (fp.server_id, "create_issue") in loaded
        assert loaded[(fp.server_id, "create_issue")] == fp

    def test_normalizes_key_via_nfkc(self, writer, ledger_path):
        fp = ToolFingerprint("mcp://x", "fil\u00e9", "e" * 64, "f" * 64, 1.0, "op")
        writer.append(fp)
        reader = LedgerReader(path=ledger_path, hmac_key="test-ledger-key")
        loaded = reader.load()
        # Key uses NFKC-normalized name
        assert ("mcp://x", "file\u0301") not in loaded  # raw decomposed form absent
        assert ("mcp://x", "fil\u00e9") in loaded

    def test_later_entry_wins_for_same_key(self, writer, ledger_path):
        fp1 = ToolFingerprint("s", "n", "a" * 64, "b" * 64, 1.0, "op1")
        fp2 = ToolFingerprint("s", "n", "c" * 64, "d" * 64, 2.0, "op2")
        writer.append(fp1)
        writer.append(fp2)
        reader = LedgerReader(path=ledger_path, hmac_key="test-ledger-key")
        loaded = reader.load()
        assert loaded[("s", "n")].schema_hash == "c" * 64

    def test_tampered_entry_raises(self, writer, fp, ledger_path):
        writer.append(fp)
        # Flip one byte in schema_hash
        text = ledger_path.read_text(encoding="utf-8")
        tampered = text.replace("a" * 64, "z" + "a" * 63)
        ledger_path.write_text(tampered, encoding="utf-8")
        reader = LedgerReader(path=ledger_path, hmac_key="test-ledger-key")
        with pytest.raises(ValueError, match="tamper"):
            reader.load()

    def test_broken_chain_raises(self, writer, ledger_path):
        fp1 = ToolFingerprint("s", "a", "e" * 64, "f" * 64, 1.0, "op")
        fp2 = ToolFingerprint("s", "b", "e" * 64, "f" * 64, 2.0, "op")
        writer.append(fp1)
        writer.append(fp2)
        # Corrupt chain_prev on second record
        lines = ledger_path.read_text(encoding="utf-8").strip().split("\n")
        second = json.loads(lines[1])
        second["chain_prev"] = "0" * 64
        lines[1] = json.dumps(second, separators=(",", ":"))
        ledger_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        reader = LedgerReader(path=ledger_path, hmac_key="test-ledger-key")
        with pytest.raises(ValueError, match="chain"):
            reader.load()

    def test_middle_entry_tamper_detected(self, writer, ledger_path):
        """Tampering a non-terminal entry must still fail the reader."""
        for i, name in enumerate(["a", "b", "c"]):
            writer.append(ToolFingerprint("s", name, "e" * 64, "f" * 64, float(i), "op"))
        lines = ledger_path.read_text(encoding="utf-8").strip().split("\n")
        # Corrupt the middle entry's schema_hash (field that's part of the HMAC payload).
        middle = json.loads(lines[1])
        middle["schema_hash"] = "z" * 64
        lines[1] = json.dumps(middle, separators=(",", ":"))
        ledger_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        reader = LedgerReader(path=ledger_path, hmac_key="test-ledger-key")
        with pytest.raises(ValueError):
            reader.load()
