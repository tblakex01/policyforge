"""Tests for the TrustManager orchestrator."""

from pathlib import Path

import pytest

from policyforge.trust.ledger import LedgerWriter
from policyforge.trust.manager import TrustManager
from policyforge.trust.models import (
    ToolFingerprint,
    TrustConfig,
    TrustMode,
    TrustVerdict,
)


@pytest.fixture
def ledger_path(tmp_path: Path) -> Path:
    return tmp_path / "approvals.jsonl"


def _pin(ledger_path: Path, name: str = "create_issue") -> ToolFingerprint:
    fp = ToolFingerprint(
        server_id="mcp://github",
        name=name,
        schema_hash="a" * 64,
        description_hash="b" * 64,
        first_seen=1700000000.0,
        approved_by="operator",
    )
    LedgerWriter(path=ledger_path, hmac_key="k").append(fp)
    return fp


class TestTrustManagerDisabled:
    def test_disabled_mode_always_allows(self, ledger_path):
        cfg = TrustConfig(mode=TrustMode.DISABLED, ledger_path=ledger_path)
        tm = TrustManager(cfg, hmac_key="k")
        result = tm.check(
            tool_name="anything",
            tool_meta={
                "server_id": "mcp://x",
                "schema_hash": "9" * 64,
                "description_hash": "7" * 64,
            },
        )
        assert result.verdict == TrustVerdict.ALLOW


class TestTrustManagerEnforce:
    def test_unknown_tool_denied(self, ledger_path):
        ledger_path.touch()
        cfg = TrustConfig(mode=TrustMode.ENFORCE, ledger_path=ledger_path)
        tm = TrustManager(cfg, hmac_key="k")
        result = tm.check(
            tool_name="unseen",
            tool_meta={
                "server_id": "mcp://x",
                "schema_hash": "5" * 64,
                "description_hash": "d" * 64,
            },
        )
        assert result.verdict == TrustVerdict.DENY
        assert result.reason == "tool_unknown"

    def test_exact_match_allowed(self, ledger_path):
        pinned = _pin(ledger_path)
        cfg = TrustConfig(mode=TrustMode.ENFORCE, ledger_path=ledger_path)
        tm = TrustManager(cfg, hmac_key="k")
        result = tm.check(
            tool_name=pinned.name,
            tool_meta={
                "server_id": pinned.server_id,
                "schema_hash": pinned.schema_hash,
                "description_hash": pinned.description_hash,
            },
        )
        assert result.verdict == TrustVerdict.ALLOW

    def test_schema_drift_denied(self, ledger_path):
        pinned = _pin(ledger_path)
        cfg = TrustConfig(mode=TrustMode.ENFORCE, ledger_path=ledger_path)
        tm = TrustManager(cfg, hmac_key="k")
        result = tm.check(
            tool_name=pinned.name,
            tool_meta={
                "server_id": pinned.server_id,
                "schema_hash": "f" * 64,  # drift
                "description_hash": pinned.description_hash,
            },
        )
        assert result.verdict == TrustVerdict.DENY
        assert result.reason == "fingerprint_drift"

    def test_description_drift_denied(self, ledger_path):
        pinned = _pin(ledger_path)
        cfg = TrustConfig(mode=TrustMode.ENFORCE, ledger_path=ledger_path)
        tm = TrustManager(cfg, hmac_key="k")
        result = tm.check(
            tool_name=pinned.name,
            tool_meta={
                "server_id": pinned.server_id,
                "schema_hash": pinned.schema_hash,
                "description_hash": "f" * 64,
            },
        )
        assert result.verdict == TrustVerdict.DENY
        assert result.reason == "fingerprint_drift"

    def test_shadow_detection_denied(self, ledger_path):
        _pin(ledger_path, name="send_email")
        cfg = TrustConfig(mode=TrustMode.ENFORCE, ledger_path=ledger_path)
        tm = TrustManager(cfg, hmac_key="k")
        # Cyrillic 's' shadowing Latin 's'
        result = tm.check(
            tool_name="\u0455end_email",
            tool_meta={
                "server_id": "mcp://github",
                "schema_hash": "a" * 64,
                "description_hash": "b" * 64,
            },
        )
        assert result.verdict == TrustVerdict.DENY
        assert result.reason == "tool_shadow_detected"

    def test_auto_approve_records_and_allows(self, ledger_path):
        cfg = TrustConfig(
            mode=TrustMode.ENFORCE,
            ledger_path=ledger_path,
            auto_approve=True,
        )
        tm = TrustManager(cfg, hmac_key="k", approved_by="test-op", now=lambda: 42.0)
        result = tm.check(
            tool_name="new_tool",
            tool_meta={
                "server_id": "mcp://x",
                "schema_hash": "5" * 64,
                "description_hash": "d" * 64,
            },
        )
        assert result.verdict == TrustVerdict.ALLOW
        # Second call with same fingerprint is still allowed
        result2 = tm.check(
            tool_name="new_tool",
            tool_meta={
                "server_id": "mcp://x",
                "schema_hash": "5" * 64,
                "description_hash": "d" * 64,
            },
        )
        assert result2.verdict == TrustVerdict.ALLOW


class TestTrustManagerWarn:
    def test_warn_mode_returns_log_only_on_drift(self, ledger_path):
        pinned = _pin(ledger_path)
        cfg = TrustConfig(
            mode=TrustMode.WARN,
            ledger_path=ledger_path,
            on_mismatch=TrustVerdict.LOG_ONLY,
        )
        tm = TrustManager(cfg, hmac_key="k")
        result = tm.check(
            tool_name=pinned.name,
            tool_meta={
                "server_id": pinned.server_id,
                "schema_hash": "f" * 64,
                "description_hash": pinned.description_hash,
            },
        )
        assert result.verdict == TrustVerdict.LOG_ONLY

    def test_warn_mode_with_default_on_mismatch_still_denies(self, ledger_path):
        """mode=WARN with default on_mismatch=DENY keeps DENY semantics.

        The class docstring / YAML comment should make this clear; this
        test pins current behavior so any change is deliberate.
        """
        pinned = _pin(ledger_path)
        cfg = TrustConfig(mode=TrustMode.WARN, ledger_path=ledger_path)
        tm = TrustManager(cfg, hmac_key="k")
        result = tm.check(
            tool_name=pinned.name,
            tool_meta={
                "server_id": pinned.server_id,
                "schema_hash": "f" * 64,
                "description_hash": pinned.description_hash,
            },
        )
        assert result.verdict == TrustVerdict.DENY


class TestTrustManagerMissingMeta:
    def test_missing_tool_meta_denies_in_enforce(self, ledger_path):
        ledger_path.touch()
        cfg = TrustConfig(mode=TrustMode.ENFORCE, ledger_path=ledger_path)
        tm = TrustManager(cfg, hmac_key="k")
        result = tm.check(tool_name="x", tool_meta=None)
        assert result.verdict == TrustVerdict.DENY
        assert result.reason == "tool_meta_missing"


class TestTrustManagerShadowFlags:
    def test_both_flags_false_disables_shadow_check(self, ledger_path):
        _pin(ledger_path, name="send_email")
        cfg = TrustConfig(
            mode=TrustMode.ENFORCE,
            ledger_path=ledger_path,
            detect_nfkc=False,
            detect_confusables=False,
        )
        tm = TrustManager(cfg, hmac_key="k")
        # Cyrillic 's' would normally shadow — with both flags off, the check is skipped
        # and the incoming name is treated as unknown instead (tool_unknown, not shadow).
        result = tm.check(
            tool_name="\u0455end_email",
            tool_meta={
                "server_id": "mcp://github",
                "schema_hash": "a" * 64,
                "description_hash": "b" * 64,
            },
        )
        assert result.reason != "tool_shadow_detected"

    def test_cross_server_same_nfkc_name_does_not_shadow(self, ledger_path):
        _pin(ledger_path, name="list_files")  # server_id="mcp://github"
        cfg = TrustConfig(mode=TrustMode.ENFORCE, ledger_path=ledger_path)
        tm = TrustManager(cfg, hmac_key="k")
        # Different server, identical NFKC name — must NOT shadow.
        # The tool is simply unknown to the other server.
        result = tm.check(
            tool_name="list_files",
            tool_meta={
                "server_id": "mcp://gitlab",
                "schema_hash": "1" * 64,
                "description_hash": "2" * 64,
            },
        )
        assert result.reason != "tool_shadow_detected"
