"""Tests for trust data models."""

import hashlib
import json

import pytest

from policyforge.trust.models import (
    ToolFingerprint,
    TrustConfig,
    TrustMode,
    TrustResult,
    TrustVerdict,
    canonical_schema_hash,
)


class TestToolFingerprint:
    def test_frozen_dataclass(self):
        fp = ToolFingerprint(
            server_id="mcp://github",
            name="create_issue",
            schema_hash="a" * 64,
            description_hash="b" * 64,
            first_seen=1700000000.0,
            approved_by="operator",
        )
        with pytest.raises(AttributeError):
            fp.name = "other"  # type: ignore[misc]

    def test_equality_on_all_fields(self):
        a = ToolFingerprint("s", "n", "x" * 64, "y" * 64, 1.0, "op")
        b = ToolFingerprint("s", "n", "x" * 64, "y" * 64, 1.0, "op")
        assert a == b


class TestCanonicalSchemaHash:
    def test_stable_across_key_order(self):
        schema_a = {"type": "object", "properties": {"a": 1, "b": 2}}
        schema_b = {"properties": {"b": 2, "a": 1}, "type": "object"}
        assert canonical_schema_hash(schema_a) == canonical_schema_hash(schema_b)

    def test_differs_on_value_change(self):
        h1 = canonical_schema_hash({"x": 1})
        h2 = canonical_schema_hash({"x": 2})
        assert h1 != h2

    def test_is_sha256_hex(self):
        h = canonical_schema_hash({"x": 1})
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)

    def test_matches_manual_computation(self):
        payload = json.dumps({"x": 1}, sort_keys=True, separators=(",", ":"))
        expected = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        assert canonical_schema_hash({"x": 1}) == expected

    def test_rejects_non_json_native_value(self):
        import datetime

        with pytest.raises(TypeError):
            canonical_schema_hash({"when": datetime.datetime(2026, 1, 1)})


class TestTrustConfig:
    def test_defaults(self):
        cfg = TrustConfig()
        assert cfg.mode == TrustMode.DISABLED
        assert cfg.on_mismatch == TrustVerdict.DENY
        assert cfg.on_unknown == TrustVerdict.DENY
        assert cfg.auto_approve is False
        assert cfg.detect_nfkc is True
        assert cfg.detect_confusables is True

    def test_ledger_path_default(self):
        cfg = TrustConfig()
        path_str = str(cfg.ledger_path).replace("\\", "/")
        assert path_str.endswith(".policyforge/approvals.jsonl")


class TestTrustResult:
    def test_ok_result(self):
        r = TrustResult.ok()
        assert r.verdict == TrustVerdict.ALLOW
        assert r.reason == ""

    def test_deny_result(self):
        r = TrustResult.deny("fingerprint_drift", "schema hash changed")
        assert r.verdict == TrustVerdict.DENY
        assert r.reason == "fingerprint_drift"
        assert r.message == "schema hash changed"

    def test_log_only_result(self):
        r = TrustResult.log_only("fingerprint_drift", "schema hash changed")
        assert r.verdict == TrustVerdict.LOG_ONLY
        assert r.reason == "fingerprint_drift"
        assert r.message == "schema hash changed"
