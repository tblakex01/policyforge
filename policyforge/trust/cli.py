"""Operator CLI for seeding the tool approvals ledger."""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from policyforge.trust.ledger import LedgerWriter
from policyforge.trust.models import ToolFingerprint


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="policyforge-approve")
    parser.add_argument("--ledger", required=True, help="Path to approvals.jsonl")
    parser.add_argument("--from-json", help="JSON file with an array of fingerprints")
    parser.add_argument("--server-id")
    parser.add_argument("--name")
    parser.add_argument("--schema-hash")
    parser.add_argument("--description-hash")
    parser.add_argument("--approved-by", default="cli")
    return parser


def _fingerprint_from_fields(fields: dict[str, Any], approved_by: str) -> ToolFingerprint:
    required = ("server_id", "name", "schema_hash", "description_hash")
    missing = [field for field in required if not fields.get(field)]
    if missing:
        raise ValueError(f"missing fields: {missing}")

    return ToolFingerprint(
        server_id=str(fields["server_id"]),
        name=str(fields["name"]),
        schema_hash=str(fields["schema_hash"]),
        description_hash=str(fields["description_hash"]),
        first_seen=time.time(),
        approved_by=approved_by,
    )


def _load_fingerprints(args: argparse.Namespace) -> list[ToolFingerprint]:
    if args.from_json:
        payload = json.loads(Path(args.from_json).read_text(encoding="utf-8"))
        if not isinstance(payload, list):
            raise ValueError("--from-json must contain a JSON array")
        return [_fingerprint_from_fields(entry, args.approved_by) for entry in payload]

    fields = {
        "server_id": args.server_id,
        "name": args.name,
        "schema_hash": args.schema_hash,
        "description_hash": args.description_hash,
    }
    return [_fingerprint_from_fields(fields, args.approved_by)]


def main(argv: Sequence[str] | None = None) -> int:
    """Run the approvals CLI and return a process-style exit code."""
    args = _build_parser().parse_args(argv)
    ledger_path = Path(args.ledger)

    try:
        fingerprints = _load_fingerprints(args)
        writer = LedgerWriter(path=ledger_path)
        for fingerprint in fingerprints:
            writer.append(fingerprint)
    except (OSError, RuntimeError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if len(fingerprints) == 1:
        fingerprint = fingerprints[0]
        print(f"Approved {fingerprint.server_id}:{fingerprint.name} into {ledger_path}")
    else:
        print(f"Approved {len(fingerprints)} tools into {ledger_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
