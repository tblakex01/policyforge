#!/usr/bin/env python3
"""Basic usage examples for the policyforge engine.

Run with:  python -m examples.basic_usage
"""

import os
import tempfile
from pathlib import Path

from policyforge import PolicyEngine, AuditLogger, Verdict
from policyforge.decorators import policy_gate, PolicyGateWrapper, PolicyDeniedError

# ─── 1. Set up audit logger ──────────────────────────────────────────────────
# In production, use a proper secret from your vault / env config.
os.environ["POLICYFORGE_HMAC_KEY"] = "change-me-in-production"

audit = AuditLogger(log_dir=tempfile.mkdtemp(prefix="audit_"), chain_hashes=True)

# ─── 2. Create engine and load policies ──────────────────────────────────────
policy_dir = Path(__file__).resolve().parent.parent / "policyforge" / "policies"

engine = PolicyEngine(
    policy_paths=[policy_dir],
    audit_logger=audit,
    agent_id="example-agent-01",
)

print(f"Loaded {len(engine.policies)} policies:")
for p in engine.policies:
    print(f"  • {p.name} v{p.version} ({len(p.rules)} rules)")


# ─── 3. Decorator approach — gate individual functions ───────────────────────
@policy_gate(engine, tool_name="web_search")
def web_search(query: str, max_results: int = 10) -> list[str]:
    """Simulated web search tool."""
    return [f"Result for '{query}'"]


@policy_gate(engine, tool_name="run_shell")
def run_shell(command: str) -> str:
    """This should always be denied by the default policy."""
    return "executed"


# ─── 4. Wrapper approach — for framework tool dicts ──────────────────────────
def read_file(path: str) -> str:
    return f"Contents of {path}"


def write_file(path: str, content: str) -> None:
    print(f"Writing to {path}")


wrapper = PolicyGateWrapper(engine)
safe_tools = wrapper.wrap_dict(
    {
        "read_file": read_file,
        "write_file": write_file,
    }
)


# ─── 5. Try it out ──────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("\n--- Decorator examples ---")

    # Allowed call
    result = web_search(query="hospitality AI trends", max_results=5)
    print(f"web_search: {result}")

    # Denied call — shell execution blocked
    try:
        run_shell(command="ls -la")
    except PolicyDeniedError as exc:
        print(f"run_shell DENIED: {exc.decision.message}")
        print("\nShareable receipt:")
        print(engine.render_share_receipt(exc.decision))

    print("\n--- Wrapper examples ---")

    # Allowed — read_file isn't in any deny list
    result = safe_tools["read_file"](path="/tmp/sandbox/data.txt")
    print(f"read_file: {result}")

    # Denied — write outside sandbox
    try:
        safe_tools["write_file"](path="/etc/passwd", content="nope")
    except PolicyDeniedError as exc:
        print(f"write_file DENIED: {exc.decision.message}")

    print("\n--- Direct engine.evaluate() ---")

    # Direct evaluation for when you want the Decision without raising
    decision = engine.evaluate(
        tool_name="query_db",
        args={"sql": "SELECT * FROM guests LIMIT 10"},
    )
    print(f"query_db → {decision.verdict.value} (rule: {decision.matched_rule})")

    decision = engine.evaluate(
        tool_name="delete_records",
        args={"table": "reservations", "count": 500},
    )
    print(f"delete_records(500) → {decision.verdict.value}: {decision.message}")
    print("\nShareable receipt:")
    print(engine.render_share_receipt(decision))

    # ─── 6. Verify audit log integrity ───────────────────────────────────────
    print("\n--- Audit verification ---")
    valid, tampered = audit.verify_log()
    print(f"Audit log: {valid} valid entries, {tampered} tampered entries")
