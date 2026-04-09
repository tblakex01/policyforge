#!/usr/bin/env python3
"""Integration pattern for Microsoft Foundry Agents (Azure AI Foundry).

Shows how to wrap Foundry Agent tool functions with policy gating
so every tool invocation passes through local policy evaluation
before execution.

This is a pattern guide — it won't run without the Foundry SDK
and a deployed agent, but it shows exactly where the gating hooks in.
"""

import os
from pathlib import Path
from policyforge import PolicyEngine, AuditLogger
from policyforge.decorators import PolicyGateWrapper

# ─── Setup ────────────────────────────────────────────────────────────────────

engine = PolicyEngine(
    policy_paths=["./policies"],
    audit_logger=AuditLogger(
        log_dir="./audit_logs",
        hmac_key=os.environ["POLICYFORGE_HMAC_KEY"],
    ),
    agent_id="foundry-agent-prod",
)

gate = PolicyGateWrapper(engine, extra_context={"environment": "production"})


# ─── Define your Foundry Agent tools as normal functions ──────────────────────


def search_reservations(guest_name: str, date_range: str) -> dict:
    """Look up reservations by guest name and date range."""
    # ... your Foundry Agent tool implementation ...
    return {"reservations": []}


def send_guest_email(to: str, subject: str, body: str) -> dict:
    """Send an email to a guest."""
    # ... implementation ...
    return {"status": "sent"}


def adjust_loyalty_points(member_id: str, delta: int, reason: str) -> dict:
    """Add or remove loyalty points."""
    # ... implementation ...
    return {"new_balance": 0}


# ─── Wrap tools with policy gating ───────────────────────────────────────────
# This is the key integration point.  The wrapped functions behave
# identically to the originals, except every call is evaluated
# against your YAML policies before execution.

gated_tools = gate.wrap_dict(
    {
        "search_reservations": search_reservations,
        "send_guest_email": send_guest_email,
        "adjust_loyalty_points": adjust_loyalty_points,
    }
)


# ─── Register with Foundry Agent ─────────────────────────────────────────────
# In your actual Foundry Agent setup, you'd register these gated
# functions instead of the originals:
#
#   from azure.ai.projects import AIProjectClient
#   from azure.ai.projects.models import FunctionTool
#
#   functions = FunctionTool(functions=[
#       gated_tools["search_reservations"],
#       gated_tools["send_guest_email"],
#       gated_tools["adjust_loyalty_points"],
#   ])
#
#   agent = project_client.agents.create_agent(
#       model="gpt-4o",
#       name="concierge-agent",
#       tools=functions.definitions,
#   )
#
# When the agent invokes any tool, the policy engine evaluates
# the call locally (zero network hops) before it executes.
# Denied calls raise PolicyDeniedError, which you can catch in
# your agent's tool-execution loop and return a safe response.


# ─── Cloud sync example ──────────────────────────────────────────────────────
# Pull the latest policies from your multi-cloud storage on startup:
#
#   from policyforge.sync import SyncManager
#   from policyforge.sync.s3 import S3SyncProvider
#   from policyforge.sync.azure_blob import AzureBlobSyncProvider
#   from policyforge.sync.oci_os import OCISyncProvider
#
#   sync = SyncManager(local_dir="./policies")
#   sync.add_provider(S3SyncProvider(bucket="corp-policies", prefix="ai-agents/"))
#   sync.add_provider(AzureBlobSyncProvider(
#       container="policies",
#       account_url="https://corpstore.blob.core.windows.net",
#   ))
#   sync.add_provider(OCISyncProvider(
#       namespace="corp-tenancy",
#       bucket="ai-policies",
#   ))
#
#   results = sync.pull()
#   for r in results:
#       print(f"{r.provider}: {r.downloaded} updated, errors={r.errors}")
#
#   # Reload engine with freshly synced policies
#   engine.reload(["./policies"])
