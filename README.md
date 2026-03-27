<p align="center">
  <img src="https://img.shields.io/badge/python-3.10%2B-blue?logo=python&logoColor=white" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="MIT License">
  <img src="https://img.shields.io/badge/tests-53%20passed-brightgreen" alt="Tests">
  <img src="https://img.shields.io/badge/dependencies-1%20(PyYAML)-orange" alt="Dependencies">
</p>

# PolicyForge

**Local policy engine for AI agent tool-call gating with optional multi-cloud sync.**

PolicyForge evaluates every AI agent tool call against YAML-defined policies *locally* — zero network hops, zero cloud dependencies for security decisions. Policies are version-controlled, human-readable, and sync across AWS S3, Azure Blob Storage, and OCI Object Storage.

```
Agent calls tool → PolicyForge evaluates locally → ALLOW / DENY / LOG_ONLY
                                                        ↓
                                              HMAC-signed audit trail
```

---

## Why PolicyForge?

Most agent security tools delegate decisions to a remote API. That means your security posture depends on someone else's uptime, latency, and infrastructure. PolicyForge takes a different approach:

- **All evaluation happens locally** — no network calls in the decision path
- **Fail-closed by default** — if something goes wrong, the tool call is denied
- **Framework-agnostic** — works with MS Foundry Agents, LangChain, OpenAI, or any callable
- **HMAC-signed audit trail** — tamper-evident logs with hash chaining
- **Multi-cloud sync** — distribute policies from S3, Azure Blob, or OCI Object Storage
- **Single dependency** — just PyYAML for the core engine

---

## Quick Start

### Install

```bash
pip install policyforge

# Optional cloud sync providers
pip install policyforge[aws]          # S3
pip install policyforge[azure]        # Azure Blob Storage
pip install policyforge[oci]          # OCI Object Storage
pip install policyforge[all-clouds]   # All three
```

### Define a Policy

```yaml
# policies/security.yaml
name: default-security
fail_mode: closed
default_verdict: ALLOW

rules:
  - name: block-shell-exec
    priority: 10
    verdict: DENY
    message: "Shell execution is blocked by policy."
    match_strategy: any
    conditions:
      - field: tool_name
        operator: in
        value: ["run_shell", "bash", "exec"]

  - name: block-internal-network
    priority: 20
    verdict: DENY
    message: "Requests to internal networks are blocked."
    conditions:
      - field: tool_name
        operator: eq
        value: http_request
      - field: args.url
        operator: regex
        value: "https?://(10\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.)"
```

### Gate Your Tools

```python
from policyforge import PolicyEngine
from policyforge.decorators import policy_gate, PolicyDeniedError

engine = PolicyEngine(policy_paths=["./policies"])

# Decorator approach
@policy_gate(engine, tool_name="web_search")
def web_search(query: str) -> list[str]:
    return search(query)

# Wrapper approach (for framework tool registries)
from policyforge.decorators import PolicyGateWrapper

wrapper = PolicyGateWrapper(engine)
safe_tools = wrapper.wrap_dict({
    "search": search_fn,
    "read_file": read_fn,
    "write_file": write_fn,
})

# Direct evaluation
decision = engine.evaluate("delete_records", args={"count": 500})
if decision.verdict.value == "DENY":
    print(f"Blocked: {decision.message}")
```

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                    Your AI Agent                     │
│  (MS Foundry / LangChain / OpenAI / Custom)         │
└──────────────────────┬──────────────────────────────┘
                       │ tool call
                       ▼
┌─────────────────────────────────────────────────────┐
│                   PolicyForge                        │
│                                                      │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────┐ │
│  │ YAML Loader  │→│ Policy Engine │→│ Audit Logger│ │
│  │ + Validation │  │ (local eval)  │  │ (HMAC+chain)│ │
│  └──────┬──────┘  └──────────────┘  └────────────┘ │
│         │                                            │
│  ┌──────┴──────────────────────────────────────────┐│
│  │          Cloud Sync (optional)                   ││
│  │  ┌─────┐  ┌────────────┐  ┌──────────────────┐ ││
│  │  │ S3  │  │ Azure Blob │  │ OCI Obj. Storage │ ││
│  │  └─────┘  └────────────┘  └──────────────────┘ ││
│  └─────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────┘
```

---

## Policy Reference

### Policy Structure

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `name` | string | *required* | Unique policy identifier |
| `description` | string | `""` | Human-readable summary |
| `rules` | list | `[]` | Ordered evaluation rules |
| `default_verdict` | `ALLOW` \| `DENY` \| `LOG_ONLY` | `DENY` | Verdict when no rule matches |
| `fail_mode` | `closed` \| `open` \| `log` | `closed` | Behavior on evaluation error |
| `version` | string | `"1.0.0"` | Policy version for tracking |
| `enabled` | bool | `true` | Master on/off switch |

### Rule Structure

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `name` | string | *required* | Rule identifier |
| `conditions` | list | *required* | At least one condition |
| `verdict` | `ALLOW` \| `DENY` \| `LOG_ONLY` | `DENY` | Verdict when rule matches |
| `match_strategy` | `all` \| `any` | `all` | AND vs OR for conditions |
| `priority` | int | `100` | Lower = evaluated first |
| `message` | string | `""` | Explanation on match |

### Condition Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `eq` | Equals | `tool_name eq "bash"` |
| `neq` | Not equals | `env neq "production"` |
| `in` | Value in list | `tool_name in ["bash", "exec"]` |
| `not_in` | Value not in list | `role not_in ["admin"]` |
| `contains` | String contains | `args.sql contains "DROP"` |
| `regex` | Regex match | `args.url regex "https?://10\\."` |
| `gt` / `lt` | Greater / less than | `args.count gt 100` |
| `gte` / `lte` | Greater/less or equal | `args.amount lte 1000` |

---

## Audit Trail

PolicyForge writes every decision to a HMAC-SHA256 signed JSON-lines log with hash chaining for tamper detection.

```python
from policyforge import AuditLogger

audit = AuditLogger(
    log_dir="./audit_logs",
    hmac_key="your-secret-key",     # or set POLICYFORGE_HMAC_KEY env var
    chain_hashes=True,               # blockchain-style tamper detection
)

engine = PolicyEngine(
    policy_paths=["./policies"],
    audit_logger=audit,
)

# Verify log integrity
valid, tampered = audit.verify_log()
print(f"{valid} valid, {tampered} tampered")
```

Each log entry contains: timestamp, request ID, tool name, agent ID, args hash (SHA-256, not raw args), verdict, matched rule, policy name, evaluation time, and HMAC signature.

---

## Cloud Sync

Sync policies across your multi-cloud environment. The sync layer is strictly for policy *distribution* — security decisions are always made locally.

```python
from policyforge.sync import SyncManager
from policyforge.sync.s3 import S3SyncProvider
from policyforge.sync.azure_blob import AzureBlobSyncProvider
from policyforge.sync.oci_os import OCISyncProvider

sync = SyncManager(local_dir="./policies")

sync.add_provider(S3SyncProvider(
    bucket="corp-ai-policies",
    prefix="agents/prod/",
    region="us-east-1",
))

sync.add_provider(AzureBlobSyncProvider(
    container="policies",
    account_url="https://corpstore.blob.core.windows.net",
))

sync.add_provider(OCISyncProvider(
    namespace="corp-tenancy",
    bucket="ai-policies",
    prefix="prod/",
))

# Pull latest policies from all providers
results = sync.pull()
for r in results:
    print(f"{r.provider}: {r.downloaded} updated, errors={r.errors}")

# Reload the engine with fresh policies
engine.reload(["./policies"])
```

---

## MS Foundry Agents Integration

```python
from policyforge import PolicyEngine, AuditLogger
from policyforge.decorators import PolicyGateWrapper

engine = PolicyEngine(policy_paths=["./policies"])
gate = PolicyGateWrapper(engine, extra_context={"environment": "production"})

# Wrap your Foundry Agent tool functions
gated_tools = gate.wrap_dict({
    "search_reservations": search_reservations,
    "send_guest_email": send_guest_email,
    "adjust_loyalty_points": adjust_loyalty_points,
})

# Register gated_tools with your Foundry Agent instead of the originals.
# Denied calls raise PolicyDeniedError — catch it in your tool-execution
# loop and return a safe response to the agent.
```

---

## Development

```bash
git clone https://github.com/tblakex01/policyforge.git
cd policyforge
pip install -e ".[dev]"
pytest -v
```

---

## License

MIT
