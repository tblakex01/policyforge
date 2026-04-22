# PolicyForge Agent-Security Suite — Design

**Status:** Draft
**Date:** 2026-04-22
**Scope:** Three additive features — Tool Fingerprint Pinning, Provenance-Tagged Args, Lethal-Trifecta Detector — shipped in that order.

---

## 1. Motivation

PolicyForge today matches regex/equality predicates against `tool_name` + `args`. Research surveyed the current threat landscape (indirect prompt injection, MCP tool poisoning, confused deputy, exfiltration chains) and the competing tools (NeMo, Invariant, Lakera, OPA, Langfuse) and found three underserved attack classes that fit PolicyForge's local/deterministic/tamper-evident posture:

| Gap | Current PF Blindness | Feature |
|---|---|---|
| MCP tool poisoning, rug-pull, typosquatting | No server-identity or schema-drift awareness | **Tool Fingerprint Pinning** |
| Indirect prompt injection, confused deputy | No notion of data origin | **Provenance-Tagged Args** |
| Read → ingest poisoned content → exfil chain | No cross-call state | **Lethal-Trifecta Detector** |

All three preserve: zero network hops, frozen-dataclass immutability, fail-closed default, YAML authorability, HMAC-chained audit.

---

## 2. Guiding Principles

1. **Additive, not breaking.** Every existing policy must evaluate identically if the new features are unconfigured. All new context fields are optional.
2. **Deterministic.** No feature requires a model call, a network hop, or a classifier. Every decision is reproducible from inputs.
3. **Audit-chained.** New subsystems extend the existing HMAC hash-chain rather than spinning up parallel logs.
4. **Lazy.** Code paths for features that aren't enabled must not execute. Module imports follow the pattern the cloud-sync providers already use.
5. **Single core dep.** No new runtime dependencies beyond PyYAML. `unicodedata` (stdlib) covers NFKC. A tiny handwritten confusables map covers homoglyphs.

---

## 3. Shipping Order & Rationale

| # | Feature | Depends On | Blast Radius | Time-to-value |
|---|---|---|---|---|
| 1 | Tool Fingerprint Pinning | Existing audit chain | Small — new module, no core API change | Fastest |
| 2 | Provenance-Tagged Args | Condition/eval + decorator | Medium — touches the arg substrate | Foundational |
| 3 | Lethal-Trifecta Detector | Feature 2's provenance labels; new session state | Medium — new stateful layer | Capstone |

**Rationale:** Feature 1 is self-contained and pays down the most-cited MCP risk with the smallest code change — it's the right de-risking ship. Feature 2 is the *substrate* Feature 3 needs (the "untrusted-content" leg is detected from provenance labels), so it must come before 3. Feature 3 is a capstone that composes everything.

An alternative — ship Feature 2 first because Feature 3 is marketable — is rejected: 2's diff touches the Condition model and the decorator's public contract, which is more disruptive than shipping the orthogonal Feature 1 first and proving the "new subsystem via YAML section" pattern.

---

## 4. Feature 1 — Tool Fingerprint Pinning

### 4.1 Purpose

Pin each tool's identity at first approval and refuse invocations whose identity has drifted or whose name shadows a trusted one via Unicode tricks.

### 4.2 Attack Coverage

- MCP rug-pull (schema/description changes post-approval).
- Tool-description prompt injection at registration time (description-hash is pinned, drift is flagged).
- Typosquatting / homoglyph shadowing (`send_email` vs Cyrillic `ѕend_email`).
- Cross-server name collisions (`server_id` is part of the key).

### 4.3 Data Model

New frozen dataclass in `policyforge/trust/models.py`:

```python
@dataclass(frozen=True)
class ToolFingerprint:
    server_id: str          # harness-provided, e.g. "mcp://github"
    name: str               # canonical NFKC-normalized
    schema_hash: str        # sha256 of canonical-JSON-serialized input schema
    description_hash: str   # sha256 of description text
    first_seen: float       # unix ts
    approved_by: str        # operator id / "auto"
```

Two event kinds added to `AuditEntry.event_type`: `tool_approved`, `fingerprint_drift`, `tool_shadow_detected`.

### 4.4 Ledger

`policyforge/trust/ledger.py` — JSON-lines file, default `~/.policyforge/approvals.jsonl` (Windows: `%APPDATA%\PolicyForge\approvals.jsonl`). Uses `AuditLogger`'s existing HMAC + chain-prev fields so operators can verify the ledger with the same tooling. A ledger is a specialized audit log, not a parallel mechanism.

### 4.5 YAML Shape

New top-level block at the policy-set level (not per-rule):

```yaml
tool_trust:
  mode: enforce        # enforce | warn | disabled
  ledger_path: ~/.policyforge/approvals.jsonl
  on_mismatch: DENY
  on_unknown: DENY     # unknown tool not in ledger
  detect_shadowing:
    nfkc: true
    confusables: true  # homoglyph map
  auto_approve: false  # if true, first-seen tools are silently pinned
```

### 4.6 Evaluation Flow

`PolicyEngine.evaluate` gains a pre-flight step when `tool_trust.mode != disabled`:

1. Require `context["tool"] = {"server_id": ..., "schema_hash": ..., "description_hash": ...}`. Missing → treat as `unknown`.
2. Normalize `tool_name` via NFKC and check the confusables table against approved names. A collision → DENY `tool_shadow_detected`.
3. Look up `(server_id, NFKC(name))` in the ledger. Miss + `on_unknown=DENY` → DENY `tool_unknown`.
4. Compare `schema_hash` / `description_hash`. Drift → DENY `fingerprint_drift`.
5. On pass, proceed to the existing rule loop unchanged.

### 4.7 Module Layout

```
policyforge/trust/
  __init__.py
  models.py        # ToolFingerprint, enums
  ledger.py        # LedgerReader, LedgerWriter (HMAC-chained)
  shadowing.py     # NFKC + confusables check
  manager.py       # TrustManager: orchestrates all of the above
```

`PolicyEngine.__init__` accepts an optional `trust_manager: TrustManager | None`. If `None`, pre-flight is skipped (backwards compatible).

### 4.8 Confusables Handling

Stdlib `unicodedata.normalize("NFKC", s)` handles canonical duplicates. Homoglyphs require a small handcrafted map (Latin ↔ Cyrillic ↔ Greek for the ~40 most-confused letters). Documented as "minimum-viable" in v1; a full ICU-equivalent table can follow if needed. No new dependency.

### 4.9 Testing

- Fingerprint match / mismatch / missing.
- NFKC collision (`file\u00E9` vs `fil\u00E9`).
- Cyrillic homoglyph collision.
- Ledger corruption (bad HMAC, broken chain) → engine refuses to start in `enforce`.
- `auto_approve` path writes a ledger entry and allows the call.

---

## 5. Feature 2 — Provenance-Tagged Args & Taint-Flow Rules

### 5.1 Purpose

Let YAML rules deny based on **where data came from**, not just what it contains. Indirect-injection attacks put malicious instructions into a benign-shaped value; origin labels catch them where content rules cannot.

### 5.2 Attack Coverage

- Indirect prompt injection (rule: "URL from web/rag cannot be the target of http.post").
- Confused deputy (rule: "object_id used in `delete_*` must have provenance `user`").
- Exfil via a generic writer tool being fed tainted content.

### 5.3 Data Model

Add an optional parallel tree to the evaluation context:

```python
context = {
    "tool_name": "http.post",
    "args":           {"url": "https://...", "body": "..."},
    "args_provenance": {"url": "web", "body": "user"},
}
```

Key choice: **parallel tree, not value envelopes.** Reasons:
- Existing `args.url` rules keep working unchanged.
- Serialization stays simple (no nested `{value, provenance}` objects to unwrap).
- Arg *values* flowing into downstream systems remain unchanged.

Provenance vocabulary (closed enum, extensible via YAML):

```
user | developer | tool_output | rag | web | email | file | constant | unknown
```

Default when unlabeled: `user` (preserves today's semantics). Configurable to `unknown` for stricter deployments.

### 5.4 YAML Shape

New accessor syntax in condition `field`: a leading `@` denotes a provenance lookup.

```yaml
- name: deny untrusted url to http.post
  priority: 10
  match_strategy: all
  conditions:
    - field: tool_name
      operator: eq
      value: http.post
    - field: "@args.url"       # provenance of args.url
      operator: in
      value: [web, rag, email, tool_output]
  verdict: DENY
  message: "URL came from untrusted data source."
```

Policy-set block:

```yaml
provenance:
  default: user            # or: unknown (strict)
  allowed_labels: [user, developer, tool_output, rag, web, email, file, constant, unknown]
```

### 5.5 Eval Changes

In `policyforge/engine.py`:

- `_resolve_field` detects a leading `@` and redirects to the provenance tree, stripping the `@`.
- Missing provenance for a present field → fall back to `provenance.default`.
- `Condition.__post_init__` validates that `@`-prefixed fields use only `eq/neq/in/not_in` (other ops make no semantic sense on labels).

### 5.6 Decorator Changes

`@policy_gate` gains an optional `arg_provenance` parameter:

```python
@policy_gate(
    policy="web_ops",
    arg_provenance={"url": "web", "body": lambda kwargs: kwargs.get("_origin", "user")},
)
def http_post(url: str, body: str) -> Response: ...
```

Static mapping or callable that receives the kwargs. The wrapper builds the `args_provenance` tree and passes it through to `engine.evaluate(..., context={"args_provenance": ...})`.

### 5.7 Testing

- `@args.url` matches on exact label and on `in` list.
- Unlabeled field falls back to configured default.
- Invalid operator on a provenance field is rejected at load time.
- `default=unknown` causes legacy policies lacking provenance context to behave strictly.
- Decorator with callable provenance resolver.

---

## 6. Feature 3 — Lethal-Trifecta Detector

### 6.1 Purpose

Close Simon Willison's framing — *access to private data + exposure to untrusted content + external communication* — as a runtime gate. Individual calls look fine; the *pattern across calls* is what's dangerous, and that requires state.

### 6.2 Attack Coverage

- Read-secret → fetch-poisoned-doc → post-to-webhook chains.
- RAG-poisoned agent that reads an internal doc then emails it out.
- Cross-tool exfiltration that no single rule could catch.

### 6.3 Data Model

Each tool declares which legs it represents in a new top-level YAML block:

```yaml
tool_capabilities:
  read_vault:     [private_data]
  sql.query:      [private_data]
  web.fetch:      [untrusted_content]
  rag.search:     [untrusted_content]
  slack.post:     [external_comm]
  http.post:      [external_comm]

trifecta_guard:
  enabled: true
  legs: [private_data, untrusted_content, external_comm]   # extensible
  window_s: 600
  on_close: DENY
  session_field: context.session_id
  exceptions:
    - name: blessed_pipeline
      chain: [read_vault, internal.scrub, slack.post]
```

### 6.4 Session State

New abstraction `policyforge/trifecta/session_store.py`:

```python
class SessionStore(Protocol):
    def record(self, session_id: str, legs: set[str], request_id: str, ts: float) -> None: ...
    def closed_legs(self, session_id: str, window_s: float, now: float) -> dict[str, float]: ...
    def drop_expired(self, now: float) -> None: ...

class InMemorySessionStore: ...   # v1 default
```

v1 ships only `InMemorySessionStore`. The protocol exists so SQLite/Redis stores can land later without churn.

### 6.5 Automatic Leg Derivation from Provenance (integration with Feature 2)

If `trifecta_guard.auto_untrusted` is true (default), any call with at least one arg whose provenance is in `{web, rag, email, tool_output}` is automatically credited with the `untrusted_content` leg — even if the tool isn't declared in `tool_capabilities`. This is the composition point between Features 2 and 3.

### 6.6 Evaluation Flow

Runs **after** fingerprint pre-flight, **before** the rule loop:

1. Derive this call's legs: declared capabilities ∪ auto-derived from provenance.
2. Compute the session's already-closed legs within `window_s`.
3. If `derived ∪ closed == legs` and the closing call isn't in `exceptions`, short-circuit with DENY `trifecta_closed`. An audit event records the closing request IDs for every leg, so operators can reconstruct the chain.
4. Otherwise, record the new legs in the store and fall through to regular evaluation.

### 6.7 Failure Modes

- Session store unavailable (e.g. Redis down) → configurable: fail-closed (default, deny the call) or fail-open with a LOG_ONLY warning.
- Session ID missing from context while `trifecta_guard.enabled=true` → DENY with a clear "session_id required" message. This is fail-closed by design.

### 6.8 Testing

- Legs close individually: no block.
- Two legs within window + third-leg call: DENY with all three request_ids in the audit.
- Third-leg call outside window: allowed (legs expired).
- Exception chain passes.
- Auto-derived untrusted leg via provenance works.
- Missing session_id fails closed.

---

## 7. Cross-Cutting Concerns

### 7.1 Backwards Compatibility

Any existing policy file and any existing `PolicyEngine(...)` construction continues to behave identically. New features activate only via new YAML blocks (`tool_trust`, `provenance`, `tool_capabilities`, `trifecta_guard`) or explicit constructor args. A policy that uses none is indistinguishable from today's behavior.

### 7.2 Performance

- Fingerprint check: single dict lookup + two `hmac.compare_digest` calls.
- Provenance check: one extra dict traversal per `@`-prefixed condition.
- Trifecta: one dict lookup into the session store, one set union, one expiration pass.

All three stay well under the sub-millisecond evaluation budget the engine targets. Expiration in the in-memory store is amortized (lazy sweep on access).

### 7.3 Audit

Three new `event_type` values: `tool_approved`, `fingerprint_drift`, `tool_shadow_detected`, `trifecta_closed`. All reuse the existing HMAC hash-chain. No new log file for anything except the approvals ledger (itself a chained JSONL).

### 7.4 Configuration Surface

Per the loader's current convention, the new blocks live alongside `policies:` in the same YAML files. The loader rejects unknown top-level keys today; it must be extended to accept these blocks and to validate them with the same strictness.

### 7.5 Testing Strategy

- Match project convention: tests in `tests/` mirror package layout (`tests/test_trust_manager.py`, `tests/test_provenance.py`, `tests/test_trifecta.py`).
- Preserve the 90% branch-coverage gate established in CI.
- Add fixtures for: a disposable in-memory ledger, a provenance-enabled context factory, a fast-forwarding clock for trifecta window tests.

### 7.6 Documentation

- Extend `README.md` with a "Threat model" section mapping features → attacks.
- New policy examples under `policyforge/policies/` demonstrating each feature:
  - `tool_trust_example.yaml`
  - `provenance_example.yaml`
  - `trifecta_example.yaml`

---

## 8. Out of Scope (v1)

- **Persistent cross-process session state.** Trifecta state is in-memory per engine instance. A Redis/SQLite store is a v2 concern.
- **Full ICU confusables table.** v1 ships a minimum-viable homoglyph map. Replacement is an internal concern.
- **Distributed approval ledger.** Cloud-sync providers could replicate `approvals.jsonl`, but that's reuse of existing sync code, not new design.
- **Automatic provenance inference.** The harness supplies labels; PolicyForge does not attempt to infer them from call history.
- **Taint propagation through model output.** That would require output inspection — a separate future feature.

---

## 9. Open Questions

1. **Ledger location on Windows.** `%APPDATA%\PolicyForge\` is the proposal. Confirm that aligns with operator expectations or prefer a project-local `.policyforge/` convention.
2. **Strict default for provenance.** Should `provenance.default` be `user` (permissive, preserves legacy) or `unknown` (strict, breaks legacy policies once a `provenance:` block appears)? Proposal: `user` when no `provenance:` block exists, `unknown` when the block is present but a field is unlabeled.
3. **`auto_approve` in production.** Dangerous or useful? Proposal: ship it but default to `false` and document as dev-only.
4. **Trifecta leg vocabulary.** The Willison framing is a useful default; should we ship it as the sole preset, or allow operators to define arbitrary N-leg patterns (e.g. a 4-leg "privileged-write trifecta")? Proposal: allow arbitrary legs; ship the 3-leg preset as a referenced example.
5. **Decorator provenance with async.** `PolicyGateWrapper` supports async today; the new `arg_provenance` callable may or may not be async. Proposal: support both via `inspect.iscoroutinefunction` branching, consistent with existing patterns.

---

## 10. Appendix — Module Map After All Three Ship

```
policyforge/
  models.py
  engine.py              # pre-flight hooks added
  loader.py              # new top-level blocks
  decorators.py          # arg_provenance param
  audit.py               # (unchanged; new event_types flow through)
  trust/                 # Feature 1
    models.py
    ledger.py
    shadowing.py
    manager.py
  provenance/            # Feature 2
    context.py           # envelope/parallel-tree helpers
    vocab.py
  trifecta/              # Feature 3
    models.py
    session_store.py
    detector.py
  policies/              # example YAML for each feature
  sync/                  # unchanged
```
