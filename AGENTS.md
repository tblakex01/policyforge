# AGENTS.md - PolicyForge

## Project Overview

PolicyForge is a local policy engine for AI agent tool-call gating with optional multi-cloud sync. It evaluates tool calls against YAML-defined policies locally with zero network hops. All evaluation is fail-closed by default.

## Quick Reference

```bash
# Install for development
pip install -e ".[dev]"

# Run tests
pytest -v

# Lint
ruff check policyforge tests

# Format check
black --check policyforge tests

# Type check (strict mode)
mypy policyforge
```

## Project Structure

```
policyforge/              # Main package
  models.py               # Core data models (Verdict, Decision, Policy, etc.)
  engine.py               # PolicyEngine - evaluates tool calls against policies
  loader.py               # PolicyLoader - loads/validates YAML policy files
  decorators.py           # @policy_gate decorator and PolicyGateWrapper
  audit.py                # AuditLogger - HMAC-signed, hash-chained JSON-lines
  policies/               # Default YAML policy templates
  sync/                   # Cloud sync providers (S3, Azure Blob, OCI)
    base.py               # SyncProvider ABC and SyncResult
    manager.py            # SyncManager orchestrator
    s3.py / azure_blob.py / oci_os.py
tests/                    # pytest test suite (mirrors package modules)
examples/                 # Usage examples and integration guides
```

## Architecture & Key Patterns

- **Frozen dataclasses** for all models (immutable by design)
- **Thread-safe** read operations on PolicyEngine
- **Short-circuit evaluation**: first DENY stops further rule checks
- **Fail-closed default**: errors result in DENY, not ALLOW
- **Lazy cloud SDK imports**: cloud providers only import their SDK when instantiated
- **Single core dependency**: only PyYAML is required at runtime

## Code Conventions

- **Python 3.10+** target
- **Type hints required** on all public APIs (strict mypy)
- **Line length**: 99 characters (both black and ruff)
- **Ruff rules**: E, F, W, I, UP, B, SIM
- **Black** for formatting
- Private methods prefixed with `_`
- Docstrings on classes and public methods

## Testing

- Framework: **pytest** with **pytest-asyncio** (auto mode)
- Test directory: `tests/`
- Tests mirror the package structure (`test_engine.py`, `test_decorators.py`, etc.)
- Run with: `pytest -v`

## CI Pipeline

GitHub Actions (`.github/workflows/ci.yml`) runs on push/PR to main:
1. **Lint & Format**: `black --check` + `ruff check` (Python 3.12)
2. **Type Check**: `mypy policyforge` strict (Python 3.12)
3. **Tests**: `pytest -v` across Python 3.10, 3.11, 3.12

## Dependencies

- **Core**: PyYAML (>=6.0)
- **Optional cloud sync**: boto3 (`[aws]`), azure-storage-blob (`[azure]`), oci (`[oci]`), or all via `[all-clouds]`
- **Dev**: pytest, pytest-asyncio, mypy, types-PyYAML, ruff, black

## Environment Variables

- `POLICYFORGE_HMAC_KEY` - HMAC key for AuditLogger (alternative to constructor param)

## Common Gotchas

- Cloud SDK types are ignored in mypy config (`boto3`, `botocore`, `oci`, `azure.*`)
- Policy YAML supports both single-document and multi-document formats
- AuditLogger uses 50 MB log rotation by default with hash chaining
- The `@policy_gate` decorator works with both sync and async functions
