---
hide:
  - navigation
  - toc
---

<div class="wl-hero" markdown>

# Wardline

### Semantic boundary enforcement for Python

Statically verify that untrusted input never reaches privileged code.
Wardline defines a four-tier trust hierarchy and catches trust-boundary
violations before they ship — via AST analysis with taint propagation.

<div class="wl-install" markdown>

```bash
pip install wardline
```

</div>

[Get Started](getting-started.md){ .md-button .md-button--primary }
[View on GitHub](https://github.com/tachyon-beep/wardline){ .md-button }
[Specification (PDF)](assets/wardline-specification.pdf){ .md-button }

</div>

---

<div class="wl-features" markdown>

<div class="wl-feature" markdown>
### :material-shield-check: Trust Tiers
Four-tier authority model: **INTEGRAL → ASSURED → GUARDED → EXTERNAL_RAW**.
Data flows down freely; flowing up requires an explicit validation boundary.
</div>

<div class="wl-feature" markdown>
### :material-magnify-scan: Static Analysis
AST-based scanner with three-phase taint propagation — variable-level,
function-level, and callgraph. Catches violations without running your code.
</div>

<div class="wl-feature" markdown>
### :material-file-document-check: SARIF Output
Findings emit SARIF v2.1.0 JSON for direct integration with GitHub Code
Scanning, VS Code SARIF Viewer, and CI/CD pipelines.
</div>

<div class="wl-feature" markdown>
### :material-gavel: Governance Model
Exception register with control-law state machine. Exceptions require
approval, carry expiry, and are tracked through their full lifecycle.
</div>

</div>

---

<div class="wl-example" markdown>

## What Wardline Catches

Untrusted input flowing to a privileged function without validation:

```python
# ❌ VIOLATION — EXTERNAL_RAW data reaches @integrity_critical
@external_boundary
def handle_webhook(payload: dict) -> None:
    record_audit_event(payload)        # PY-WL-003: tier violation

@integrity_critical
def record_audit_event(data: dict) -> None:
    db.write_audit(data)
```

Insert a validation boundary to fix:

```python
# ✅ CORRECT — data is validated before reaching Tier 1
@external_boundary
def handle_webhook(payload: dict) -> None:
    validated = parse_payload(payload)  # GUARDED after this
    record_audit_event(validated)

@validates_shape
def parse_payload(raw: dict) -> AuditRecord:
    if "action" not in raw:
        raise ValueError("missing action")
    return AuditRecord(action=raw["action"])

@integrity_critical
def record_audit_event(record: AuditRecord) -> None:
    db.write_audit(record)
```

</div>

---

<div class="wl-quicknav" markdown>

## I need to...

| Question | Start here |
|----------|-----------|
| Understand why a rule fired | [Rules](reference/rules.md) → [Severity Matrix](reference/severity-matrix.md) |
| Pick the right decorator | [Decorators](reference/decorators.md) |
| Understand a taint state | [Taint States](reference/taint-states.md) |
| Fix a scan error | [Error Messages](reference/error-messages.md) |
| Set up wardline in my project | [Getting Started](getting-started.md) |
| Integrate with CI/CD | [CI Integration](guides/ci-integration.md) |
| Manage exceptions | [Governance](guides/governance.md) |
| Consume output in CI | [SARIF Format](reference/sarif-format.md) |
| Configure wardline.yaml | [Manifest](reference/manifest.md) |
| Look up a term | [Glossary](reference/glossary.md) |

</div>
