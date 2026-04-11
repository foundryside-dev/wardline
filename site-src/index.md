---
hide:
  - navigation
  - toc
---

<div class="wl-hero" markdown>

<div class="wl-hero__copy" markdown>

<span class="wl-hero__eyebrow">v0.3.0 · Release Candidate</span>

# Trust boundaries,<br><span class="wl-hero__accent">statically verified.</span>

<p class="wl-hero__lede">
Wardline is a semantic boundary enforcement framework for Python. Define a
four-tier trust hierarchy, mark your validation points, and the scanner proves
that untrusted input never reaches privileged code — before it ships.
</p>

<div class="wl-hero__actions" markdown>
[Get Started](getting-started.md){ .md-button .md-button--primary }
[Read the Spec](specification.md){ .md-button }
[View on GitHub](https://github.com/tachyon-beep/wardline){ .md-button }
</div>

<div class="wl-hero__install" markdown>

=== "pip"

    ```bash
    pip install wardline
    ```

=== "uv"

    ```bash
    uv add wardline
    ```

=== "pipx"

    ```bash
    pipx install wardline
    ```

</div>

</div>

<div class="wl-hero__diagram" markdown>

![Wardline four-tier trust hierarchy](assets/tier-diagram.svg)

</div>

</div>

<div class="wl-badges" markdown>
[![PyPI version](https://img.shields.io/pypi/v/wardline?style=flat-square&logo=pypi&logoColor=white&color=0d9488&labelColor=0b1120)](https://pypi.org/project/wardline/)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-0d9488?style=flat-square&logo=python&logoColor=white&labelColor=0b1120)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-0d9488?style=flat-square&labelColor=0b1120)](https://github.com/tachyon-beep/wardline/blob/main/LICENSE)
[![Spec: 0.3.0 RC](https://img.shields.io/badge/spec-0.3.0%20RC-14b8a6?style=flat-square&labelColor=0b1120)](specification.md)
[![SARIF 2.1.0](https://img.shields.io/badge/output-SARIF%202.1.0-14b8a6?style=flat-square&labelColor=0b1120)](reference/sarif-format.md)
</div>

<section class="wl-section" markdown>

<span class="wl-section__eyebrow">Capabilities</span>
## Everything a trust boundary needs

<p class="wl-section__intro">
Wardline ships as a static scanner, a decorator library, a runtime enforcer,
and a governance register — all driven by one portable YAML manifest.
</p>

<div class="wl-features" markdown>

<div class="wl-feature" markdown>
<span class="wl-feature__icon">:material-shield-check:{ .lg .middle }</span>
### Four-tier authority model
**INTEGRAL → ASSURED → GUARDED → EXTERNAL_RAW.** Data flows down freely;
flowing up requires an explicit validation boundary. Eight canonical taint
states with a commutative join lattice.
</div>

<div class="wl-feature" markdown>
<span class="wl-feature__icon">:material-magnify-scan:{ .lg .middle }</span>
### AST scanner with taint propagation
Three-phase engine — variable, function, and callgraph — catches violations
without running your code. Resilient: parse errors skip the file, rule
crashes emit a `TOOL-ERROR` finding.
</div>

<div class="wl-feature" markdown>
<span class="wl-feature__icon">:material-file-document-check:{ .lg .middle }</span>
### SARIF 2.1.0 output
Findings emit native SARIF for GitHub Code Scanning, the VS Code SARIF Viewer,
and any CI system that speaks the format. No glue code, no custom parsers.
</div>

<div class="wl-feature" markdown>
<span class="wl-feature__icon">:material-gavel:{ .lg .middle }</span>
### Exception governance
A control-law state machine tracks every exception from request through
approval, expiry, and retirement. Audit trails, retention rules, and SIEM
export are built in.
</div>

<div class="wl-feature" markdown>
<span class="wl-feature__icon">:material-package-variant:{ .lg .middle }</span>
### Portable manifest
One `wardline.yaml` declares tier assignments, boundaries, and exceptions.
Monorepo overlays let sub-packages extend the root policy without forking it.
</div>

<div class="wl-feature" markdown>
<span class="wl-feature__icon">:material-shield-lock-outline:{ .lg .middle }</span>
### Runtime enforcement
Descriptor-based boundary checks catch anything the scanner can't prove
statically — protocol violations, dynamic dispatch, plugin surfaces — with
deterministic failure modes.
</div>

</div>

</section>

<section class="wl-section" markdown>

<span class="wl-section__eyebrow">Why Wardline</span>
## One rule ships; one rule ships better

<p class="wl-section__intro">
The scanner catches the same kind of violation Python code reviews miss every
day: untrusted input reaching a function that trusts its arguments. Here's
what that looks like in practice.
</p>

<div class="wl-compare" markdown>

<div class="wl-compare__col" markdown>
<div class="wl-compare__header wl-compare__header--bad" markdown>:material-close-octagon: Violation · PY-WL-003</div>

```python
@external_boundary
def handle_webhook(payload: dict) -> None:
    record_audit_event(payload)

@integrity_critical
def record_audit_event(data: dict) -> None:
    db.write_audit(data)
```
</div>

<div class="wl-compare__col" markdown>
<div class="wl-compare__header wl-compare__header--good" markdown>:material-check-circle: Validated</div>

```python
@external_boundary
def handle_webhook(payload: dict) -> None:
    validated = parse_payload(payload)
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

</div>

</section>

<section class="wl-section" markdown>

<span class="wl-section__eyebrow">Where to start</span>
## Find your path

<div class="wl-paths" markdown>

<div class="wl-path" markdown>
<span class="wl-path__eyebrow">For developers</span>
### Ship a boundary

- [Install Wardline](getting-started.md)
- [Annotation vocabulary](reference/decorators.md)
- [Error messages](reference/error-messages.md)
- [Taint states](reference/taint-states.md)
</div>

<div class="wl-path" markdown>
<span class="wl-path__eyebrow">For reviewers</span>
### Understand a finding

- [Rule catalogue](reference/rules.md)
- [Severity matrix](reference/severity-matrix.md)
- [SARIF format](reference/sarif-format.md)
- [Glossary](reference/glossary.md)
</div>

<div class="wl-path" markdown>
<span class="wl-path__eyebrow">For adopters</span>
### Roll it out

- [Adoption guide](guides/adoption.md)
- [CI integration](guides/ci-integration.md)
- [Governance model](guides/governance.md)
- [Manifest reference](reference/manifest.md)
</div>

</div>

</section>

<div class="wl-cta" markdown>

## The specification is the source of truth

Every binding maps to the same framework. Read the canonical PDF or browse the
chapters online — both are built from the same Markdown source.

<div class="wl-cta__actions" markdown>
[Download PDF](assets/wardline-specification.pdf){ .md-button .md-button--primary }
[Browse chapters](specification.md){ .md-button }
</div>

</div>
