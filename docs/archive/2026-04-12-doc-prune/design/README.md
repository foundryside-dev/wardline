# Design Documents

Active design specifications for features in development or planned for upcoming releases.

## Documents

| Document | Scope | Target |
|----------|-------|--------|
| [wardline-python-design](2026-03-21-wardline-python-design.md) | Master architecture and source layout | Foundational |
| [l3-callgraph-taint](2026-03-24-l3-callgraph-taint-design.md) | L3 call-graph taint propagation | WP 2.1 (v0.3.0) |
| [governance-cli](2026-03-24-governance-cli-design.md) | Governance CLI commands and data flows | WP 2.3a (v0.3.0) |
| [runtime-enforcement](2026-03-24-runtime-enforcement-design.md) | Runtime type + structural checking | WP 3.2 |
| [flake8-plugin](2026-03-24-flake8-plugin-design.md) | Flake8 linter integration | WP 3.1 |
| [sarif-aggregation](2026-03-24-sarif-aggregation-design.md) | Multi-tool SARIF aggregation | WP 3.3 |
| [two-hop-rejection-path](2026-03-25-two-hop-rejection-path-design.md) | PY-WL-008 two-hop detection | HC-2 remediation |
| [audit-remediation-phase1](2026-03-25-audit-remediation-phase1-design.md) | CF-1 body eval taint + HC-1/HC-2 tests | Audit remediation |

## Lifecycle

When a design's implementation is fully delivered and merged, move the document to `archive/` under the appropriate release subdirectory.
