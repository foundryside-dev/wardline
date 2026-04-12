# Wardline Documentation

## Directory Structure

| Directory | Purpose | Status |
|-----------|---------|--------|
| [reference/](reference/) | Quick-reference lookups: rules, severity matrix, taint states, SARIF format, glossary | Living reference |
| [guides/](guides/) | Task-oriented guides: adoption, CI, governance, analysis levels, profiles, troubleshooting | Living reference |
| [spec/](spec/) | Wardline framework specification and language bindings (normative) | Living reference |
| [adr/](adr/) | Architectural decision records and rationale for durable project decisions | Living reference |
| [verification/](verification/) | Compliance ledgers, release projections, and conformance working artifacts | Active |
| [requirements/](requirements/) | Spec-fitness baselines, review records, and project-facing requirement sets | Active |
| [audits/](audits/) | Conformance audits and retained audit evidence | Active |

## Reading Order

1. **New to Wardline?** Start with [getting-started.md](getting-started.md) for a hands-on quickstart, then the [spec/](spec/) directory for the full specification.
2. **Looking something up?** The [reference/](reference/) directory has quick-reference tables for rules, severity matrix, taint states, decorators, manifest fields, SARIF format, and error messages.
3. **Adopting or integrating?** The [guides/](guides/) directory covers adoption, CI integration, governance, analysis levels, and troubleshooting.
4. **Building or reviewing?** Start with [specification.md](specification.md), then use [spec/](spec/) for the full normative specification and language bindings.
5. **Understanding key decisions?** The [adr/](adr/) directory records durable architectural and governance decisions that still constrain implementation and conformance claims.
6. **Assessing release/compliance state?** Use [verification/](verification/) for the current release projection and compliance ledger, and [requirements/spec-fitness/](requirements/spec-fitness/) for the supporting baselines.
7. **Auditing?** The [audits/](audits/) directory retains audit summaries and evidence that still matter to current conformance work.

## Conventions

- **Date-prefixed filenames** (`YYYY-MM-DD-name.md`) indicate when a document was created, not when it was last modified. Use `git log` for modification history.
- **Active vs removed:** Historical process artifacts may be removed from `docs/` once they are no longer part of the maintained documentation surface. Use `git log` to recover prior states when needed.
