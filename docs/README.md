# Wardline Documentation

## Directory Structure

| Directory | Purpose | Status |
|-----------|---------|--------|
| [reference/](reference/) | Quick-reference lookups: rules, severity matrix, taint states, SARIF format, glossary | Living reference |
| [guides/](guides/) | Task-oriented guides: adoption, CI, governance, analysis levels, profiles, troubleshooting | Living reference |
| [spec/](spec/) | Wardline Framework Specification v0.2.0 (normative) | Living reference |
| [design/](design/) | Active design documents and architecture specs | Active |
| [plans/](plans/) | Implementation plans and roadmaps | Active |
| [audits/](audits/) | Conformance audits and remediation tracking | Active |
| [archive/](archive/) | Completed work artifacts (v0.2.0 plans, reviews, research) | Historical |

## Reading Order

1. **New to Wardline?** Start with [spec/wardline-lite.md](spec/wardline-lite.md) for a 5-question overview, then [getting-started.md](getting-started.md) for a hands-on quickstart.
2. **Looking something up?** The [reference/](reference/) directory has quick-reference tables for rules, severity matrix, taint states, decorators, manifest fields, SARIF format, and error messages.
3. **Adopting or integrating?** The [guides/](guides/) directory covers adoption, CI integration, governance, analysis levels, and troubleshooting.
4. **Building or reviewing?** The [spec/](spec/) directory contains the full normative specification (Part I framework, Part II language bindings).
5. **Contributing?** Check [plans/2026-03-23-post-mvp-roadmap.md](plans/2026-03-23-post-mvp-roadmap.md) for the release roadmap, then look at active plans for the current milestone.
6. **Auditing?** The [audits/](audits/) directory contains the rule conformance audit and its remediation status.

## Conventions

- **Date-prefixed filenames** (`YYYY-MM-DD-name.md`) indicate when a document was created, not when it was last modified. Use `git log` for modification history.
- **Active vs archived:** If a document's work is fully delivered and merged, it belongs in `archive/`. If it's still consulted for ongoing work, it stays in its category directory.
