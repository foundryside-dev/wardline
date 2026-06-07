---
template: home.html
hide:
  - navigation
  - toc
---

## Install

```bash
pip install "wardline[scanner]"
```

Wardline ships in layers, so you only pull what you use:

| Install | Pulls in | Gives you |
| --- | --- | --- |
| `wardline` (base) | nothing | the analysis engine as a zero-dependency library |
| `wardline[scanner]` | pyyaml, jsonschema, click | the `wardline scan` command-line tool |

The `wardline scan` CLI lives in the `scanner` extra, so install
`wardline[scanner]` to run the examples below. Everything in the
[Weft integration](guides/weft.md) guide — SARIF output, the Filigree emitter,
Loomweave conformance — also ships in `scanner` (the Filigree emitter uses only
the standard library), so no further extra is required.

## 30-second example

Point `wardline scan` at a directory:

```bash
wardline scan . --format jsonl
```

```text
scanned 2 file(s); 4 finding(s) — 0 suppressed (0 baseline / 0 waiver / 0 judged), 1 active -> findings.jsonl
```

In JSONL mode the findings are written to `findings.jsonl` in the current
directory; the line above is the run summary. One of those findings flags a
trust-boundary violation:

```json
{"rule_id": "PY-WL-101", "severity": "ERROR", "kind": "defect", "qualname": "service.current_user", "location": {"path": "service.py", "line_start": 7, "line_end": 8, "col_start": 0, "col_end": 26}, "message": "service.current_user declares return trust INTEGRAL but actually returns EXTERNAL_RAW (less trusted) — untrusted data reaches a trusted producer", "properties": {"declared_return": "INTEGRAL", "actual_return": "EXTERNAL_RAW"}, "suppression_state": "active"}
```

That is Wardline reporting that a function annotated as a trusted producer
actually returns raw, untrusted data — a trust-boundary leak. The
[Getting Started](getting-started.md) guide walks through this finding field by
field.

## Next steps

- [Getting Started](getting-started.md) — install, run a first scan, and read a finding.
- [The model](concepts/model.md) — trust tiers, boundaries, and how taint flows.
- [Arming agents](guides/agents.md) — using Wardline to give coding agents a trust-boundary check.
