# Wardline

Wardline is a lightweight semantic-tainting static analyzer for trust
boundaries. It scans Python source, includes a Rust command-injection preview,
and gives agents and CI a deterministic gate for untrusted data reaching trusted
code.

This is the wardline documentation site — the front door for installing,
running, and integrating the tool, with the concept, guide, and reference
material behind it.

## Install

```bash
pip install "wardline[scanner]"
```

Wardline ships in layers, so you only pull what you use:

| Install | Pulls in | Gives you |
| --- | --- | --- |
| `wardline` (base) | nothing | the analysis engine as a zero-dependency library |
| `wardline[scanner]` | pyyaml, jsonschema, click | the `wardline scan` command-line tool |
| `wardline[rust]` | scanner extra, tree-sitter, tree-sitter-rust | the Rust command-injection preview frontend |

The `wardline scan` CLI lives in the `scanner` extra, so install
`wardline[scanner]` to run the examples below. Everything in the
[Weft integration](guides/weft.md) guide — SARIF output, agent-summary output,
signed governance artifacts, native Filigree emission, and Loomweave
conformance — composes with the normal scanner path.

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

## Product workflow

1. Mark the boundary with `@external_boundary`, `@trust_boundary`, or
   `@trusted`.
2. Run `wardline scan . --fail-on ERROR` locally or in CI.
3. Ask `wardline explain-taint` or the MCP `explain_taint` tool why the gate
   tripped.
4. Fix the validation or normalization at the boundary and rescan.

Agents can run the same loop through `wardline mcp` without scraping terminal
output. Use `wardline install` to add the agent guidance and MCP registration to
an application project.

## Next steps

- [Getting Started](getting-started.md) — install, run a first scan, and read a finding.
- [The model](concepts/model.md) — trust tiers, boundaries, and how taint flows.
- [Rust support](guides/rust-preview.md) — command-injection preview for Rust code.
- [Weft integration](guides/weft.md) — SARIF, Filigree, Loomweave, and signed handoff paths.
- [Arming agents](guides/agents.md) — using Wardline to give coding agents a trust-boundary check.
- [MCP tool reference](reference/mcp.md) — all 18 MCP tools the `wardline mcp` server serves.
