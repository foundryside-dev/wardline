# Catalog Contract (read this fully before writing your entry)

You are one of 12 parallel `codebase-explorer` agents documenting the **wardline** codebase
(`/home/john/wardline`, a Python semantic-tainting static analyzer @ commit `e4668abc`). You own **one
subsystem**. Produce **one schema-conforming catalog entry** and write it to your assigned
`temp/catalog-SX.md` file. Do not analyze files outside your assigned list (other agents own them), but
you MUST name cross-subsystem dependencies using the shared labels below.

## The 12 subsystems (use these exact labels for all cross-references)

| ID | Label | Owns (summary) |
|----|-------|----------------|
| S1 | **Scanner Engine** | AST walk / pipeline / analysis context / grammar / index |
| S2 | **Rule Lattice** | the 26 PY-WL rules + rule metadata/severity + the 3 runtime trust decorators |
| S3 | **Taint Engine** | callgraph, propagation, summaries, providers, fixed point |
| S4 | **Core Orchestration & Config** | run_scan/gate, scan jobs, config + schema, ruleset, discovery, registry, errors, protocols, path confinement (`safe_paths.py`) |
| S5 | **Findings, Outputs & Emit** | Finding model, JSONL/SARIF/Filigree emit, agent-summary, explain |
| S6 | **Gate Discipline & Remediation** | baseline, waivers, suppression, triage, delta scan, autofix |
| S7 | **Trust Evidence & Judge** | attest, assure, dossier, judge, decorator-coverage posture |
| S8 | **Identity & SEI** | finding/node identity, fingerprint, qualname, SEI resolution, rekey |
| S9 | **Federation Clients** | HMAC HTTP, federation-status, legis, Loomweave + Filigree clients, live oracle |
| S10 | **MCP & LSP Server** | JSON-RPC MCP-over-stdio server, tools/resources/prompts, LSP diagnostics |
| S11 | **CLI & Install/Activation** | click command surface + agent enablement (pre-commit, .mcp.json, packs, skills) |
| S12 | **Rust Frontend** | tree-sitter Rust command-injection preview |

## MANDATES (these are what make the catalog trustworthy)

1. **Dependencies come from the graph, not from guessing.** This repo has a fresh Loomweave index
   (`mcp__loomweave__*`). For your subsystem's key entities, derive Inbound/Outbound edges from
   `entity_callers_list`, `entity_neighborhood_get`, and `entity_relation_list` — get ids via
   `entity_find` / `entity_at`. Corroborate with real `Read`s (cite `file:line`). **Do NOT infer
   dependencies from `import` lines alone.** Map each cross-subsystem edge to one of the S1–S12 labels above.
2. **Every claim carries evidence.** Cite `path:line` from files you actually read. No file:line → mark it
   an inference and lower confidence.
3. **Corroborate the known layering violation if it touches you.** The import-linter contract says the
   taint engine must not import the attestation layer, but `scanner/pipeline.py` and
   `scanner/taint/project_resolver.py` import `wardline.core.attest` (tracked as `wardline-9ec283d168`).
   If you own S1, S3, or S7, confirm this from source with exact `file:line` (don't just restate the comment).
4. **Read meaningfully, not exhaustively.** You don't have to read every line of every file; read enough
   to characterize responsibility, key components, patterns, and concerns with evidence. Big files: read
   the top + the public surface + anything your dependency probes flag.
5. **NEVER run git.** Do not run `git` in any form — no status/log/diff/add/stash/checkout/restore/reset/commit.
   You are read-only on the tree except for your single `temp/catalog-SX.md` output file.
6. **Return channel:** WRITE your full entry to `docs/arch-analysis-2026-06-28-0749/temp/catalog-SX.md`
   (replace X with your number). Your final chat message back should be ≤5 lines: the subsystem label,
   confidence, and the 1–2 most important concerns. The file is the deliverable; the message is a receipt.

## Catalog entry template (fill exactly this shape)

```markdown
## SX — <Label>

**Location:** `<dirs/globs you own>`

**Responsibility:** <one sentence — what this subsystem is for>

**Key Components:**
- `path/file.py` — <what it does> (`file:line` for the central symbol)
- ... (the load-bearing files; you don't need every file, but cover the important ones)

**Public surface / entry points:** <functions/classes other subsystems call in, with file:line>

**Dependencies (graph-derived):**
- Inbound (who calls into this, by S-label): <e.g. "S11 CLI → run_scan (cli/scan.py:NN)">
- Outbound (what this calls, by S-label): <e.g. "S3 Taint Engine, S5 Findings">

**Patterns Observed:** <design patterns, idioms, invariants — 2-5 bullets with evidence>

**Concerns:** <bugs, smells, coupling, risks, dead code — each with file:line; or "None observed" with what you checked>

**Confidence:** <High/Medium/Low> — <reasoning: what you read vs inferred>
```

## Notes specific to this codebase
- Base package is **zero-runtime-dependency**; functionality lives behind extras (`scanner`, `rust`,
  `loomweave`, `docs`). Flag any base-module import of a third-party package as a concern.
- `from __future__ import annotations` is universal; the project is mypy-strict and ruff-clean in CI.
- Trust vocabulary: `@external_boundary`, `@trust_boundary`, `@trusted`; rules are `PY-WL-1xx` / `RS-WL-1xx`.
- "SEI" = Stable Entity Identifier (rename-stable id from the Loomweave/Clarion sibling).
