# 01 — Discovery Findings (Holistic Assessment)

**Target:** `wardline` @ `e4668abc` (branch `release/consolidation-2026-06-26`)
**Date:** 2026-06-28 · **Analyst:** orchestrator + Loomweave index (fresh) + Filigree tracker

---

## 1. What the system is

Wardline is a **deterministic, opt-in semantic-tainting static analyzer for Python** (with a preview
Rust command-injection frontend). It reads code statically — never executes it — and tracks a *trust
level* (taint) for values through function bodies and the project call graph, flagging where untrusted
data reaches a trusted producer or a dangerous sink without validation in between.

Its defining design stance, stated in the README and enforced throughout: **silent until opt-in.**
Undecorated code is "unknown-trust" and produces no findings; the developer declares trust with three
decorators (`@external_boundary`, `@trust_boundary`, `@trusted`) and only then is enforcement active.
This is what lets it scan a large codebase (including its own) with zero noise.

It is one tool in the **Weft** suite (sibling tools: Loomweave code-archaeology, Filigree issue tracker,
legis governance). Wardline *analyzes* trust; it federates with siblings but does not depend on them at
runtime — they are opt-in integrations behind extras.

**Maturity:** `Development Status :: 5 - Production/Stable`, version 1.0.6 shipped to PyPI. Staged build
SP0–SP9 complete.

## 2. Technology stack

| Dimension | Choice | Notes |
|-----------|--------|-------|
| Language | Python ≥ 3.12 | `from __future__ import annotations` throughout; typed (`Typing :: Typed`) |
| Build | hatchling 1.30.1, `uv` | version from `src/wardline/_version.py` |
| **Base runtime deps** | **none** | `dependencies = []` — the zero-dep base is a hard product invariant |
| Extras | `scanner` (pyyaml/jsonschema/click), `docs` (mkdocs), `loomweave` (blake3), `rust` (tree-sitter + tree-sitter-rust) | power is opt-in *activation*, not opt-in config |
| Parsing | stdlib `ast` (Python); `tree-sitter` (Rust preview) | no third-party Python parser |
| Dev tooling | pytest (+cov, +randomly, hypothesis), ruff, mypy strict, **import-linter** | `make ci = lint typecheck test-cov`, 90% coverage gate |
| Wire/crypto | stdlib `hashlib`/`hmac`/`urllib` only | HMAC-signed federation hops; no `requests`/`httpx` |

## 3. Size & shape

- **182 Python source files, ~42,584 LOC** in `src/wardline/`; **367 test files** in `tests/` (≈2:1 test:source by file count — strong test investment).
- Loomweave index (fresh @ HEAD): **7,729 entities, 20,068 edges, 540 subsystem clusters**; SEI populated.
- LOC by top-level module:

| Module | LOC | Role |
|--------|-----|------|
| `scanner/` | 14,088 | The analysis engine: AST primitives, taint dataflow, the rule lattice |
| `core/` | 13,550 | Orchestration, config, findings/outputs, gate discipline, trust-evidence, identity, federation |
| `mcp/` | 5,453 | Dependency-free MCP-over-stdio server (the "primary agent surface") |
| `rust/` | 3,156 | Tree-sitter Rust command-injection preview frontend |
| `cli/` | 2,641 | `click` command surface (one module per command) |
| `install/` | 1,766 | Agent enablement: pre-commit, `.mcp.json`, packs, skills |
| `loomweave/` | 1,002 | Loomweave/Clarion taint-store HTTP client (HMAC wire) |
| `filigree/` | 262 | Filigree emitter + dossier client |
| `decorators/` | 148 | The runtime trust-vocabulary grammar (the 3 decorators) |

## 4. Entry points & runtime flow

- **Console script:** `wardline = wardline.cli.entrypoint:main` — a dependency-light shim that imports
  `cli.main:cli` and prints a clean "install `wardline[scanner]`" error if the scanner extra is missing.
- **CLI surface:** `cli/main.py` wires ~20 command modules (scan, explain_taint, judge, fix, doctor,
  assure, attest, dossier, rekey, baseline/waiver via findings, install, mcp, lsp, scan_job(+worker), …).
- **MCP server:** `wardline mcp` → `mcp/server.py` — JSON-RPC 2.0 over stdio, no SDK; 15+ tools.
- **Shared core:** both CLI and MCP call `core/run.py:run_scan` / `gate_decision` — *identical by
  construction* (the SP8 keystone extraction). `core/baseline.generate_baseline` and
  `core/judge_run.run_judge` are the other two extracted shared entry points.
- **Pipeline (per scan):** discover sources → frontend analyzer (`scanner/pipeline.py`) builds an
  `AnalysisContext` (AST + taint over call graph) → rule lattice emits `Finding`s → suppression
  (baseline/waivers/judged) → gate decision → emit (JSONL/SARIF/Filigree/legis).

## 5. Intended architecture & known boundary debt

The `[tool.importlinter]` config encodes intended `core/` layering and **documents a live violation**:

> "Taint engine must not import the attestation layer" — **BROKEN today**:
> `wardline.scanner.pipeline` / `wardline.scanner.taint.project_resolver` import `wardline.core.attest`.
> Contract is report-only (`lint-imports || true`); the fix is tracked as `wardline-9ec283d168`.

This is a real, self-acknowledged architectural concern: the layering is **scanner (engine) ← core
(orchestration/evidence)** in intent, but the engine reaches up into the attestation layer. Carried into
the quality assessment.

## 6. Proposed subsystem decomposition (11)

Coupling is largely one-directional: **CLI / MCP → core → scanner**, with `loomweave`/`filigree`/`legis`
as leaf federation clients and `rust`/`decorators` as leaf providers. The 11 cohesive units (see
`00-coordination.md` for file membership):

1. Scanner Engine · 2. Rule Lattice (+ decorators) · 3. Taint Engine · 4. Core Orchestration & Config ·
5. Findings, Outputs & Emit · 6. Gate Discipline · 7. Trust Evidence & Judge · 8. Identity, SEI &
Federation · 9. MCP Server · 10. CLI & Install/Activation · 11. Rust Frontend

## 7. Structural oddities noted (low severity)
- `src/src/` (empty) and `src/wardline/src/wardline/` (perm-restricted stray) — likely build/worktree
  artifacts, not packaged; verify they are gitignored / excluded from sdist.
- `src/wardline/skills/wardline-gate/` — a bundled agent skill payload shipped inside the package.

## 8. Confidence
**High** for structure, stack, entry points, and the layering-debt finding (all from primary sources:
pyproject, import-linter config, source headers, Loomweave index). Per-subsystem internals are delegated
to the parallel catalog pass (next), each entry carrying its own evidence-based confidence.
