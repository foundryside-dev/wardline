# Wardline Roadmap

Wardline is a lightweight, opt-in semantic-tainting analyzer for Python. This is
a direction sketch, not a commitment — dates are deliberately omitted.

## Where we are

**0.3.0 — shipped.** The staged build (SP0–SP9) is complete:

- Function-, variable-, and project-level taint over an inter-module call graph
  (L1–L2 with an L3 fixed point).
- The NG-25 trust vocabulary and three opt-in decorators.
- Four policy rules (PY-WL-101..104), severity/enable config, baselines + waivers.
- JSONL + SARIF + native Filigree emit.
- Dependency-free MCP-over-stdio server (`wardline mcp`).
- Opt-in LLM triage judge (`wardline judge`).
- `wardline install` agent enablement.
- Opt-in Clarion taint-store integration.
- Published to PyPI; docs site live; CI dogfoods Wardline on its own source.

## Scope

Wardline is deliberately **L1–L2 with an L3 project fixed point**, not an
exhaustive path-sensitive whole-program prover, and Python-only. We favor a
small, precise, opt-in rule set over broad SAST coverage.

## Near-term threads

Tracked in the project's Filigree issues:

- **N-hop `explain_taint` chain completeness** — full boundary-chain reconstruction
  on the explain surface (`wardline-82f49ec3c3`).
- **Return-indirection in `compute_return_callee`** — explain-surface completeness
  for returns routed through intermediates (`wardline-82f49ec3c3`).
- **Taint-combination hardening** — first-class hardening from the 2026-05-31
  audit (`wardline-2b138b3662`).
- **Star-import decorator markers** — resolve `from x import *` so trust markers
  are not missed (`wardline-2b427a9579`).

## Out of scope (for now)

- Languages other than Python.
- A general-purpose, dozens-of-rules SAST suite.
- A hosted/cloud service — Wardline stays local-first.
