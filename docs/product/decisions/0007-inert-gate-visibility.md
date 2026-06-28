# PDR 0007 — Surface the INERT taint gate (Python enforcement-posture visibility)

`Date: 2026-06-28` · `Status: Accepted` · `Decider: product-owner agent (within grant —
owner-directed dogfood investigation; reversible visibility feature, local commit, no release)`

## Context

Owner-directed: investigate the `~/elspeth/` dogfood report. A sibling agent had armed a
`wardline scan . --fail-on ERROR` pre-commit gate on elspeth (a FastAPI app) and diagnosed
its inertness as a missing `blake3` / `wardline[loomweave]` extra. The investigation
**disproved that** (blake3 is imported only in the loomweave/explain/dossier/attest/rust
*write* paths, never in `scanner/taint`; the corpus fires 23 ERROR defects with blake3 import
**blocked**) and established the real cause: **wardline is annotation-driven** — a PY-WL defect
fires only when untrusted data crosses a *declared* trust tier (`@trusted` / `@external_boundary`
/ `@trust_boundary`). An unannotated codebase produces **zero** defects no matter what it does,
so `--fail-on ERROR` over it passes **green while checking nothing**. The only prior signal was
buried INFO-severity `WLN-L3-LOW-RESOLUTION` — exactly the severity an agent filters out.

This is a direct **thesis / G3** false-assurance gap: "works first time" silently became
"checks nothing," and the agent commits that green as the premise of its next decision — the
same confident-empty blast-radius class as the seam-honesty Now bet, but on the core gate.

## Options

- **(a) Do nothing — rely on the existing INFO `WLN-L3-LOW-RESOLUTION` findings.** *Rejected:*
  agents filter INFO; the false-green stays invisible (the elspeth agent saw those findings and
  still misdiagnosed).
- **(b) Make an inert scan a hard gate failure, always.** *Rejected:* breaks CI on
  legitimately-unannotated / pure-logic repos — cry-wolf, a G1 precision-fatigue regression.
- **(c) Always-on structured `resolution.inert` field + a RELIANCE-GATED loud banner.** *Chosen.*

## The call

Ship Part A (commit `b3d0a81e`). `core/resolution_posture.py` computes inertness from the
engine's **existing** `WLN-ENGINE-METRICS` finding (`taint_source_counts.anchored`/`config` =
recognized boundaries; histogram sum = functions) — **no engine change, golden intact**.
`resolution.inert` is **always emitted** in the agent-summary + MCP scan output (MCP schema
golden deliberately re-frozen). The loud stderr banner is **reliance-gated**: it fires only
when a severity gate was armed (`--fail-on`) and **passed** while inert — the exact
false-assurance case — so bare/dogfood scans stay quiet (they already print `gate:
NOT_EVALUATED`). It is the Python counterpart of wardline's existing **Rust** empty-trust-surface
warning. Calibrated live: elspeth → `inert=True`; wardline corpus (anchored=43) → `inert=False`.
Full suite **4449 passed**, ruff/mypy clean. Tracker `wardline-bd9d1e65cb`.

## Rationale

Closes the false-assurance gap **honestly without crying wolf**. Reliance-gating (warn only
when someone is *trusting* the gate) resolves the pure-logic-library fatigue risk — verified:
a bare scan of wardline's own `core` (485 fns, zero boundaries) is silent; only an *armed* gate
over it warns. Within grant: reversible visibility feature, local commit, no release.

## Reversal trigger

Metric-bound, tied to `metrics.md` **G1 (precision)** and **G3 (zero-config)**:
1. **False inert.** If the banner ever fires on a scan that *does* recognize boundaries
   (`recognized_boundaries > 0`), that is a G1-class precision regression — revisit the
   discriminator. (P1.)
2. **Too narrow.** If agents are observed reading a *bare*-scan green as "enforced" despite the
   `NOT_EVALUATED` line, widen the banner beyond the reliance gate.
3. **Redundancy.** If a future `doctor` engine self-test (Part B) subsumes this, consolidate the
   two surfaces rather than carry both.
