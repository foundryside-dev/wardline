# PDR-0010: Scan-pipeline extras self-include scanner (fix uv-tool install-friction)

Date: 2026-06-29
Status: accepted
Author: agent:claude (engineering session; recorded at /product-checkpoint)
Owner sign-off: autonomous within grant — a repo-local, reversible defect fix on the
install surface (the grant authorizes accept/dispatch of reversible repo-local work).
Committed + pushed on `release/consolidation-2026-06-26` (PR #69). Reaching users via a
**PyPI publish is owner-gated** and is NOT performed here.
Related: `vision.md` thesis invariant #1 (plug-and-play install); G4 (extras/weight
discipline) + G3 (zero-config activation) in `metrics.md`; tracker `wardline-c8d7e020e8`
(filed + closed this session); PDR-0007/0008 (the elspeth dogfood that surfaced
install-surface friction).

## Context

A dogfood report from `~/elspeth` (installed wardline 1.0.7, uv-tool install) hit an
install whack-a-mole: `uv tool install wardline[loomweave]` *uninstalled* the scanner deps
(pyyaml/jsonschema/click) and installed only blake3, so `wardline init`/`scan` then errored
"requires the scanner extra"; reinstalling scanner dropped blake3 again. Root cause: `uv
tool install` REPLACES the tool env with exactly the named extras (it does not merge), and
`loomweave = ["blake3>=1.0"]` was not self-sufficient — unlike the `rust` extra, which
already self-includes `wardline[scanner]` for exactly this reason. This breaks thesis
invariant #1 ("install it and it stands itself up"): installing a capability extra broke
the tool.

## Options considered

1. **Guidance only** — tell users to combine extras (`wardline[scanner,loomweave]`).
   Rejected: pushes the uv-tool gotcha onto every user; the single-extra install (the
   natural action, and what the doctor hint advised) stays broken.
2. **Make scan-pipeline extras self-sufficient** (CHOSEN) — `loomweave` self-includes
   `wardline[scanner]`, mirroring `rust`; a single-extra install carries its prerequisites.
3. **Collapse loomweave into base/scanner** — rejected: violates G4 (capability stays
   behind opt-in extras) and the zero-dep base.

## The call

**Make scan-pipeline extras self-sufficient.** `loomweave = ["wardline[scanner]",
"blake3>=1.0"]` (loomweave's taint-store writes fire only during `wardline scan`, so it
genuinely needs the pipeline; there is no loomweave-without-scanner path — the CLI refuses
to start without scanner). Plus a shared `extra_install_hint(extra)` naming both installers
(`uv tool install` vs `pip install`, since pip targets the wrong env for a uv-tool install)
across every extra hint, and a regression guard (`test_extras_composition.py`) pinning the
self-sufficiency invariant. Verified: built-wheel METADATA resolves `loomweave →
blake3+click+jsonschema+pyyaml`; a single `[loomweave]` install now keeps scanner (no
whack-a-mole, confirmed live in the uv tool); 256 install+cli tests + layering conformance
green. Commits `87f13b0d` + `8c950e02`.

## Rationale

Serves invariant #1 directly — the install surface is part of "plug-and-play." The fix is
the established in-repo pattern (`rust`), keeps the base zero-dep and capability opt-in (G4
holds), and closes a previously **untested** invariant. Engineering-tracked in
`wardline-c8d7e020e8`; recorded as a product decision because the install surface is a
thesis-invariant-#1 concern, not incidental hygiene.

## Reversal trigger

Reopen the bundling decision if a legitimate consumer needs `wardline[loomweave]` WITHOUT
the scanner pipeline (none exists today), or if the extras-composition guard is ever
relaxed — watched under G4's per-release extras re-check (`metrics.md`). The
install-friction class itself reopens if a single-extra `uv tool install` whack-a-moles
again on any extra after this fix.
