# PRD-0001 — Codex P1 close-out            Status: ready-for-planning
Decision: PDR-0001   Bet (roadmap.md): Now   Target metric (metrics.md): G2 — soundness / surface integrity

## Problem

**Who** — the 1–2 developer team running Wardline in their agent's edit-verify
loop and in CI, and the operator who runs `wardline doctor` to set integrations
up. They point Wardline at code they did not write — that is the whole job.

**The problem (their pain)** — two confirmed findings let an *untrusted
repository under analysis* subvert the analyzer itself. (1) A single
attacker-crafted Python file (≈1100 one-armed branches) drives the lambda
candidate-set merge to O(N³) — ~15s and climbing — and this is on the **default
`wardline scan --fail-on` gate**, no opt-in. The gate of record becomes a denial
of service on every local and CI run. (2) `wardline doctor` reads a
repo-controlled `.weft/filigree/ephemeral.port` and sends the operator's
Filigree federation **bearer token** to whatever loopback port the repo names;
under `--repair` it also probes the cross-project home mint
`~/.config/filigree/federation_token`. The tool whose purpose is to make
untrusted input safe is itself turned by untrusted input — a breach of Wardline's
own trust boundary.

**Desired outcome** — scanning or doctoring a hostile repository is safe:
analysis completes in bounded time regardless of input shape, and no credential
is disclosed to an endpoint that has not proven it is a genuine Filigree daemon.
No fail-open, no false green, no token leak.

**Why now** — an external Codex security review surfaced 26 findings; the
2026-06-22 deep triage (52 agents, adversarially verified) confirmed these are
the **only two** that breach the default gate or expose a credential — while 23
others are scoped to opt-in or preview surfaces and 2 were already fixed. Closing
this breach class is the precondition for declaring the hardening campaign sound
and opening the next (MCP-primary) front. Both fixes are size-S.

## Success metric (the signal the bet paid off)

**G2 — soundness / surface integrity** (`metrics.md`): *zero known fail-open or
policy-bypass holes on the agent surface.* This bet moves the P1 slice of that
guardrail.
- BASELINE (2026-06-22): 2 confirmed default-gate-reachable / credential-exposure
  holes open (`c797baf28b`, `d96b94d4e9`).
- TARGET: **0** such holes — both resolved and regression-pinned — within the
  campaign window (`metrics.md` G2 backstop: 2026-07-31).
- Falsification: if either P1 hole remains demonstrable at the window close, the
  bet has not paid off.

## Acceptance criteria (falsifiable)

1. **SUCCESS — DoS bound (`c797baf28b`).** A regression test that reproduces the
   adversarial input (N one-armed lambda branches) **fails on pre-fix code and
   passes on the fix**, and analysis of that input completes within a committed,
   deterministic time/space bound (no superlinear blow-up), merged to `main`
   within 7 days of the close-out PR opening.
   *Reject branch:* no such test, or analysis still superlinear at the window
   close → bet rejected for this finding; open follow-up PDR.
2. **SUCCESS — credential gate (`d96b94d4e9`).** `wardline doctor` (and
   `--repair`) sends **no** Filigree token to a loopback endpoint sourced solely
   from a repo-controlled port file; a test proves the pre-fix leak and its
   absence post-fix, merged within 7 days of the close-out PR opening.
   *Reject branch:* token still reaches a non-provenanced endpoint → rejected.
3. **GUARDRAIL — precision (G1) must not degrade.** The DoS bound drops **zero**
   real findings: Wardline's full suite **and** a dogfood scan of its own source
   yield a byte-identical active-finding set before vs. after, over the same
   window.
   *Reject branch:* any active finding lost, or any new false-negative → bet
   rejected **even if (1) passes**; the bound is redesigned.
4. **GUARDRAIL — no new bypass (G2).** The doctor provenance gate is
   fail-**closed** and introduces no regression: with no genuine daemon present,
   no token is sent anywhere; with a genuine daemon present, doctor still
   succeeds. Verified over the same window.
   *Reject branch:* token sent to an unverified endpoint, OR doctor breaks
   against a real daemon → rejected.
5. **SCOPE — default path, no flag.** Both fixes are always-on on the default
   surfaces (c797 in the default scan, d96b in plain `doctor`) — not behind an
   opt-in toggle — at merge.
   *Reject branch:* either fix gated to a subset/flag → this criterion is unmet.

## Non-goals (this bet)

- The remaining **21 P3** Codex findings (their own batches B2–B6; tagged
  `codex-triage-2026-06-22`).
- **B7 / `c852f6d8b5`** — the outward-facing site-kit CI pin. Escalated and
  **gated** for owner confirmation; explicitly out of this bet.
- Any new capability, rule, or surface — this is a hardening close-out, not a
  feature.
- Broad refactor of the `doctor` / scan-merge subsystems beyond the two fixes.
- **Secondary (non-gating):** `4e664591e6` (P2) and `044a260b6a` (P3) may ride
  the same PRs if they fit without scope growth; if not, they fall back to their
  own queue. They do **not** gate this bet's acceptance.

## Constraints & guardrails

- **G1 precision floor** and **G2 no-new-bypass** are hard (criteria 3–4).
- **G4 weight:** fix within the stdlib — no new runtime dependency.
- **G3 zero-config:** the doctor provenance gate must require **no new human
  configuration**; it activates by default.
- **Determinism:** the c797 bound must be deterministic — no flaky/time-based
  threshold that varies by host.
- **Fix at the boundary**, per the `wardline-gate` discipline — bound the
  algorithm / gate the credential at the trust boundary, not by masking the sink.

## Open questions / assumptions

- **Measurement instrument.** G2's "0 known holes" is asserted by the re-triage +
  adversarial-verify pass and the regression tests, not by live telemetry — which
  is the appropriate instrument for a security-hardening bet. The north-star
  (agent-fix success) is not yet instrumented; this bet is judged on guardrails by
  design. *If wrong:* if the owner wants a continuous surface-integrity metric,
  that must be added to `metrics.md` first.
- **c797 bound mechanism** (hard cap on candidate-set size vs. an O(N) merge
  rewrite) is a **design** choice → `/axiom-solution-architect`. Assumption: a
  bound exists that preserves every real finding (criterion 3); if no such bound
  does, the finding-model itself needs rework — a bigger bet.
- **d96b provenance mechanism** (how a loopback endpoint *proves* it is the real
  Filigree daemon — registry/identity handshake vs. refuse-and-fail-closed) → 
  `/axiom-solution-architect`. Assumption: fail-closed (send nothing) is always an
  acceptable floor.
- Triage confirmed both P1s are present at HEAD `09eae7a2`; assumes no in-flight
  branch already fixes them.

## Handoff

- **Top item → `/axiom-planning`:** the **c797 DoS bound** (`wardline-c797baf28b`)
  — the only default-gate breach, highest blast radius, size-S. Turn into an
  executable, codebase-validated implementation plan first.
- **Solution shape → `/axiom-solution-architect`:** the **d96b daemon-provenance
  gate** (authenticate the loopback Filigree daemon before sending a token) and
  the **c797 bound mechanism** (cap vs. O(N) merge). The PRD names the constraints;
  the design is theirs.
- **Tracker IDs:** `wardline-c797baf28b` (P1), `wardline-d96b94d4e9` (P1),
  `wardline-4e664591e6` (P2, secondary), `wardline-044a260b6a` (P3, secondary).
  Decision: PDR-0001. Batches B1 / B5 in `docs/product/codex-triage-2026-06-22.md`.
- **Forecast/sequencing → `/axiom-program-management`.** No delivery date is set
  here; the dated commitment comes from its forecast.
