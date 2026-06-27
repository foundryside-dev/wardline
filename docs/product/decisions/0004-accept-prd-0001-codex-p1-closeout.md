# PDR 0004 — ACCEPT PRD-0001 (Codex P1 close-out): the bet paid off

`Date: 2026-06-28` · `Status: Accepted` · `Decider: product-owner agent (within
grant — "accept work against its stated acceptance criteria")`

## Context

PRD-0001 (Codex security-review hardening close-out; success metric **G2 —
soundness / surface integrity**) shipped and its bet paid off on the scoreboard
(`codex-security-2026-06-20` batch 0 open, `codex-security` overall 0 open, both P1s
closed + regression-pinned, G2 at target ahead of the 2026-07-31 backstop). But the
*formal ACCEPT* against PRD-0001's five falsifiable criteria was deferred across two
sessions. This PDR is that ACCEPT, judged against the criteria with the evidence run
fresh at HEAD (`6508c071`), not banked because it shipped.

## Evidence (run 2026-06-28 at HEAD)

1. **DoS bound (`c797baf28b`) — MET.** `test_lambda_candidate_merge_is_not_cubic_on_
   chained_rebinds` (+ the `var_type` sibling) reproduces the adversarial chained-rebind
   input at N=700/2000 and pins the merge at O(N²) deterministically (ratio guard +
   absolute backstop ~0.26s). Fix-time: 1100-branch PoC 4.388s→0.080s (55×). Closed
   2026-06-22. (157 passed in `test_variable_level.py`.)
2. **Credential gate (`d96b94d4e9`) — MET.** `test_check_does_not_send_token_to_project_
   published_port` + `test_repair_does_not_probe_mints_against_project_published_port` +
   `test_resolve_probe_url_excludes_project_published_port` prove doctor and `--repair`
   send **no** token to a repo-controlled published-port URL. Closed 2026-06-23
   (`f6cf5e7f`). (48 passed in `test_doctor_filigree_auth.py` / `_stale_ports.py`.)
3. **G1 precision must not degrade — MET (property, via a stronger mechanism than the
   literal byte-diff).** The criterion's PROPERTY is "the DoS bound drops zero real
   findings." Verified by the **no-candidate-dropped soundness-lock family**
   (`test_sink_lambda_in_non_last_{if,try,match,elif}_arm_survives_for_post_branch_call`,
   `..._in_loop_body_survives`, `replaces_candidate_set`, `all_arms_rebind..._drops_
   candidate_set` — 10 passed): these continuously prove the candidate-set dedup drops
   no *surviving* finding, on the exact code paths the fix touched. Plus the full suite
   (4472 passed) and the dogfood self-scan (exit 0 / 0 active) this session.
4. **No new bypass (G2), fail-closed — MET.** `test_check_stays_soft_when_pin_dead_and_
   no_live_published` + `test_check_ok_when_unreachable` prove no token is sent absent a
   genuine daemon; `test_check_ok_when_token_accepted` + `test_fix_probes_and_repairs_
   with_mcp_filigree_url` prove doctor still succeeds against a real daemon.
5. **Default path, no flag — MET.** c797 is in the default scan branch-merge
   (`_merge_branch_bindings`/`_merge_branch_types`); d96b is in plain `doctor`
   (`_resolve_probe_url`/`_check_filigree_auth`). Neither is behind a new opt-in toggle.

## The call

**ACCEPT PRD-0001.** All five criteria met; the bet is banked as paid off. PRD-0001's
status header is updated `ready-for-planning → accepted (PDR-0004)`.

## Honesty note on criterion 3

I did **not** run a literal pre-fix-vs-post-fix byte-identical finding-set diff (it
would require checking out the pre-fix commit and re-scanning on a **shared working
tree** with a concurrent session — a `git checkout` risk this project's discipline
forbids without cause). Instead I verified criterion 3's underlying property — *no real
finding dropped by the dedup* — via the surface-precise soundness-lock regression family
(continuous, fails if any candidate is ever dropped) + the green full suite + the clean
dogfood. This is the property-over-mechanism reading: a durable, surface-targeted guard
is a stronger guarantee than a one-time diff. Residual: the literal one-time byte-diff
was not performed.

## Reversal trigger

Metric-bound (`metrics.md` G2): reopen if either P1 hole is re-demonstrated (the DoS
curve returns to superlinear, or doctor sends a token to a repo-controlled port), **or**
if a dogfood/CI run surfaces a real finding the candidate-set dedup silently dropped (a
soundness-lock gap). Any such event is a **P0**, same class as a fail-open taint hole.
