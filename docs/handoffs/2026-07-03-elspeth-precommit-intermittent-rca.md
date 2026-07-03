# RCA: elspeth pre-commit "wardline silently swallows the first commit" — NOT a wardline failure

Date: 2026-07-03
From: wardline session (systematic-debugging pass over the fable-fixer bug report of 2026-07-03).
Re: intermittent first-commit failure with wardline named as the failing hook, clean scan
summary, no error line; identical retry passes.

## TL;DR

**wardline exited 0 in every observed occurrence.** The commit was rejected by
**pre-commit's own "files were modified by this hook" check**: pre-commit 4.6.0 snapshots
`git diff` before and after each hook and fails any hook whose execution window saw the
tracked-file diff change (`pre_commit/commands/run.py:203-235`). On a shared checkout with a
second agent session actively editing tracked files, the wardline hook — the **last** hook in
elspeth's chain, whole-tree (`pass_filenames: false`), **~15 s** vs ~1 s for every other
hook — is overwhelmingly the hook whose window absorbs the concurrent write, so it gets the
blame. Retry passes because the concurrent edit is by then already inside `diff_before`.

Reproduced in a sandbox: a slow `exit 0` hook + a background write to a *different tracked
file* 2 s into its run → hook marked `Failed`, `- files were modified by this hook`, **no
`- exit code:` line**, hook stdout (the clean summary) printed below; `pre-commit run --files`
exits 1; identical immediate rerun passes with the concurrent edit still uncommitted.

## Why the report's evidence already proves this

- **No `- exit code: N` line** in the failure block. pre-commit prints that line for every
  non-zero hook exit (`run.py:223-224`) — its absence means the hook exited **0**. The one
  way a 0-exit hook fails is the files-modified check (`run.py:208`).
- **The full scan summary printed.** wardline's summary echo sits *after* the
  `except WardlineError → error: … → SystemExit(2)` funnel (`cli/scan.py:520-522` vs `:614`),
  so no exit-2 path can ever print it. Summary present + no `error:` line ⇒ not exit 2.
- **Findings byte-identical across failed and passing runs** — the scan itself was identical.
- `.wardline/` is untracked/gitignored and `_get_diff()` is a tracked-file `git diff`
  (`run.py:274-279`), so — as the report correctly inferred — wardline's own writes are
  invisible to the check. What the report missed is that the **other session's tracked-file
  writes** during the 15 s window are exactly what the check sees.
- The `- files were modified by this hook` header line *was* almost certainly in the output,
  a few lines above the summary — the capture was `tail`-truncated.

## Verdicts on the report's four requests (3-agent source audit, file:line evidence)

1. **"Never exit non-zero silently" — already true.** The scan command has exactly two exit
   sites: `SystemExit(1)` (always preceded by `gate: FAILED …` + `gate: evaluated …` on
   stderr) and the `SystemExit(2)` funnel (always preceded by `error: <exc>` on stderr;
   stdout empty). No silent exit-2 path exists. Caveat: all exit-2 messaging is stderr-only,
   and crashes/Ctrl-C exit **1** (traceback / `Aborted!`), not 2.
2. **Gate verdict trailer — real gap, now FIXED (wardline-eef3d30c7d).** A clean armed pass
   printed no verdict at all. `wardline scan --fail-on <SEV>` now ends with
   `gate: PASSED (--fail-on <SEV>) — <reason>` + `gate: evaluated <population>` on stderr.
   The next such pre-commit failure is self-diagnosing from its captured tail: wardline says
   PASSED, the hook still Failed ⇒ look at the harness, not the scanner.
3. **Torn-read hardening — already implemented, stronger than requested.** Per-file isolation
   catches `OSError`/`SyntaxError`/`UnicodeDecodeError` (`scanner/pipeline.py:129-231`) and
   emits a **gate-eligible** `WLN-ENGINE-PARSE-ERROR` (ERROR/DEFECT) — fail-closed, named,
   never a whole-scan abort. A real torn read under `--fail-on ERROR` would have been a
   *loud exit-1 trip naming the file*, which is not what was observed — further
   disconfirming hypothesis 1.
4. **Sibling-publish escalation — cannot happen.** The scan CLI builds the Filigree emitter
   with `protocol_errors_loud=False` (unreachable/4xx/5xx/malformed → warning + local-only
   fallback, `filigree_emit.py:856-941`); the Loomweave write is doubly fail-soft
   (`cli/scan.py:493`, `loomweave/client.py:236-247`); legis makes **no network call**
   during scan. The only publish-adjacent exit-2 is a *pre-network* misconfiguration
   (non-http(s)/malformed `--filigree-url`), which prints `error: …` first.

## Recommendations for elspeth

- **The race is structural, not wardline's**: pre-commit cannot distinguish hook writes from
  external writes, and there is no per-hook opt-out of the check. While two sessions commit
  concurrently in one checkout, *any* hook can absorb the blame — wardline just has the
  biggest window. The reliable fixes are: don't run a whole-tree 15 s scan per commit
  (elspeth's own config header already says whole-repo gates belong to CI — the wardline
  hook contradicts it), or serialize commits across sessions, or keep the verified
  retry-once workaround.
- The hook is currently INERT on elspeth (0 recognized trust boundaries) — it blocks commits
  while enforcing nothing. Either arm it (declare boundaries / pack-bridge, see
  wardline-bd9d1e65cb) or move it to CI until armed.
- The "retry the commit once" institutional memory can now be retired in favour of:
  *check the failing hook block for `- files were modified by this hook` and the new
  `gate: PASSED` trailer; if both present, the commit was rejected by pre-commit's
  concurrent-write check — retry is safe.*
