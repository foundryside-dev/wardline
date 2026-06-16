# Fingerprint rekey — index & spine

> Move-stable finding identity: drop `line_start` from the fingerprint, give every
> multi-emit rule a source-derived move-stable discriminator, stamp the scheme so a
> half-migrated store loud-fails, and ship a one-shot scan-driven `wardline rekey`.
> **Architecture is decided — every phase is "do this," not "choose one."**
>
> Tracking: residual of `weft-4a9d0f863c` (resolved); panel `panel-2026-06-09`.
> Tickets: `wardline-8fb773a7af` (P2 = finalizer), `wardline-8654423823` (P3 =
> discriminator redesign), `wardline-6102d4c833` (broad/silent fix, folded into P3),
> migration `weft-e618c4118a` (WL-1). All work on the single `rc4` branch.

## The problem in one picture

`src/wardline/core/finding.py:154-165`:

```python
def compute_finding_fingerprint(*, rule_id, path, line_start, qualname=None, taint_path=None) -> str:
    parts = (rule_id, path, str(line_start), qualname or "", taint_path or "")   # <-- line_start is IN the key
    return hashlib.sha256("\x00".join(parts).encode()).hexdigest()
```

Insert a benign comment above a sink → `str(line_start)` `2`→`3` → the 64-hex value
changes. All four stores (`baseline.py` frozenset, `judged.py` `_by_fp`, `waivers.py`
`_by_fp`, `filigree_emit.py` wire) join on the bare hex and store **none** of the
inputs → the old verdict orphans and the finding resurfaces ACTIVE, trips the gate,
mints a Filigree dup.

## The fix in one picture

```python
FINGERPRINT_SCHEME = "wlfp2"   # scheme-infra (P1) ships "wlfp1" first (format-only)
def compute_finding_fingerprint(*, rule_id, path, qualname=None, taint_path=None) -> str:
    parts = (rule_id, path, qualname or "", taint_path or "")   # line_start GONE
    return hashlib.sha256("\x00".join(parts).encode()).hexdigest()
```

Multi-emit discriminator in `taint_path`: singletons → `None`; multi-emit →
`f"{rel_line}:{col_offset}:{end_col_offset}:{callee_or_token}"` where
`rel_line = node.lineno - entity.location.line_start` (CPython byte offsets). PY-WL-114
keeps its `#{ordinal}`. `line_start` stays on `Finding.location` for SARIF region / display.

## The spine (THE one true order)

| # | Phase | file | rekey-impact | corpus_version | scheme persisted |
|---|-------|------|--------------|----------------|------------------|
| P1 | scheme-infra | `…-01-scheme-stamp-infra.md` | format-only | 2 → 3 | `wlfp1` (OLD line_start-in formula) |
| P2 | finalizer guard | `…-02-collision-finalizer.md` | none | unchanged | — |
| P3 | rules-discriminator (THE value-rekey) | `…-03-drop-linestart-discriminator.md` | value-rekey | 3 → 4 | `wlfp2` |
| P4 | migration (`wardline rekey`) | `…-04-scan-driven-migration.md` | value-rekey (operator) | — | from=`wlfp1`, to=`wlfp2` |
| P5 | rust worktree reconciliation | `…-05-rust-worktree-reconciliation.md` | n/a (NOT rc4) | — | inherits |

**Inviolable constraints:**
- **P2 strictly before P3** — the collision finalizer is the tripwire that must exist *before* `line_start` leaves the hash, or a discriminator bug collapses silently in `baseline.py` `setdefault`.
- **P1 before P4** — migration's loud-miss safety consumes P1's `SchemeMismatchError`.
- **P3 before P4** — migration reads `new_fp` (P3's engine output) and the v0 discriminator component P3 exposes.
- **P1 scheme label MUST differ from P3 scheme label** (`wlfp1` ≠ `wlfp2`). The single decision that makes the loud-fail primitive work: a store written between P1 and P3 must `SCHEME_MISMATCH` after P3. Same label → stale old-formula value loads clean → mass orphan.

## Verification (after EACH phase)
- Full suite (~2625) green.
- Identity oracle **byte-green on BOTH 3.12 and 3.13** (`compute_finding_fingerprint_v0` lives in its own module, never called by production).
- `ruff` + `mypy` clean.

## Tracker hygiene (Filigree — `blocks`/`blocked_by` only; no `guarded-by`)
- `wardline-8654423823` priority 3 → 2; label `panel-2026-06-09`.
- `wardline-6102d4c833 blocked_by wardline-8fb773a7af` (latent fix needs the tripwire).
- `wardline-8654423823 blocked_by wardline-8fb773a7af` (redesign needs the tripwire).
- `wardline-6102d4c833 blocked_by wardline-8654423823` (latent fix needs the redesign).

## Start here
Open `tests/unit/core/test_fingerprint_scheme.py` (create) + `src/wardline/core/finding.py`.
**P1 / S1** — add `FINGERPRINT_SCHEME = "wlfp1"` + `format_fingerprint`/`parse_fingerprint`,
hash UNTOUCHED. Format-only, byte-safe, lays the loud-fail floor. → `…-01-scheme-stamp-infra.md`.
