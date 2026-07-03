# scan_manifest seam — BUILT + RELEASED (bless + closure handover)

Date: 2026-07-01
From: warpline session (the seam was built here at the owner's direction; this documents
the shipped result and the one hub-side act left).
Re: **AMBER-2 / `weft-9a35aa00e7`** — "Plainweave peer-facts dependency: Wardline must emit
a scan_manifest contract". **Now satisfied on both sides.**

## TL;DR — the half-built seam is closed

Plainweave's `wardline_adapter` reached for a `scan_manifest` record wardline never emitted,
so it degraded to a path-set heuristic (`wardline_scan_identity_absent`). Wardline now emits
it. **Producer and consumer are both committed and released** — the only thing left is the
governance step: **bless the contract hub-side and close the ticket.**

## What shipped

**Producer — wardline (DONE, released in `v1.2.0`):**
- `cli/scan.py` prepends a `scan_manifest` header line to the default
  `.wardline/<ts>-findings.jsonl` artifact (the glob plainweave reads), **unconditionally**
  (a clean zero-finding scan still carries coverage). Additive — the signed legis artifact /
  `scan_scope` is untouched; existing line-by-line finding readers ignore the unknown `kind`.
- `core/run.py` exposes `ScanResult.analyzed_paths` (the analyzed subset).
- Committed in `14030acb`, on `release/consolidation-2026-06-26`, **in tag `v1.2.0`**.
- Verified: real scan emits the exact shape; e2e (wardline scan → plainweave reads
  `covered_paths`, no degrade); 358-test regression green; ruff/mypy clean.

**Consumer — plainweave (DONE):** `wardline_adapter` consumes the real manifest; recent
commits `9ca6698` (guard ruleset-mismatch on both manifests) + `4782fd6` (green `make ci` +
wardline scan for wardline/warpline producers) show it reading real wardline output CI-green.

## The contract to bless hub-side — `weft.wardline.scan_manifest.v1`

Register this as the canonical federation contract so it can't drift (the same lesson as the
un-ratified requirements-enrichment schema). Emitted as the **first line** of
`.wardline/<ts>-findings.jsonl`:

```json
{"kind": "scan_manifest",
 "scope": {"covered_paths": ["<repo-relative posix path>", "..."]},
 "ruleset_id": "sha256:<hex>"}
```

Field semantics (the load-bearing part):
- **`covered_paths`** = the paths wardline actually **analyzed**, in the SAME repo-relative
  POSIX format as `Finding.location.path`. A now-absent prior finding reads **RESOLVED** only
  when its path is genuinely in this set. **Defaults to the ANALYZED set** so `--affected`
  delta mode does not over-claim coverage (a discovered-but-not-re-analyzed file stays
  *indeterminate*, not falsely resolved); `wardline scan --manifest-full-coverage` restores
  the full discovered inventory.
- **`ruleset_id`** = `ruleset_hash(config)` (`sha256:…`, == the legis `rule_set_version`) so
  the consumer can detect a ruleset change between two snapshots and NOT read a finding's
  disappearance under a different ruleset as a resolution.
- Producer: **wardline**. Consumer: **plainweave** (echo-only, advisory).

## The two acts left (owner / hub)

1. **Bless `weft.wardline.scan_manifest.v1`** as the canonical contract (register the shape +
   field semantics above hub-side), so wardline emission and plainweave consumption stay pinned.
2. **Close `weft-9a35aa00e7` / AMBER-2** — the producer-side gap it tracks no longer exists.
   Recommended final gate before closing: one end-to-end confirmation on the released code
   (real `wardline scan` → plainweave adapter reads `covered_paths`, `wardline_scan_identity_absent`
   does not fire) — plainweave's `make ci + wardline scan` commit indicates this already passes.

*Everything above is shipped; these two are governance/closure, not engineering.*
