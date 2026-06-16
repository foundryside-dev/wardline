# Wardline rename: Clarion→Loomweave, Loom→Weft (2026-06-05)

**Status:** DONE 2026-06-06 (uncommitted). Lockstep with the federation-wide rebrand
(`~/weft` hub + `~/clarion` engine, mid-flight 2026-06-05). This doc is the
**authoritative substitution table** and the brief every editor (human or subagent)
followed.

**Verification at completion:** residual grep `clarion`=0 / stray-`loom`=0 (outside the
intentional keeps below); full suite **2406 passed** (12 live-oracle deselected); `ruff`
+ `mypy` clean; `mkdocs build --strict` clean; CLI exposes `--loomweave-url`. Physical
renames also covered the missed `packages/loom-markers/`→`packages/weft-markers/`
(python pkg `loom_markers`→`weft_markers`) and 2 test files; golden identity corpus
regenerated (only `content_hash` + provenance changed — no identity/structure drift).

**Intentional keeps (still carry old names, by design):** `.claude/` + `.agents/`
filigree-workflow skill files (tool-managed by `filigree init`); all of
`docs/superpowers/**` and `docs/**/archive/**` (historical working records); the audit
files. The wire carve-outs `/api/wardline/*`, `/api/v1/*`, the `sei` key, and the token
`wardline` are unchanged on purpose.

**Engine-lockstep assumptions baked in:** the engine ships a `loomweave` binary
(`shutil.which("loomweave")`, `WARDLINE_LOOMWEAVE_BIN`); serves `/api/weft/*` (renamed
from `/api/loom/*`), `X-Weft-*` headers (renamed from `X-Loom-*`), HMAC value prefix
`loomweave:`, and SEI token `loomweave:eid:`. If any of these differ on the engine when
it lands, reconcile here.

## Why now

The engine (formerly Clarion, now **Loomweave**) and the federation (formerly
Loom, now **Weft**) have moved their *code*, not just their docs:

- engine source: `loomweave:eid:` ×98, `clarion:eid:` ×0; HMAC
  `strip_prefix("loomweave:")`; crates `loomweave-*`; on-disk `.loomweave/loomweave.db`,
  `loomweave.yaml`; repo `foundryside-dev/loomweave`.
- federation decision (2026-06-05): rename the **whole wire layer** `loom→weft`
  (`/api/loom/*`→`/api/weft/*`, `X-Loom-*`→`X-Weft-*`), the cross-product key
  `clarion_entity_id`→`loomweave_entity_id`, and error-code prefix `CLA-`→`LMWV-`
  (the last does **not** appear in Wardline).

The hub *docs* (`sei-standard.md` "LOCKED", `contracts.md` "clarion:eid:") **lag the
code**; the code is the target. If Wardline does not move in lockstep now, it is
stuck on dead names.

## Ordering hazard (MUST follow)

`Loomweave` *contains* the substring "Loom". Apply the passes in this order so a
`loom→weft` pass never corrupts a freshly-introduced `Loomweave`:

1. **Pass 1 — `loom`/`Loom` → `weft`/`Weft`** (today no "loomweave" token exists in
   Wardline, so every "loom" is the federation brand — safe).
2. **Pass 2 — `clarion`/`Clarion` → `loomweave`/`Loomweave`** (introduces "loomweave";
   Pass 1 is already done, so nothing re-runs over it).

Preserve case: `Loom`→`Weft`, `loom`→`weft`, `LOOM`→`WEFT`; `Clarion`→`Loomweave`,
`clarion`→`loomweave`, `CLARION`→`LOOMWEAVE`.

## Pass 1 — loom → weft

| From | To | Notes |
|---|---|---|
| `loom_dossier` (file/symbol) | `weft_dossier` | `src/wardline/loom_dossier.py` → `weft_dossier.py` |
| `loom_decorator_coverage` | `weft_decorator_coverage` | file + symbols |
| `build_loom_dossier` | `build_weft_dossier` | |
| `LoomDossier` | `WeftDossier` | |
| `_LOOM_MARKER` | `_WEFT_MARKER` | `core/filigree_issue.py:26` |
| `/api/loom/` (incl. `/api/loom/scan-results`) | `/api/weft/` | Filigree intake route — 64 sites |
| `X-Loom-Component` | `X-Weft-Component` | HMAC header name |
| `X-Loom-Timestamp` / `X-Loom-Nonce` | `X-Weft-Timestamp` / `X-Weft-Nonce` | if present |
| `X-Wardline-Timestamp` | `X-Weft-Timestamp` | unify the timestamp header to the weft wire |
| `loom_markers` | `weft_markers` | decorator-source namespace (`doctor.py:188`) — **cross-product string; must match engine** |
| `loom-mkdocs.css` | `weft-mkdocs.css` | + nav refs |
| "Loom Federation" / "Loom integration" / "Loom" (prose) | "Weft" / "Weft" | docs/guides/comments |
| `guides/loom.md` | `guides/weft.md` | + mkdocs nav label |

## Pass 2 — clarion → loomweave

| From | To | Notes |
|---|---|---|
| `wardline.clarion` (import path) | `wardline.loomweave` | dir `src/wardline/clarion/` → `loomweave/` |
| `ClarionClient` | `LoomweaveClient` | |
| `ClarionError` | `LoomweaveError` | |
| `ClarionBindingProvider` | `LoomweaveBindingProvider` | |
| `ClarionLinkageProvider` | `LoomweaveLinkageProvider` | |
| `clarion_client` / `clarion_url` (vars/params) | `loomweave_client` / `loomweave_url` | |
| `_detect_clarion` / `_clarion_url_from_config` / `load_clarion_token` | `_detect_loomweave` / `_loomweave_url_from_config` / `load_loomweave_token` | |
| `--clarion-url` (CLI flag) | `--loomweave-url` | no back-compat alias (pre-1.0) |
| `WARDLINE_CLARION_BIN` / `WARDLINE_CLARION_URL` | `WARDLINE_LOOMWEAVE_BIN` / `WARDLINE_LOOMWEAVE_URL` | |
| `clarion_e2e` (pytest marker) | `loomweave_e2e` | pyproject + ci.yml |
| `clarion = ["blake3..."]` (extra) | `loomweave = [...]` | pyproject; `wardline[clarion]`→`wardline[loomweave]` in docs |
| `clarion.yaml` | `loomweave.yaml` | engine reads `loomweave.yaml` now |
| `.clarion/` (dir refs) | `.loomweave/` | engine writes `.loomweave/loomweave.db` |
| `shutil.which("clarion")` | `shutil.which("loomweave")` | engine binary renamed (lockstep) |
| `clarion:eid:` | `loomweave:eid:` | SEI token prefix — incl. the `startswith` classify in `core/filigree_issue.py` |
| `f"clarion:{sig}"` (HMAC value prefix) | `f"loomweave:{sig}"` | `clarion/client.py:166` |
| `clarion_entity_id` (JSON key) | `loomweave_entity_id` | `filigree/dossier_client.py` deserialization |
| `tachyon-beep/clarion` | `foundryside-dev/loomweave` | repo URL |
| "Clarion ADR-0xx" / "Clarion" (prose) | "Loomweave ADR-0xx" / "Loomweave" | |

## CARVE-OUTS — do NOT rename

- `/api/wardline/*`, `/api/v1/*`, `/api/v1/_capabilities`, `/api/v1/identity/*` —
  `wardline` and `v1` are brand-neutral; these route names are **unchanged**.
- The `sei` capability key and `sei` field names — unchanged.
- The token `wardline` everywhere (product keeps its name).
- Any "loom" substring inside `loomweave` (avoided by pass ordering).

## Scope boundary

- **In scope (files + content):** all `src/**` and `tests/**` (non-archive);
  user-facing docs — `docs/guides/**`, `docs/reference/**`, `docs/integration/**`,
  `docs/decisions/**`, `docs/index.md`, `docs/stylesheets/**`; top-level
  `README.md`, `CHANGELOG.md`, `CONTRIBUTING.md`, `ROADMAP.md`; config/CI —
  `pyproject.toml`, `mkdocs.yml`, `.github/workflows/ci.yml`, `clarion.yaml`;
  skill `SKILL.md` files.
- **Out of scope (historical/working records, left as-is):** `docs/**/archive/**`,
  all of `docs/superpowers/**` (working specs/plans + progress tracker — internal
  design history, cross-linked by exact name), and point-in-time audit files
  (`wardline-readonly-audit-*.md`, `docs/audits/2026-06-08-comprehensive-audit.md`). Renaming these rewrites the record
  for no live value and risks cross-link breakage.

## Deferred (NOT a rename — flagged, not done here)

The HMAC **signing contract** has diverged beyond branding: the engine's current
`canonical_hmac_message` is `METHOD\nPATH\nsha256(body)\nTS\nNONCE` with a replay
nonce, whereas Wardline signs `METHOD\nPATH\nTS\nsha256(body)` with no nonce. This
pass renames the header/prefix strings only. Bringing Wardline's signer to the
engine's canonical order + nonce is a **separate wire-protocol resync** (the engine
side is itself still in flux). Until then, authenticated/write-enabled `/api/weft/`
+ `/api/wardline/*` calls will still fail auth; default no-secret read deployments
are unaffected.

## Verification gate

`ruff check` + `mypy` clean; full `pytest` (excl. live oracles) green; residual grep
finds zero `clarion`/`Clarion` and zero stray `loom`/`Loom` outside `docs/**/archive/**`
(and the legit `/api/wardline` / `wardline` keeps). Wire targets present:
`X-Weft-Component`, `loomweave:`, `loomweave:eid:`, `/api/weft/`, `loomweave_entity_id`.
