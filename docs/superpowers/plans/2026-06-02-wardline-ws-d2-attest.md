# Workstream D2 — `attest`: signed, reproducible evidence bundle — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. **Build D1 (assure) first** — `attest` signs D1's posture.

**Goal:** Produce a signed, reproducible evidence bundle — "at commit X (clean/dirty), ruleset hash Y, the trust surface had this coverage and these boundaries held" — and a `verify` path that re-checks both the signature and the reproducibility, with the signing key **minted by `wardline install`** so it needs zero further config.

**Architecture:** A pure core module (`core/attest.py`) canonicalises the D1 posture + commit + ruleset hash into a deterministic bundle, signs it with HMAC-SHA256 over a stdlib key (no `wardline.clarion` import — base stays zero-dep). `wardline install` mints the project key into `.env` (mirroring Clarion's token convention) and ensures `.env` is gitignored. SEI-keying of boundaries is enrichment behind a lazy Clarion import (reusing the existing resolver seam — **no dependency on Workstream E**), with an honest qualname fallback. CLI (`wardline attest` / `--verify`) and the MCP `attest`/`verify_attestation` tools delegate to the same core — identical by construction.

**Tech Stack:** Python 3 stdlib (`hmac`, `hashlib`, `secrets`, `json`, `subprocess` for git), `click`. SEI enrichment via the optional `[clarion]` extra, lazy-imported.

---

## Design decisions (pinned BEFORE code — read first)

### Threat model — what the signature actually proves (do NOT overclaim)

HMAC-SHA256 with a **shared project key** gives **tamper-evidence within a trust domain** (CI, a team sharing the key): a holder of the key can confirm the bundle was produced by a key-holder and not altered. It is **NOT** public, third-party, non-repudiable proof — anyone with the key can forge, and verification *requires possessing the key*. Asymmetric signing would prove more but needs a non-stdlib dependency, which the zero-dependency base forbids — so HMAC is **forced, not chosen**. The bundle, the CLI/MCP output, and the docs must say plainly: **"verification requires the shared project key; this is tamper-evidence, not public non-repudiation."** The issue's phrase "third-party-verifiable" is narrowed to "verifiable by any holder of the project key." Honesty here *is* the Wardline tenet — a bundle that implies asymmetric proof is a false-green.

### Key storage — mirror Clarion's token precedent (do not invent)

Clarion's HMAC secret (`clarion/config.load_clarion_token`) is read from env (`WARDLINE_CLARION_TOKEN`) or a `KEY=VALUE` line in `root/.env`. Attest follows the **same** pattern:
- New `core/attest_key.py` (base, stdlib): `load_attest_key(root) -> str | None` reading `WARDLINE_ATTEST_KEY` env then a `WARDLINE_ATTEST_KEY=` line in `root/.env`; `mint_attest_key(root) -> (key, status)` generating `secrets.token_hex(32)` and appending it to `.env` **iff** absent (idempotent), and ensuring `.env` is gitignored (append `.env` to `root/.gitignore` if a gitignore exists and doesn't already cover it; otherwise emit a warning line — never silently write a secret into a tracked file).
- A secret must **never** go in `.wardline/` (that dir holds committed state — `baseline.yaml`/`judged.yaml`). The D2 spec's "into `.wardline/`" is imprecise; the activation invariant ("install mints it, zero further config") is satisfied by minting into `.env`. Document this reconciliation in the guide.

`wardline install` calls `mint_attest_key(root)` as a new step (reported in its output, skippable with `--no-attest-key`). Activation, not configuration: the key exists after `install`, the user does nothing.

### What goes in the bundle + reproducibility

Bundle = a canonical JSON object (sorted keys, `separators=(",",":")`, sorted lists) with a top-level `payload` and a detached `signature`:

```json
{
  "schema": "wardline-attest-1",
  "payload": {
    "wardline_version": "0.1.0",
    "commit": "abc123…",            // git rev-parse HEAD, or null
    "dirty": false,                  // uncommitted changes present? (see below)
    "ruleset_hash": "sha256:…",      // deterministic hash of effective rules config
    "posture": { …D1 AssurancePosture.to_dict()… },
    "boundaries": [                  // the proven/defect/unknown boundaries, SEI-keyed when available
      {"qualname": "pkg.m.f", "sei": "clarion:eid:…"|null, "verdict": "clean", "tier": "INTEGRAL"}
    ],
    "sei_source": "clarion"|"unavailable"
  },
  "signature": {"alg": "HMAC-SHA256", "value": "…hex…", "key_id": "…short fp of the key…"}
}
```

- **`commit` / `dirty` (advisor constraint — no dirty false-green):** `commit` = `git rev-parse HEAD` (stripped) or `null` when not a git repo. `dirty` = `True` when `git status --porcelain` is non-empty. A dirty tree means "boundaries held at commit X" is **false** (X ≠ what was scanned), so `dirty: true` is recorded honestly and `attest` prints a loud warning; `--strict` (and the MCP default) **refuses** to attest a dirty tree (exit 2 / tool error) unless `--allow-dirty` is passed. Never silently attest a dirty tree as clean.
- **`ruleset_hash`:** deterministic `sha256` over the effective rule configuration — the sorted enabled-rule ids + their effective severities + the Wardline version. Same config → same hash; a severity/enable change moves it. (Compute from the loaded `Config`, not the raw YAML text, so formatting noise doesn't perturb it.)
- **`signature.value`:** HMAC-SHA256 of the **canonical bytes of `payload`** (the exact `json.dumps(payload, sort_keys=True, separators=(",",":")).encode()`), keyed on the project key. `key_id` = first 8 hex of `sha256(key)` so two bundles signed with different keys are distinguishable without revealing the key.

### SEI-keying without Workstream E (advisor-confirmed)

E is *input* addressing (tools accept `sei:` as a key). D2 needs *output* keying (resolve qualname→SEI to write into `boundaries`). The output seam already exists and is already wired with no E: `loom_dossier`/`clarion.dossier_sources.resolve_entity_binding(clarion_client, resolver, qualname)`. `attest` reuses it behind a **lazy** clarion import: with a reachable Clarion, each boundary's `sei` is the resolved opaque SEI and `sei_source: "clarion"`; with no Clarion (or it can't resolve), `sei: null` and `sei_source: "unavailable"` — a qualname-keyed bundle, honestly marked. **Base attest works with zero extras.**

### verify — two separable checks (advisor constraint)

`verify_attestation(bundle, key, *, root=None, reproduce=False)`:
1. **Signature check** (always; needs the key; no scan; offline): recompute HMAC over `bundle["payload"]` canonical bytes, constant-time compare. Pass/fail independent of the working tree.
2. **Reproducibility check** (only when `reproduce=True` and `root` given): re-run `build_posture` at the **current** tree, re-derive the boundaries/ruleset_hash, and compare to the recorded payload. State explicitly that reproducibility holds only against the **recorded commit** — if the tree has moved, a mismatch is "tree changed," not "tamper." Return a structured `{signature_valid, reproduced, mismatches:[…], note}` so the two outcomes are never conflated.

### Determinism

Canonical JSON (sorted keys + sorted `boundaries` by qualname) is a hard requirement — the bundle's own bytes are the signed material and the reproducibility target, and the suite runs under `pytest-randomly`.

---

## File Structure

- **Create** `src/wardline/core/attest_key.py` — `load_attest_key`, `mint_attest_key` (stdlib, base).
- **Create** `src/wardline/core/attest.py` — bundle build/sign/verify; `git` helpers; `ruleset_hash`; lazy SEI enrichment.
- **Modify** `src/wardline/install/detect.py` *(or new `install/keys.py`)* — `mint_attest_key` step.
- **Modify** `src/wardline/cli/install.py` — call the key-mint step (+ `--no-attest-key`).
- **Create** `src/wardline/cli/attest.py` — `wardline attest` / `wardline attest --verify <bundle.json>`.
- **Modify** `src/wardline/cli/main.py` — register `attest`.
- **Modify** `src/wardline/mcp/server.py` — `attest` + `verify_attestation` tools.
- **Modify** `tests/conformance/test_mcp_handshake.py` — add the two tools.
- **Create** tests: `tests/unit/core/test_attest_key.py`, `tests/unit/core/test_attest.py`, `tests/unit/cli/test_attest_cmd.py`, `tests/unit/cli/test_install_attest_key.py`, `tests/unit/mcp/test_server_attest.py`.
- **Docs**: `docs/guides/attestation.md` + nav + CHANGELOG.

---

## Task 1: `attest_key` — mint + load (mirror Clarion's token)

**Files:** Create `src/wardline/core/attest_key.py`; Test `tests/unit/core/test_attest_key.py`

- [ ] **Step 1: Failing tests.** `load_attest_key` returns the env value when set; falls back to the `WARDLINE_ATTEST_KEY=` line in `.env`; returns `None` when neither. `mint_attest_key`: creates `.env` with a 64-hex key when absent; is idempotent (a second call returns the same key, no duplicate line); ensures `.env` is in `.gitignore` (creates/append) — assert the gitignore contains `.env` after minting. (Use `monkeypatch.delenv`/`setenv` and a `tmp_path` root.)
- [ ] **Step 2: Run — expect FAIL.**
- [ ] **Step 3: Implement** `attest_key.py` (stdlib only: `os`, `secrets`, `pathlib`). `load_attest_key` mirrors `clarion/config.load_clarion_token` (env wins, then `.env` `KEY=VALUE` parse). `mint_attest_key(root)`: if `load_attest_key` already returns a key → `(key, "present")`; else generate `secrets.token_hex(32)`, append `WARDLINE_ATTEST_KEY="…"\n` to `.env` (create if needed), ensure `.env` gitignored (append to `root/.gitignore` if present and not covered; if no `.gitignore`, create one with `.env`), return `(key, "minted")`.
- [ ] **Step 4: Run — expect PASS.**
- [ ] **Step 5: Commit.** `git commit -am "feat(core): attest project key mint/load (.env, gitignored)"`

---

## Task 2: `wardline install` mints the key (activation invariant)

**Files:** Modify `src/wardline/install/detect.py` (or new `install/keys.py`), `src/wardline/cli/install.py`; Test `tests/unit/cli/test_install_attest_key.py`

- [ ] **Step 1: Failing test.** `wardline install --root tmp --no-claude-md --no-agents-md --no-skill --no-mcp --no-bindings` still mints the attest key (unless `--no-attest-key`): after the run, `load_attest_key(tmp)` is non-None and `.env` is gitignored. With `--no-attest-key`, no key is minted.
- [ ] **Step 2: Run — expect FAIL.**
- [ ] **Step 3: Implement.** Add a `mint_attest_key` step to `install` (its own `--no-attest-key` flag), reporting `attest key: minted|present` in the output. Keep it inside the existing `try/except WardlineError` block.
- [ ] **Step 4: Run — expect PASS**; `uv run wardline install --root <throwaway tmp>` by hand to eyeball output (use a temp dir — do NOT mutate the repo's own `.env`).
- [ ] **Step 5: Commit.** `git commit -am "feat(install): mint the attest project key (activation, not config)"`

---

## Task 3: bundle build + sign + git/ruleset helpers

**Files:** Create `src/wardline/core/attest.py`; Test `tests/unit/core/test_attest.py`

- [ ] **Step 1: Failing tests** (no SEI / no Clarion path first):
  - `ruleset_hash(config)` is deterministic and changes when a rule severity changes.
  - `git_state(root)` returns `(commit, dirty)` — test with a `tmp_path` git repo: a clean commit → `(sha, False)`; after an untracked/modified file → `dirty True`; a non-git dir → `(None, False)`.
  - `build_attestation(root, key, *, allow_dirty=True, today=PINNED)` on a clean tiny annotated repo returns a bundle whose `payload.posture` equals `build_posture(...).to_dict()`, `boundaries` is sorted by qualname with `sei: null` + `sei_source: "unavailable"`, and `signature.value` verifies.
  - **Reproducibility:** two `build_attestation` calls on the same unchanged tree produce **byte-identical** `payload` canonical bytes (pin via `json.dumps(..., sort_keys=True, separators=(",",":"))`).
  - **Dirty refusal:** `build_attestation(..., allow_dirty=False)` on a dirty tree raises a `WardlineError` (tool-execution fault).
- [ ] **Step 2: Run — expect FAIL.**
- [ ] **Step 3: Implement `core/attest.py`:**
  - `git_state(root)`: `subprocess.run(["git","rev-parse","HEAD"], cwd=root, ...)` and `["git","status","--porcelain"]`; tolerate non-git (FileNotFoundError / non-zero) → `(None, False)`. No network, no mutation.
  - `ruleset_hash(config)`: `sha256` over a canonical string of sorted `(rule_id, effective_severity)` pairs + wardline version; return `"sha256:<hex>"`.
  - `_sign(payload_obj, key)`: canonical bytes → `hmac.new(key.encode(), bytes, sha256).hexdigest()`; `key_id` = `sha256(key)[:8]`. (stdlib `hmac`/`hashlib` directly — do **not** import `wardline.clarion`.)
  - `build_attestation(root, key, *, config_path=None, clarion_client=None, allow_dirty=True, today=None)`: build posture, git state (refuse if dirty and not allowed), ruleset hash, boundaries (from posture's proven/defect/unknown — re-walk `declared_qualnames` with `classify_entity_trust`, or carry the per-entity list out of D1; SEI null unless `clarion_client`), assemble payload, sign, return the full bundle dict.
  - `verify_attestation(bundle, key, *, root=None, reproduce=False) -> dict`: signature check (constant-time `hmac.compare_digest`); optional reproducibility (re-derive payload at current tree, diff). Returns `{signature_valid, reproduced, mismatches, note}`.
- [ ] **Step 4: Run — expect PASS.**
- [ ] **Step 5: Commit.** `git commit -am "feat(core): attest bundle build/sign/verify (HMAC, reproducible, dirty-honest)"`

---

## Task 4: SEI enrichment (lazy clarion, no E dependency)

**Files:** Modify `src/wardline/core/attest.py`; Test add to `tests/unit/core/test_attest.py`

- [ ] **Step 1: Failing test.** With a **fake** clarion client (a test double exposing `capabilities`/`resolve`/`resolve_identity`/`resolve_sei` like `loom_dossier._ClarionClient`) that resolves a known qualname to a SEI, `build_attestation(..., clarion_client=fake)` sets that boundary's `sei` to the opaque value and `sei_source: "clarion"`. A client that raises/returns None → that boundary's `sei: null`, and `sei_source` stays `"clarion"` only if any resolved, else `"unavailable"` (define: `sei_source = "clarion"` when a client was supplied AND ≥1 SEI resolved, else `"unavailable"`).
- [ ] **Step 2: Run — expect FAIL.**
- [ ] **Step 3: Implement** the enrichment: when `clarion_client` is supplied, lazily `from wardline.clarion.dossier_sources import resolve_entity_binding` and `from wardline.clarion.identity import SeiResolver, SeiCapability`, build the resolver from `clarion_client.capabilities()`, resolve each boundary's qualname → binding.sei (fail-soft per boundary — a raise/None leaves `sei: null`). Never let an unreachable Clarion fail the attestation (it degrades to qualname-keyed).
- [ ] **Step 4: Run — expect PASS.**
- [ ] **Step 5: Commit.** `git commit -am "feat(core): attest SEI-keying via the existing resolver seam (no WS-E dep)"`

---

## Task 5: CLI `wardline attest` + `--verify`

**Files:** Create `src/wardline/cli/attest.py`; Modify `src/wardline/cli/main.py`; Test `tests/unit/cli/test_attest_cmd.py`

- [ ] **Step 1: Failing tests** (`CliRunner`, in a `tmp_path` git repo so dirty/clean is controllable):
  - `wardline attest <path>` on a clean repo prints the bundle JSON (exit 0); the printed bundle's signature verifies with the key.
  - No key minted → a clear `error:` + exit 2 (instruct to run `wardline install`).
  - Dirty tree → refused (exit 2) unless `--allow-dirty`.
  - `wardline attest --verify bundle.json <path>` prints `{signature_valid: true, …}` and exits 0; a tampered bundle → `signature_valid: false`, exit 1.
  - `--clarion-url` opt-in for SEI-keying (fail-soft).
- [ ] **Step 2: Run — expect FAIL.**
- [ ] **Step 3: Implement** `cli/attest.py` mirroring `cli/dossier.py`'s URL-resolution + lazy clarion-client construction. Flags: `path`, `--config`, `--clarion-url`, `--allow-dirty`, `--verify <file>`, `--out <file>` (optional write). Load the key via `load_attest_key`; if absent → exit 2 with a "run `wardline install`" hint. Map `WardlineError` → `error:` + exit 2. Verify mode reads the bundle JSON, loads the key, calls `verify_attestation`, prints the structured result, exit 0 if `signature_valid` else 1.
- [ ] **Step 4: Register** in `main.py`; run — expect PASS.
- [ ] **Step 5: Commit.** `git commit -am "feat(cli): wardline attest + --verify"`

---

## Task 6: MCP `attest` + `verify_attestation` (CLI=MCP parity)

**Files:** Modify `src/wardline/mcp/server.py`, `tests/conformance/test_mcp_handshake.py`; Test `tests/unit/mcp/test_server_attest.py`

- [ ] **Step 1: Failing tests.** The `attest` handler on a clean repo returns a bundle byte-identical (canonical payload) to the CLI/core for the same tree + key; **refuses a dirty tree by default** (tool-execution error) — the MCP default is strict (an agent shouldn't silently attest a dirty tree); `verify_attestation` handler returns the structured verify result. Update the handshake tool-set.
- [ ] **Step 2: Run — expect FAIL.**
- [ ] **Step 3: Implement** `_attest(args, root, clarion)` and `_verify_attestation(args, root)` near `_dossier`. `attest` loads the key via `load_attest_key(root)` (missing key → tool error "run wardline install"), default `allow_dirty=False` (override with an explicit `allow_dirty: true` arg), SEI enrichment via `self._clarion_client()`. Register both tools with schemas; findings/secrets are never resources. Key material is never echoed in output (only `key_id`).
- [ ] **Step 4: Run — expect PASS** (incl. handshake).
- [ ] **Step 5: Commit.** `git commit -am "feat(mcp): attest + verify_attestation (CLI=MCP parity, dirty-strict)"`

---

## Task 7: Docs + CHANGELOG

**Files:** Create `docs/guides/attestation.md`; Modify `mkdocs.yml`, `CHANGELOG.md`

- [ ] **Step 1:** Write `docs/guides/attestation.md`: the evidence primitive, **the HMAC threat model stated plainly** (tamper-evidence within a key-holding trust domain, NOT public non-repudiation; verify needs the shared key), the install-minted key (activation, `.env`, gitignored), the bundle shape, dirty-tree honesty, the two verify checks, and an agent-first MCP example. Cross-link the assurance-posture guide (attest signs D1's number) and legis (which consumes the bundle).
- [ ] **Step 2:** mkdocs nav + CHANGELOG `[Unreleased] Added`.
- [ ] **Step 3:** `uv run mkdocs build --strict`.
- [ ] **Step 4: Commit.** `git commit -am "docs: attestation (wardline attest) guide + threat model"`

---

## Final gate (controller runs after all tasks)

- `uv run pytest` (random order) — green; `ruff check`/`ruff format --check`/`mypy` — clean.
- `uv run wardline scan src/wardline --fail-on ERROR` — dogfood exit 0.
- Frictionless criteria for `attest`/`verify`: one round-trip, structured bundle, **zero-config** (install-minted key — the binding D2 acceptance criterion), CLI=MCP parity, fail-closed (dirty-tree honesty; SEI fallback honest; signature/repro never conflated; no overclaim of asymmetric proof).
- Manual end-to-end: `install` (temp dir) → `attest` → `attest --verify` round-trips with **no manual key step**.
