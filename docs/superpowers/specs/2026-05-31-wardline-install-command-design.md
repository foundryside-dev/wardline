# Wardline `install` command — design

**Date:** 2026-05-31
**Status:** Approved (brainstorming → spec)
**Branch:** `feat/wardline-install-command`

## Problem

Wardline teaches agents how to use it only through **pull-based, MCP-bound**
channels: the MCP server's tool descriptions, the `wardline:loop` prompt, and
the four `wardline://…` resources — all of which reach an agent only if the
consuming project has wired up `wardline mcp` — plus `docs/agents.md`, which a
human has to find and act on.

There is **no push mechanism**. An agent dropped into a repo that merely *uses*
wardline learns nothing about it automatically. By contrast, a sibling tool
(filigree) installs a hashed instruction block into `CLAUDE.md`/`AGENTS.md`, a
skill into `.claude/skills/`, and a SessionStart snapshot — so its agents are
taught at session start without any per-project wiring.

This spec closes that gap with a single `wardline install` command — the
**"inject" half of filigree's pipeline**, deliberately **without** the
SessionStart hook. The hook is where the mechanism tips into the
session-infrastructure "enterprise weight" the wardline rebuild dropped; wardline
is a gate, not a workflow orchestrator, so it does not own the session lifecycle.

A secondary goal: when `wardline install` runs, it should detect the two sibling
integrations it can compose with — the Clarion taint store and the Filigree
emitter — and set up those bindings where it can.

## Non-goals

- **No SessionStart hook**, no dashboard, no freshness daemon. Freshness is
  enforced only when a human re-runs `wardline install`.
- **No interactive prompting** in the default path. `wardline install` must be
  safe to run non-interactively (CI, scripted setup).
- **No magic URL discovery.** Sibling services live at runtime/deployment URLs
  that are not recorded in any project marker; the command never guesses a URL
  it cannot verify from an explicit source (env var).

## Design overview

`wardline install` performs five steps, all enabled by default, each
individually opt-out-able:

| Step | Writes | Opt-out flag |
|------|--------|--------------|
| 1. Config plumbing (prerequisite, always active) | reads `clarion.url`/`filigree.url` at runtime | — |
| 2. Lightweight instruction block | `CLAUDE.md`, `AGENTS.md` | `--no-claude-md`, `--no-agents-md` |
| 3. `wardline-gate` skill | `.claude/skills/`, `.agents/skills/` | `--no-skill` |
| 4. MCP wiring | `.mcp.json` (merge) | `--no-mcp` |
| 5. Binding detection | `wardline.yaml` (`clarion:`/`filigree:`) | `--no-bindings` |

The command is idempotent end-to-end and prints a summary of what it
wrote / skipped / detected.

---

## Component 1 — Config plumbing (prerequisite)

Today `clarion.url` and `filigree.url` do not exist as usable config: the
`clarion:` and `filigree:` sections are accepted by `WARDLINE_SCHEMA` as inert
`{"type": "object"}` placeholders, and the loader exposes them as opaque dicts
that no code reads. The URLs flow **only** through the `--clarion-url` /
`--filigree-url` CLI flags. A binding written to `wardline.yaml` would therefore
be dead unless the runtime reads it.

**Change:** promote `clarion.url` and `filigree.url` to real, schema'd fields and
have the runtime read them.

- Extend `WARDLINE_SCHEMA` (`core/config_schema.py`): `clarion` and `filigree`
  become `{"type": "object", "additionalProperties": False,
  "properties": {"url": {"type": "string"}}}`.
- The config loader (`core/config.py`) continues to expose `clarion` /
  `filigree` mappings; add typed accessors `config.clarion_url` /
  `config.filigree_url` returning `str | None`.
- Resolution precedence, applied at the CLI/MCP entry points:
  **CLI flag > env var > `wardline.yaml`**.
  - Both URL env vars are **new**: `WARDLINE_CLARION_URL` and
    `WARDLINE_FILIGREE_URL`. (Today only the token env var
    `WARDLINE_CLARION_TOKEN` exists; the Clarion *URL* is flag-only and no
    URL env var is read.)
- `wardline scan` reads both resolved URLs; `wardline mcp` reads the resolved
  `clarion.url`. Net effect: the `.mcp.json` entry can be a bare
  `wardline mcp --root .` with **no URL in its args** — the server picks up
  Clarion from config. One source of truth; the URL is never duplicated into
  `.mcp.json`.

This change is in scope for this feature (no deferral): the placeholders were
reserved for exactly this, and without it the binding-detection step writes
something the runtime ignores.

**Behavior preserved:** the `--clarion-url` / `--filigree-url` flags keep their
current meaning and still win over env/config.

---

## Component 2 — The lightweight instruction block

A short, hash-fenced block injected into `CLAUDE.md` and `AGENTS.md` (both by
default; each created if absent). It is **always-loaded** context, so it must
stay small — it makes the agent *aware* of the gate and points at the deeper
material; it does not reproduce it.

Fence and shape:

```
<!-- wardline:instructions:v<schema>:<hash> -->
This project uses **wardline** as its trust-boundary gate. Before handing back
code that touches external input, run `wardline scan . --fail-on ERROR`
(exit 0 = clean, 1 = gate tripped, 2 = wardline error) and fix findings at the
boundary, not the sink. The full scan → explain → fix → rescan loop and the
baseline-vs-waiver discipline live in the `wardline-gate` skill and in
`docs/agents.md`.
<!-- /wardline:instructions -->
```

**Injection (text-level):**
- If the open/close fence pair is present, replace the content between them.
- Else append the block (with a leading blank line) to the file.
- The `<hash>` is computed over the rendered block text. Re-running replaces the
  block **only if** the bundled hash differs from the one in the fence;
  otherwise the file is left byte-identical.
- The `<schema>` segment is the block-template version (bumped when the template
  text changes), mirroring filigree's `vX.Y.Z:hash` marker convention.

---

## Component 3 — The `wardline-gate` skill

Shipped as **package data** at `src/wardline/skills/wardline-gate/SKILL.md`
(force-included into the wheel alongside the existing YAML data files). Copied
into both `.claude/skills/wardline-gate/` and `.agents/skills/wardline-gate/`
(Codex) as an idempotent overwrite.

Frontmatter `description` triggers on the gate use cases — e.g. "scan for
trust-boundary / taint findings", "fix a wardline finding", "wire wardline into
the agent loop". Body is assembled from material that already exists, so the
skill is authored content, not new doctrine:

- the `wardline:loop` four-step cycle (scan → explain_taint → fix-at-boundary →
  rescan);
- the exit-code contract and how the agent self-corrects on a trip;
- baseline-vs-waiver discipline ("prefer fixing; a waiver is an audited,
  time-boxed exception");
- `judge` is opt-in and network-fenced, fails loud;
- the MCP path (tools/resources/prompt) vs. the CLI path.

The skill carries the substance the always-loaded block deliberately omits.

---

## Component 4 — MCP wiring

**Merge** a `wardline` server into the existing `.mcp.json` `mcpServers` object,
preserving any entries already present (the repo already ships a `filigree`
stdio entry):

```json
{
  "mcpServers": {
    "filigree": { "...": "preserved verbatim" },
    "wardline": { "type": "stdio", "command": "wardline", "args": ["mcp", "--root", "."] }
  }
}
```

- If `.mcp.json` is absent, create it with just the `wardline` entry.
- If present, parse JSON, add/replace **only** the `wardline` key under
  `mcpServers`, and write back. Never overwrite the file wholesale; never touch
  sibling entries.
- No `--clarion-url` in the args — the server resolves Clarion from config
  (Component 1).
- `command`: resolve the wardline executable (prefer the running
  `sys.executable -m wardline` invocation form if a bare `wardline` is not on a
  predictable PATH; final form decided in the plan, but it must be invocable by
  the MCP client).

---

## Component 5 — Binding detection

On install (unless `--no-bindings`), detect the two siblings and record what is
found into `wardline.yaml`.

**Detection signals (presence only):**
- **Filigree in use:** `.filigree.conf` exists in the project root. (Confirmed
  reliable: it is a small JSON file with `project_name`/`prefix`/`db`.)
- **Clarion available:** `clarion` resolvable on `PATH`, **or**
  `WARDLINE_CLARION_URL` set.

**URL resolution (honest, never guesses):**
- If the integration's env var is set (`WARDLINE_CLARION_URL` /
  `WARDLINE_FILIGREE_URL`), write a **live** stanza with that URL.
- Else (presence detected, no URL known) write a **commented** stanza noting the
  detected presence, with the URL left for the user to fill:

  ```yaml
  # Clarion taint store detected (clarion on PATH) but no URL configured.
  # Set the taint-store URL to enable per-entity taint-fact enrichment:
  # clarion:
  #   url: "http://localhost:PORT"
  ```

  ```yaml
  # Filigree detected (.filigree.conf present) but no Loom URL configured.
  # Set the Loom scan-results URL to POST findings into Filigree:
  # filigree:
  #   url: "http://localhost:PORT/api/loom/scan-results"
  ```

**Writing into `wardline.yaml` (text-append, guarded):**
- pyyaml cannot round-trip comments, so the command does **not** parse-and-
  rewrite an existing `wardline.yaml`.
- Cheap parse to check whether a top-level `clarion:` / `filigree:` key already
  exists. If it does, leave it untouched (the user owns it).
- If absent, **append** the stanza (live or commented) as text, preserving all
  existing content and comments.
- If `wardline.yaml` does not exist, create it containing only the detected
  stanza(s).

---

## Command surface

```
wardline install [--no-claude-md] [--no-agents-md] [--no-skill]
                 [--no-mcp] [--no-bindings] [--root PATH]
```

- All five steps run by default. Each flag skips its step.
- `--root` (default `.`) sets the project root all paths are resolved under.
- Non-interactive; idempotent; CI-safe.
- Exits `0` on success (including "nothing to update"); non-zero only on a real
  IO/parse error it cannot fail-soft past.
- Prints a per-step summary: for each artifact, one of
  `created` / `updated` / `unchanged` / `skipped`, plus the detection result
  (`clarion: detected (commented)`, `filigree: wired (env URL)`, etc.).

---

## Packaging

- `src/wardline/skills/wardline-gate/SKILL.md` and the instruction-block template
  ship as package data, force-included into the wheel the same way
  `stdlib_taint.yaml` and `vocabulary.yaml` already are
  (`[tool.hatch.build.targets.wheel.force-include]`).
- Read at install time via `Path(__file__).parent`.
- No new runtime dependency — the zero-dependency analysis core is preserved;
  the install command uses only the stdlib plus the already-present CLI deps
  (`click`, `pyyaml`).

## Module layout (provisional, finalized in the plan)

- `src/wardline/cli/install.py` — the `install` click command + summary output.
- `src/wardline/install/` — the mechanics, each unit independently testable:
  - `block.py` — render + hash-fence inject/replace for `CLAUDE.md`/`AGENTS.md`.
  - `skill.py` — copy the bundled skill into `.claude`/`.agents`.
  - `mcp_json.py` — merge the `wardline` entry into `.mcp.json`.
  - `detect.py` — presence detection + `wardline.yaml` stanza append.
- `src/wardline/skills/wardline-gate/SKILL.md` — bundled skill (package data).
- Config plumbing edits in `core/config.py` + `core/config_schema.py` and the
  `scan` / `mcp` entry points.

## Testing strategy

- **Block injection:** fresh file (append), existing file with no fence (append),
  existing file with stale-hash fence (replace), existing file with current-hash
  fence (unchanged/byte-identical), idempotent re-run.
- **Skill copy:** fresh dir, overwrite of an older copy, both `.claude` and
  `.agents` targets.
- **`.mcp.json` merge:** absent file (create), present file with a `filigree`
  entry (preserved, `wardline` added), present file with a stale `wardline`
  entry (replaced), malformed JSON (fail with a clear error, do not clobber).
- **Detection:** Filigree present/absent (`.filigree.conf`), Clarion present via
  PATH, present via env var (live stanza), present without URL (commented
  stanza), `wardline.yaml` absent (create) vs. existing key present (untouched)
  vs. existing file without the key (append, comments preserved).
- **Config plumbing:** precedence flag > env > config for both `scan` and `mcp`;
  a `clarion.url` in config reaches the MCP server with a bare
  `wardline mcp --root .`.
- **End-to-end:** `wardline install` in a temp project, then assert every
  artifact, then re-run and assert all-`unchanged`.

## Risks / open points for the plan

- Final form of the `command` string in `.mcp.json` (bare `wardline` vs.
  `python -m wardline`) — must be reliably invocable by the MCP client.
- Whether the instruction block should also be removable (`wardline install
  --uninstall` / an `uninstall` verb) — deferred unless the plan surfaces a need;
  the fenced block is already safe to delete by hand.
