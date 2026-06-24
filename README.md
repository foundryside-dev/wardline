# Wardline

Generic, lightweight semantic-tainting static analyzer for trust boundaries. Wardline's full analyzer targets
Python; its Rust preview catches command-injection defects over crate-aware identity. The base package has zero
runtime dependencies, and scanner/front-end functionality stays behind opt-in extras.

[![CI](https://github.com/foundryside-dev/wardline/actions/workflows/ci.yml/badge.svg)](https://github.com/foundryside-dev/wardline/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/wardline)](https://pypi.org/project/wardline/)
[![Python 3.12+](https://img.shields.io/pypi/pyversions/wardline)](https://pypi.org/project/wardline/)
[![License: MIT](https://img.shields.io/pypi/l/wardline)](https://github.com/foundryside-dev/wardline/blob/main/LICENSE)

```python
# demo.py
from weft_markers import trusted, external_boundary

@external_boundary
def read_request(req):
    return req.body            # raw, untrusted (EXTERNAL_RAW)

@trusted(level="ASSURED")
def build_record(req):
    return read_request(req)   # claims ASSURED, returns raw — no validation
```

```console
$ wardline scan . --fail-on ERROR
scanned 1 file(s); 2 finding(s) — 0 suppressed (0 baseline / 0 waiver / 0 judged), 1 active -> .wardline/20260620T153012Z-findings.jsonl
$ echo $?
1
```

The gate trips (exit 1) and the findings land in timestamped JSON Lines under
`.wardline/` by default (`--output PATH` writes to an exact path; `--format
sarif` emits SARIF for GitHub code scanning). Wardline is agent-first — you
don't read that file by hand. Your coding agent does: ask it *"why did the scan
fail?"* and it surfaces the one active defect (the other finding is a
`NONE`-severity engine fact):

> **`demo.build_record`** declares return trust `ASSURED` but actually returns
> `EXTERNAL_RAW` (less trusted) — untrusted data reaches a trusted producer.
> &nbsp;&nbsp;`demo.py:8` · `PY-WL-101`

## What is Wardline?

Wardline reads your code statically — it never runs it — and asks one question
of every trust-annotated boundary: **is the data this function works with as
trusted as it claims?** For Python, it tracks a *taint* (a trust level) for
values through function bodies and the project call graph, flagging places where
untrusted data reaches a trusted producer with no validation in between. For
Rust, the preview frontend currently focuses on command-injection sinks around
`std::process::Command`.

Wardline is part of **Weft** — an agent-first suite of small, local-first
developer tools, each driven by a coding agent as much as a person, giving small
teams capable tooling without enterprise weight. The authoritative federation
hub, roster, and composition doctrine live at `~/weft` (see
`~/weft/doctrine.md`); rather than restate membership here, refer to the hub for
the current roster and the enrich-only axiom that governs how the tools compose.

**Opt-in by design.** Wardline is silent until you opt in. Undecorated code sits
in the developer-freedom zone — unknown-trust, no findings. You declare trust on
the functions that matter, and only then does Wardline enforce it. That is what
lets it scan a large untouched codebase (including its own) with zero noise.

## Key Features

- **Deterministic Python taint analysis** — function-, variable-, and
  project-level analysis over an inter-module call graph; no runtime
  instrumentation.
- **Rust command-injection preview** — `wardline scan --lang rust` finds
  `RS-WL-108`/`RS-WL-112` over `.rs` trees with crate-prefixed, baseline-eligible
  finding identity.
- **Opt-in trust model** — Python decorators (`@external_boundary`,
  `@trust_boundary`, `@trusted`) and Rust doc-comment markers declare the
  boundary surface; undecorated code stays quiet.
- **Trust-boundary and sink rules** — boundary-integrity rules, exception-flow
  rules, and expanded sink families for command execution, dynamic code/imports,
  deserialization, path traversal, SSRF, SQL injection, XML parsing, templates,
  native library loads, logging format strings, and SMTP sends.
- **Zero-dependency base** — `pip install wardline` pulls nothing; scanner,
  Loomweave, Rust, and docs functionality live behind small extras.
- **Structured output** — JSONL, SARIF, agent-summary JSON, signed legis scan
  artifacts, and native Filigree emission for finding lifecycle work.
- **MCP-primary agent surface** — `wardline mcp` is a dependency-free
  MCP-over-stdio server with structured tool output, schema declarations, and
  tools for scan, explain, fix, judge, doctor, rekey, assurance, attestation,
  dossier, and finding lifecycle work.
- **Reproducible evidence and migrations** — `assure`, `attest`, and `rekey`
  report trust-surface coverage, sign reproducible posture bundles, and migrate
  fingerprint-keyed stores across scheme changes.
- **Opt-in LLM triage** — `wardline judge` labels findings TRUE/FALSE positive
  (dependency-free; never runs automatically).
- **Light-touch suppression** — baselines, time-boxed waivers, and judged
  findings with explicit gate semantics.
- **Loomweave integration** — persist per-entity taint facts to a Loomweave store.

## Quick Start

```bash
pip install 'wardline[scanner]'   # quote the extras for zsh
```

```python
# app.py
from weft_markers import trusted, external_boundary

@external_boundary
def read_request(req):
    return req.body

@trusted(level="ASSURED")
def build_record(req):
    return read_request(req)
```

```bash
wardline scan . --fail-on ERROR   # exit 0 = clean, 1 = gate tripped, 2 = wardline error
```

Fix findings at the **boundary** (validate before returning), not at the sink.

## Installation

```bash
pip install weft-markers          # tiny runtime marker package for application code
pip install wardline              # zero-dependency base (library + decorators)
pip install 'wardline[scanner]'   # the scan/judge/baseline CLI + MCP server (quote for zsh)
pip install 'wardline[rust]'      # Rust command-injection preview frontend
```

Prefer `weft_markers` in application code. Wardline still recognizes
`wardline.decorators` for backward compatibility and direct Wardline users, but
`weft-markers` is the neutral marker-only runtime dependency.

| Extra | Pulls | Enables |
|-------|-------|---------|
| `scanner` | pyyaml, jsonschema, click | the `wardline` CLI and `wardline mcp` server |
| `loomweave` | blake3 | persisting taint facts to a Loomweave store |
| `rust` | scanner extra, tree-sitter, tree-sitter-rust | `wardline scan --lang rust` |
| `docs` | mkdocs, mkdocs-material | a local MkDocs render of `docs/` |

The LLM triage judge (`wardline judge`) is dependency-free (stdlib `urllib` →
OpenRouter) and needs no extra.

## Use Wardline with your coding agent

```bash
wardline install
```

This injects a hash-fenced instruction block into `CLAUDE.md`/`AGENTS.md`,
installs the `wardline-gate` skill, merges a `wardline` entry into `.mcp.json`,
writes Codex's `~/.codex/config.toml` MCP entry, detects Loomweave/Filigree
siblings, mints an attest signing key, and adds pre-commit hook config. Agents
then run the scan → explain → fix-at-boundary → rescan loop natively. The `wardline mcp` server
exposes the primary tool surface over JSON-RPC with no SDK, including scan,
filtered findings, explain-taint, fix, judge, baseline/waiver, doctor, rekey,
assure, attest, dossier, and Filigree filing tools.

`wardline install` also reminds application projects to install `weft-markers`
and import from `weft_markers` when they want runtime-importable trust markers
without depending on the full Wardline scanner package.

Run `wardline doctor` to check those artifacts later, or `wardline doctor
--repair` to refresh stale/missing wiring after moving tools or starting a
Filigree dashboard.

## Configuration and state

Wardline reads operator configuration from the `[wardline]` table in
`weft.toml`. Machine-written state lives under `.weft/wardline/`: baselines,
waivers, judged findings, and cache data stay out of the authored config file.

Sibling URLs are resolved at runtime from flags, environment variables, or
published local Weft port files. `wardline install` and `wardline doctor` detect
sibling tools such as Filigree and Loomweave, but they do not persist endpoint
bindings into project config.

## Where Wardline fits

Use Wardline when you want a deterministic, opt-in trust-boundary gate you can
run in CI and hand to an agent — lightweight, Python-native, no external service.

It is **not** the right tool when you need:

- **Full interprocedural everything.** Wardline is precise at the function and
  project-call-graph level (L1–L2 with an L3 fixed point), not an exhaustive,
  path-sensitive whole-program prover.
- **A broad SAST suite.** Wardline checks trust boundaries and a small set of
  exception-handling rules; it is not a replacement for a general-purpose
  scanner that covers dozens of vulnerability classes.
- **Full non-Python coverage.** Wardline's Rust frontend is a preview for
  command-injection findings only; it is not a general Rust SAST engine.
- **Zero-config coverage.** Wardline is silent until you declare trust — that is
  the point, but it means it finds nothing meaningful on an un-annotated
  codebase.

## Documentation

Full documentation lives in the [`docs/`](https://github.com/foundryside-dev/wardline/tree/main/docs) tree.

| Document | Description |
|----------|-------------|
| [Getting Started](https://github.com/foundryside-dev/wardline/blob/main/docs/getting-started.md) | Install, decorate, first scan |
| [Taint & Trust Model](https://github.com/foundryside-dev/wardline/blob/main/docs/concepts/model.md) | The lattice, decorators, and propagation |
| [Rules](https://github.com/foundryside-dev/wardline/blob/main/docs/concepts/rules.md) | The boundary, exception-flow, and sink rules |
| [Configuration](https://github.com/foundryside-dev/wardline/blob/main/docs/guides/configuration.md) | `weft.toml` `[wardline]`: rules, severity, excludes |
| [Suppression](https://github.com/foundryside-dev/wardline/blob/main/docs/guides/suppression.md) | Baselines and waivers |
| [LLM Triage Judge](https://github.com/foundryside-dev/wardline/blob/main/docs/guides/judge.md) | Opt-in TRUE/FALSE-positive labelling |
| [Rust Support](https://github.com/foundryside-dev/wardline/blob/main/docs/guides/rust-preview.md) | Preview Rust command-injection frontend |
| [Weft Integration](https://github.com/foundryside-dev/wardline/blob/main/docs/guides/weft.md) | SARIF, Filigree, Loomweave, and sibling URL resolution |
| [Assurance Posture](https://github.com/foundryside-dev/wardline/blob/main/docs/guides/assurance-posture.md) | Coverage posture, attestations, and trust-surface evidence |
| [Loomweave Taint Store](https://github.com/foundryside-dev/wardline/blob/main/docs/guides/loomweave-taint-store.md) | Persisting taint facts |
| [CLI Reference](https://github.com/foundryside-dev/wardline/blob/main/docs/reference/cli.md) | Every command and flag |
| [Trust Vocabulary](https://github.com/foundryside-dev/wardline/blob/main/docs/reference/vocabulary.md) | The decorators and their arguments |
| [Agent Integration](https://github.com/foundryside-dev/wardline/blob/main/docs/guides/agents.md) | Using Wardline from a coding agent |

## Development

Requires Python ≥3.12. Developed on 3.13 with [uv](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/foundryside-dev/wardline
cd wardline
uv sync --all-extras --group dev

make ci          # ruff check + format check + mypy strict + pytest (90% coverage floor)
make lint        # ruff check + format --check
make format      # auto-format and fix
make typecheck   # mypy strict
make test        # pytest
make scan-self   # dogfood: scan wardline's own source
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full workflow and
[CLAUDE.md](CLAUDE.md) for the developer architecture guide.

## Acknowledgements

Wardline is one of the **Weft** tools (with Loomweave and Filigree) — an
agent-first, local-first developer tooling suite for small teams.

## License

[MIT](LICENSE) — Copyright (c) 2026 John Morrissey
