# Wardline

Generic, lightweight semantic-tainting static analyzer for Python — track untrusted data across your codebase and gate trust-boundary violations, with zero runtime dependencies.

[![CI](https://github.com/foundryside-dev/wardline/actions/workflows/ci.yml/badge.svg)](https://github.com/foundryside-dev/wardline/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/wardline)](https://pypi.org/project/wardline/)
[![Python 3.12+](https://img.shields.io/pypi/pyversions/wardline)](https://pypi.org/project/wardline/)
[![License: MIT](https://img.shields.io/pypi/l/wardline)](https://github.com/foundryside-dev/wardline/blob/main/LICENSE)

```python
# demo.py
from wardline.decorators import trusted, external_boundary

@external_boundary
def read_request(req):
    return req.body            # raw, untrusted (EXTERNAL_RAW)

@trusted(level="ASSURED")
def build_record(req):
    return read_request(req)   # claims ASSURED, returns raw — no validation
```

```console
$ wardline scan . --fail-on ERROR
scanned 1 file(s); 3 finding(s) — 0 suppressed (0 baseline / 0 waiver / 0 judged), 1 new -> findings.jsonl
$ echo $?
1
```

The gate trips (exit 1) and the findings land in `findings.jsonl` (JSON Lines;
`--format sarif` for GitHub code scanning). Wardline is agent-first — you don't
read that file by hand. Your coding agent does: ask it *"why did the scan fail?"*
and it surfaces the one active defect (the other two findings are `NONE`-severity
engine facts):

> **`demo.build_record`** declares return trust `ASSURED` but actually returns
> `EXTERNAL_RAW` (less trusted) — untrusted data reaches a trusted producer.
> &nbsp;&nbsp;`demo.py:8` · `PY-WL-101`

## What is Wardline?

Wardline reads your Python statically — it never runs your code — and asks one
question of every trust-annotated function: **is the data this function works
with as trusted as it claims?** It tracks a *taint* (a trust level) for every
value and propagates it across the whole project, flagging the places where
untrusted data reaches a trusted producer with no validation in between.

Wardline is part of **Loom** — an agent-first suite of small, local-first
developer tools (Wardline analysis, **Clarion** code intelligence, **Filigree**
issue tracking). Every tool is built to be driven by a coding agent as much as a
person, giving small teams capable tooling without enterprise weight.

**Opt-in by design.** Wardline is silent until you opt in. Undecorated code sits
in the developer-freedom zone — unknown-trust, no findings. You declare trust on
the functions that matter, and only then does Wardline enforce it. That is what
lets it scan a large untouched codebase (including its own) with zero noise.

## Key Features

- **Deterministic whole-program taint** — function-, variable-, and project-level
  analysis over an inter-module call graph; no runtime instrumentation.
- **Opt-in trust model** — three decorators (`@external_boundary`,
  `@trust_boundary`, `@trusted`) mark your boundaries; the engine infers the rest.
- **Four policy rules** — untrusted-reaches-trusted, non-rejecting boundary,
  broad exception handler, and silently-swallowed exception.
- **Zero-dependency base** — `pip install wardline` pulls nothing; functionality
  lives behind small extras.
- **Structured output** — JSONL, SARIF (GitHub code-scanning), and native
  Filigree emit.
- **Agent-native** — `wardline mcp` is a dependency-free MCP-over-stdio server;
  `wardline install` wires Wardline into your coding agent in one command.
- **Opt-in LLM triage** — `wardline judge` labels findings TRUE/FALSE positive
  (dependency-free; never runs automatically).
- **Light-touch suppression** — baselines and time-boxed, reasoned waivers.
- **Clarion integration** — persist per-entity taint facts to a Clarion store.

## Quick Start

```bash
pip install 'wardline[scanner]'   # quote the extras for zsh
```

```python
# app.py
from wardline.decorators import trusted, external_boundary

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
pip install wardline              # zero-dependency base (library + decorators)
pip install 'wardline[scanner]'   # the scan/judge/baseline CLI + MCP server (quote for zsh)
```

| Extra | Pulls | Enables |
|-------|-------|---------|
| `scanner` | pyyaml, jsonschema, click | the `wardline` CLI and `wardline mcp` server |
| `clarion` | blake3 | persisting taint facts to a Clarion store |
| `docs` | mkdocs, mkdocs-material | building the documentation site |

The LLM triage judge (`wardline judge`) is dependency-free (stdlib `urllib` →
OpenRouter) and needs no extra.

## Use Wardline with your coding agent

```bash
wardline install
```

This injects a hash-fenced instruction block into `CLAUDE.md`/`AGENTS.md`,
installs the `wardline-gate` skill, merges a `wardline` entry into `.mcp.json`,
and records Clarion/Filigree bindings if present. Agents then run the
scan → explain → fix-at-boundary → rescan loop natively. The `wardline mcp`
server exposes `scan`, `explain_taint`, `fix`, `judge`, baseline, and waiver
tools over JSON-RPC with no SDK.

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
- **Non-Python code.** Wardline analyzes Python ≥3.12 only.
- **Zero-config coverage.** Wardline is silent until you declare trust — that is
  the point, but it means it finds nothing on an un-annotated codebase.

## Documentation

Full documentation lives at **<https://foundryside-dev.github.io/wardline/>**.

| Document | Description |
|----------|-------------|
| [Getting Started](https://foundryside-dev.github.io/wardline/getting-started/) | Install, decorate, first scan |
| [Taint & Trust Model](https://foundryside-dev.github.io/wardline/concepts/model/) | The lattice, decorators, and propagation |
| [Rules](https://foundryside-dev.github.io/wardline/concepts/rules/) | The four policy rules |
| [Configuration](https://foundryside-dev.github.io/wardline/guides/configuration/) | `wardline.yaml`: rules, severity, excludes |
| [Suppression](https://foundryside-dev.github.io/wardline/guides/suppression/) | Baselines and waivers |
| [LLM Triage Judge](https://foundryside-dev.github.io/wardline/guides/judge/) | Opt-in TRUE/FALSE-positive labelling |
| [Clarion Taint Store](https://foundryside-dev.github.io/wardline/guides/clarion-taint-store/) | Persisting taint facts |
| [CLI Reference](https://foundryside-dev.github.io/wardline/reference/cli/) | Every command and flag |
| [Trust Vocabulary](https://foundryside-dev.github.io/wardline/reference/vocabulary/) | The decorators and their arguments |
| [Agent Integration](https://foundryside-dev.github.io/wardline/guides/agents/) | Using Wardline from a coding agent |

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

Wardline is one of the **Loom** tools (with Clarion and Filigree) — an
agent-first, local-first developer tooling suite for small teams.

## License

[MIT](LICENSE) — Copyright (c) 2026 John Morrissey
