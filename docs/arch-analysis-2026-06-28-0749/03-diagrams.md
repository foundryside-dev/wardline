# 03 — Architecture Diagrams

**Target:** `wardline` @ `e4668abc` · **Date:** 2026-06-28. Edges below are taken from the
Loomweave-graph-derived dependency sections of `02-subsystem-catalog.md` (not import inference).

---

## C1 — System Context

Who uses Wardline and what it talks to. Wardline is **local-first**: every external link is opt-in and
fail-soft — a sibling outage degrades a section, never breaks a scan.

```mermaid
graph TB
    agent["Coding agent / developer<br/>(humans on the loop)"]
    subgraph wl["Wardline (local CLI + MCP + LSP)"]
      core["Taint engine + rules + gate"]
    end
    loom["Loomweave<br/>(taint-fact store + SEI identity)<br/>HMAC over urllib"]
    fil["Filigree<br/>(issue tracker / finding lifecycle)<br/>Bearer over loopback"]
    legis["legis<br/>(governance)<br/>signed artifact, agent-posted"]
    orouter["OpenRouter<br/>(LLM triage judge)<br/>opt-in, network-fenced"]
    code["Target source tree<br/>(.py / .rs — untrusted input)"]

    agent -->|"wardline scan / MCP tools"| wl
    wl -->|reads statically, never executes| code
    wl -.->|opt-in: persist taint facts / resolve SEI| loom
    wl -.->|opt-in: emit findings / dossier work| fil
    wl -.->|opt-in: signed scan artifact| legis
    wl -.->|opt-in: judge findings| orouter
```

---

## C2 — Containers / Packaging

The **zero-dependency base** is a hard product invariant; capability ships behind small extras. One
package, several runnable surfaces, all routing through one shared core.

```mermaid
graph TB
    subgraph pkg["wardline (PyPI package — base dependencies = [] )"]
      console["console script<br/>wardline.cli.entrypoint:main<br/>(dep-light shim)"]
      subgraph base["base (stdlib only)"]
        coremodel["core finding model, taint lattice,<br/>config, paths, safe_paths, identity"]
      end
      subgraph scannerx["[scanner] extra — pyyaml/jsonschema/click"]
        cli["CLI (S11)"]
        mcp["MCP + LSP server (S10)"]
        engine["Scanner engine + rules + taint (S1/S2/S3)"]
        orch["Core orchestration + gate + evidence (S4/S5/S6/S7/S8)"]
        install["install / activation (S11)"]
      end
      subgraph loomx["[loomweave] extra — blake3"]
        fed["Federation clients (S9)"]
      end
      subgraph rustx["[rust] extra — tree-sitter + tree-sitter-rust"]
        rust["Rust frontend (S12)"]
      end
      subgraph docsx["[docs] extra — mkdocs"]
        docs["docs site build"]
      end
    end
    console --> cli
    cli --> orch
    mcp --> orch
    orch --> engine
    orch -.lazy.-> rust
    orch -.lazy.-> fed
```

---

## C3 — Components (the 12 subsystems) & their dependency edges

Coupling is largely one-directional **surfaces → orchestration → engine**, with federation/identity as
leaves and a few back-edges (noted). `run_scan`/`gate_decision` (S4) is the keystone both surfaces share.

```mermaid
graph TD
    classDef surface fill:#e8f0ff,stroke:#4a73c0;
    classDef orch fill:#fff3e0,stroke:#c08a3a;
    classDef engine fill:#e9f7e9,stroke:#4aa04a;
    classDef leaf fill:#f3e8ff,stroke:#8a4ac0;

    S11["S11 · CLI & Install"]:::surface
    S10["S10 · MCP & LSP Server"]:::surface

    S4["S4 · Core Orchestration & Config<br/>(run_scan / gate_decision — keystone)"]:::orch
    S5["S5 · Findings, Outputs & Emit"]:::orch
    S6["S6 · Gate Discipline & Remediation"]:::orch
    S7["S7 · Trust Evidence & Judge"]:::orch
    S8["S8 · Identity & SEI"]:::orch

    S1["S1 · Scanner Engine"]:::engine
    S2["S2 · Rule Lattice (+decorators)"]:::engine
    S3["S3 · Taint Engine"]:::engine
    S12["S12 · Rust Frontend"]:::engine

    S9["S9 · Federation Clients"]:::leaf

    S11 --> S4 & S5 & S6 & S7 & S8 & S9 & S10
    S10 --> S4 & S5 & S6 & S7 & S8 & S9
    S4 --> S1 & S3 & S5 & S6 & S8
    S4 -.lazy.-> S12
    S4 -.injected.-> S8
    S6 -.->|lazy import: breaks S6↔S4 cycle| S4
    S1 --> S2 & S3
    S2 -.->|imports _private decorator helpers| S3
    S3 --> S4
    S12 --> S5 & S8 & S3 & S2
    S7 --> S4 & S5 & S6 & S8 & S9
    S8 --> S6 & S9
    S5 --> S1 & S9
    S9 --> S4 & S5 & S7 & S8
```

**Back-edges / cycles worth seeing (from the catalog):**
- **S6 ↔ S4** — `core/run.py` imports the S6 baseline/suppression loaders; `baseline.collect_and_write_baseline`
  lazy-imports `run.run_scan` at call time (`baseline.py:232`) to break the cycle.
- **S2 → S3 (private)** — rules import `decorator_provider._is_builtin_decorator_fqn` / `_shadowed_builtin_roots`.
- **S3 → S4 (`core.taints`/`core.ruleset`)** — the taint *lattice* and `ruleset_hash` physically live in
  `core/` but are the engine's vocabulary; `ruleset_hash` was deliberately rehomed *below* both engine and
  attest to remove the old engine→attest inversion (closed `wardline-9ec283d168`).
- **S5 → S1** — `explain.py` reads `AnalysisContext` provenance maps directly (no narrow interface).

---

## Intended layering vs reality

The closed ticket `wardline-9ec283d168` defines the intended layering **engine ⇦ policy ⇦ surface ⇦
federation**. The single import-linter contract that encodes one slice of it (`scanner ⇏ core.attest`)
**passes** (1 kept/0 broken). But the broader goal is only *partially* realized — the catalog and the
ticket's own close-note show real `core/` cycles still broken by **~102 function-local imports** (down
from 158).

```mermaid
graph TB
    subgraph T5["Surfaces (S10, S11)"]
      direction LR
      A1["CLI"]; A2["MCP / LSP"]
    end
    subgraph T4["Federation clients (S9)"]
      B1["Loomweave / Filigree / legis"]
    end
    subgraph T3["Evidence & outputs (S5, S7)"]
      C1["emit / sarif / explain"]; C2["attest / assure / dossier / judge"]
    end
    subgraph T2["Policy / orchestration (S4, S6, S8)"]
      D1["run_scan / gate"]; D2["baseline / waivers / suppression / delta"]; D3["identity / SEI"]
    end
    subgraph T1["Engine floor (S1, S2, S3, S12)"]
      E1["scanner engine"]; E2["rules + decorators"]; E3["taint"]; E4["rust"]
    end
    subgraph T0["Shared stdlib kernel"]
      F1["taints · finding-model · config · paths · safe_paths · ruleset · registry · errors"]
    end
    T5 --> T2
    T5 --> T3
    T3 --> T2
    T4 --> T2
    T2 --> T1
    T1 --> T0
    T3 --> T0
    T4 --> T0
    note["⚠ Real residual cycles through T0/T2 (e.g. run → … → attest → assure → run)<br/>still broken by ~102 deferred imports — the broad layering goal is partially done"]
```

---

## Scan pipeline (sequence)

The behaviour both `wardline scan` (S11) and the MCP `scan` tool (S10) share — **identical by
construction** because both call `run_scan`/`gate_decision`.

```mermaid
sequenceDiagram
    participant Surf as Surface (CLI / MCP / LSP)
    participant Run as S4 run_scan
    participant Disc as S4 discover (confined)
    participant Eng as S1 analyzer
    participant Taint as S3 taint (L1→L3→L2)
    participant Rules as S2 rule lattice
    participant Supp as S6 suppression
    participant Gate as S4 gate_decision
    participant Emit as S5 emit / S9 federation

    Surf->>Run: run_scan(root, config, …)
    Run->>Disc: discover source_roots (read-confined, THREAT-001)
    Run->>Eng: Analyzer.analyze(files)
    Eng->>Taint: resolve_project_taints + build_call_taint_map
    Taint-->>Eng: ResolverResult (fixed point) + L2 var taints
    Eng->>Rules: RuleRegistry.run(AnalysisContext)
    Rules-->>Eng: Finding[] (defects + facts)
    Eng-->>Run: Finding[]
    Run->>Supp: apply_suppressions(baseline/waivers/judged) → un-suppressed gate population
    Run->>Gate: gate_decision(gate_findings, fail_on)
    Gate-->>Surf: GateDecision (tripped⇒never PASSED)
    Surf-)Emit: JSONL / SARIF / Filigree / legis (fail-soft)
```
