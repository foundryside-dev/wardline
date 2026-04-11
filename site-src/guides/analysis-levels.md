# Analysis Levels Guide

Wardline scans at three analysis levels. Higher levels find more violations but
scan slower and require more annotation coverage to be effective.

## Quick Comparison

| | L1 (Default) | L2 | L3 |
|---|---|---|---|
| **Taint granularity** | Function-level | Variable-level | Interprocedural |
| **What it tracks** | One taint per function body | Different taint per variable | Taint through call chains |
| **Speed** | Fast | Moderate | Slowest |
| **False negatives** | Highest (multiplicative) | Medium | Lowest |
| **False positives** | Lowest | Low | Low |
| **Annotation needs** | Minimal | Moderate | Comprehensive |
| **Best for** | Initial adoption, fast CI | Growing projects | High-assurance systems |

## L1: Function-Level Taint

Every value inside a function body gets the function's taint state. If a function
is decorated with `@integrity_critical`, every variable in that function is
treated as `INTEGRAL`.

**Strengths:**
- Fast — single pass, no data-flow analysis
- Works with minimal decorators

**Weaknesses:**
- Cannot distinguish tainted and untainted variables within the same function
- Two-hop heuristic: undecorated function calls are treated as pass-through,
  which can miss violations through longer call chains
- These approximations compound multiplicatively — both the function-level
  approximation and the two-hop heuristic apply at the same time

**Example false negative at L1:**
```python
@integrity_critical
def process(user_input, db_record):
    # L1 treats both as INTEGRAL — misses the risk from user_input
    result = user_input["name"]  # Actually EXTERNAL_RAW!
    db.write(result)
```

## L2: Variable-Level Taint

Tracks taint per variable within a function. Different variables can carry
different taint states.

**Strengths:**
- Catches the L1 false negative above — `user_input` and `db_record` get
  different taints
- Still reasonably fast

**Weaknesses:**
- No transitive call-graph inference — if taint flows through a chain of
  undecorated helper functions, L2 may not follow it

## L3: Callgraph-Level Taint

Full interprocedural analysis. The scanner builds a call graph, computes
strongly-connected components (SCCs), and runs fixed-point taint propagation.

**Strengths:**
- Catches violations through arbitrary call chains
- Two-hop rejection delegation — follows rejection paths through function calls
- Most accurate analysis level

**Weaknesses:**
- Slowest — requires full call-graph construction
- Needs good annotation coverage to resolve call edges
- May hit convergence bounds on large codebases (`L3-CONVERGENCE-BOUND`)
- Low-resolution warning when >70% of call edges are unresolved
  (`L3-LOW-RESOLUTION`)

## Choosing a Level

| Situation | Recommended Level |
|-----------|-------------------|
| Just installed wardline, few decorators | L1 |
| Moderate decorator coverage, want fewer false negatives | L2 |
| High decorator coverage, regulated codebase, need maximum precision | L3 |
| CI on every PR (speed matters) | L1 or L2 |
| Nightly full scan (thoroughness matters) | L3 |

A common pattern: **L1 in PR checks, L3 in nightly scans.**

## Configuration

In `wardline.toml`:

```toml
[wardline]
analysis_level = 2
```

Or via CLI:

```bash
wardline scan src/ --analysis-level 3
```

## Further Reading

- [Taint State Reference](../reference/taint-states.md) — what taint states mean
- [Severity Matrix](../reference/severity-matrix.md) — how taint affects severity
- [Adoption Guide](adoption.md) — incremental adoption strategy
