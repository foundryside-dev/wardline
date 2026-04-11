# flake8 Plugin Design + Implementation Plan — WP 3.1

**Date:** 2026-03-24
**Status:** Draft (revised after 7-reviewer panel)
**Scope:** Separate `wardline-flake8` package implementing PY-WL-001–005 as flake8 AST checkers
**Target release:** v0.4.0
**Dependencies:** None (reimplements patterns in flake8's framework, no wardline import)

**Panel review findings incorporated (7 reviewers):**
- **Python C:** Build-backend `_legacy:_Backend` → `setuptools.build_meta`
- **Python C:** `ast.MatchMapping`/`MatchClass` don't exist on 3.9 — guard with `hasattr`
- **Static Analysis C + SA I1 + QE C1:** WL001 missing `setdefault` + `defaultdict` patterns; arg count `>=2` not `==2`
- **Static Analysis C:** `schema_default()` governance collapse undocumented
- **Static Analysis I + SA I3/I4 + QE I4:** WL004 missing tuple handlers, qualified names, `TryStar` dedup
- **Static Analysis I + SA I5 + QE I3:** WL005 missing `continue`/`break` bodies
- **Systems C + Security C + IRAP I-2:** Advisory suffix on all messages — contradictions damage scanner trust
- **IRAP C-1:** Error codes confusable with scanner findings — add `[advisory]` tag
- **SA I6:** Checker class in `__init__.py` → move to `checker.py`
- **QE C3 + QE I1:** Integration test needs home in scaffold; entry point registration test needed

## Design

### What It Is

A standalone flake8 plugin (`pip install wardline-flake8`) that fires **advisory** warnings in IDE and CI for the 5 core wardline patterns. Per-file AST matching only — no manifest, no taint context, no tier-graded severity. Every match is a WARNING. This is the "zero-config immediate feedback" path.

**Every emitted message carries an `[advisory]` tag** to make the non-authoritative status visible at point of use, not just in documentation. Example: `WL001 [advisory] dict.get() with fallback default — run wardline scan for taint-context verdict`.

### What It Is NOT

- Not a substitute for `wardline scan` (which has taint context, severity grading, exception register)
- Not a runtime of the full rule engine (no `RuleBase`, no `ScanContext`)
- Does not import from `wardline` at all — fully self-contained
- **Output must NOT be used in IRAP evidence packs** — only `wardline scan` output is authoritative

### Error Codes

| Code | Maps to | Patterns (all from full rule) |
|---|---|---|
| `WL001` | PY-WL-001 | `.get(key, default)` (>=2 args), `.setdefault(key, default)`, `defaultdict(factory)` |
| `WL002` | PY-WL-002 | `getattr(obj, name, default)` (3 args) |
| `WL003` | PY-WL-003 | `key in X` / `hasattr()` / `match/case` with `MatchMapping`/`MatchClass` (3.10+ only, guarded) |
| `WL004` | PY-WL-004 | `except Exception` / `except BaseException` / bare `except:` / tuple handlers / qualified names / `except*` (3.11+, guarded) |
| `WL005` | PY-WL-005 | `except X: pass` / `except X: ...` / `except X: continue` / `except X: break` |

### Package Structure

```
wardline-flake8/
├── pyproject.toml
├── README.md
├── src/
│   └── wardline_flake8/
│       ├── __init__.py     # re-export WardlineChecker
│       ├── checker.py      # WardlineChecker class (flake8 entry point)
│       ├── wl001.py        # dict.get/setdefault/defaultdict
│       ├── wl002.py        # getattr
│       ├── wl003.py        # existence checks (MatchMapping guarded for 3.9)
│       ├── wl004.py        # broad handlers (TryStar guarded for <3.11)
│       └── wl005.py        # silent handlers (pass/Ellipsis/continue/break)
└── tests/
    ├── conftest.py         # shared parse_and_check helper
    ├── test_wl001.py
    ├── test_wl002.py
    ├── test_wl003.py
    ├── test_wl004.py
    ├── test_wl005.py
    └── test_integration.py # flake8 runner + entry point registration
```

### flake8 Plugin API

```python
# checker.py
class WardlineChecker:
    name = "wardline-flake8"  # distinct from "wardline" scanner
    version = "0.1.0"

    def __init__(self, tree: ast.Module) -> None:
        self._tree = tree

    def run(self) -> Iterator[tuple[int, int, str, type]]:
        yield from check_wl001(self._tree)
        yield from check_wl002(self._tree)
        yield from check_wl003(self._tree)
        yield from check_wl004(self._tree)
        yield from check_wl005(self._tree)
```

Entry point registration:
```toml
[project.entry-points."flake8.extension"]
WL = "wardline_flake8:WardlineChecker"
```

### Pattern Detection

Each `check_wlNNN` function walks the AST via `ast.walk(tree)` (module root, not per-function) and yields `(line, col, message, type)` tuples.

**Simplifications from full rules:**
- No taint gating (fires on every match)
- No severity grading (everything is flake8 warning)
- No `ScanContext` (pure AST)
- `ast.walk` instead of `walk_skip_nested_defs`

**Python version guards:**
- WL003: `if hasattr(ast, "MatchMapping")` for match/case detection (3.10+)
- WL004/WL005: `getattr(ast, "TryStar", None)` for except* dedup (3.11+)

### Known Limitations

1. **More false positives than `wardline scan`** — no taint context, no exception register. By design.
2. **Contradicts scanner** for taint-suppressed findings (e.g., `key in config` at INTEGRAL). The `[advisory]` message tag makes this visible.
3. **WL001 fires on `schema_default()` call sites** that `wardline scan` suppresses as governed defaults. The plugin has no overlay boundary context.
4. **WL003 fires on ALL `in` operators** — no type resolution to distinguish dict/list/set/string.
5. **No exception register awareness** — teams with legitimately excepted findings must use `# noqa: WL001` or similar.

### pyproject.toml

```toml
[project]
name = "wardline-flake8"
version = "0.1.0"
description = "Wardline advisory rules for flake8 — run wardline scan for authoritative analysis"
requires-python = ">=3.9"
dependencies = ["flake8>=5.0"]

[project.entry-points."flake8.extension"]
WL = "wardline_flake8:WardlineChecker"

[build-system]
requires = ["setuptools>=64"]
build-backend = "setuptools.build_meta"
```

### Testing (~35 tests)

**conftest.py:** Shared `parse_and_check(source, code_prefix)` helper.

**WL001 (~8 tests):** .get with default (fires), .get without default (clean), setdefault with default (fires), setdefault without (clean), defaultdict with factory (fires), defaultdict no factory (clean), nested .get, non-dict .get (fires — advisory).

**WL002 (~4 tests):** 3-arg getattr (fires), 2-arg (clean), keyword default (fires), nested.

**WL003 (~5 tests):** `in` operator (fires), `hasattr` (fires), `not in` (fires), match/case MatchMapping (fires on 3.10+, skipped on 3.9), clean function with no existence checks.

**WL004 (~7 tests):** `except Exception` (fires), `except BaseException` (fires), bare except (fires), `except ValueError` (clean), tuple `except (Exception, ValueError)` (fires), qualified `builtins.Exception` (fires), `except*` (3.11+ only, guarded).

**WL005 (~6 tests):** `except: pass` (fires), `except: ...` (fires), `except: continue` (fires), `except: break` (fires), `except: log.error()` (clean), multiple handlers (mixed).

**Integration (~5 tests):** Entry point registration via `importlib.metadata`, flake8 runner with `--select=WL` against all-rules fixture, verify all 5 codes appear, verify `[advisory]` in messages, verify line numbers.

## Implementation Plan

### Task 1: Package Scaffold

Create `wardline-flake8/` directory with pyproject.toml (correct build-backend), `src/wardline_flake8/checker.py` + `__init__.py` re-export, empty rule modules, `tests/conftest.py` with parse helper.

### Task 2: WL001 — dict.get/setdefault/defaultdict

All three patterns. `.get()` and `.setdefault()` with `>=2` args. `defaultdict` constructor with factory arg. Message: `"WL001 [advisory] fallback default on dict access — run wardline scan for taint-context verdict"`. 8 tests.

### Task 3: WL002 — getattr

`getattr()` with 3+ args. Message: `"WL002 [advisory] getattr() with fallback default"`. 4 tests.

### Task 4: WL003 — Existence Checking

`in` / `not in` operator, `hasattr()`, `match/case` with `MatchMapping`/`MatchClass` (guarded for 3.9). Message: `"WL003 [advisory] existence checking as structural gate"`. 5 tests.

### Task 5: WL004 — Broad Exception Handlers

Bare except, `except Exception/BaseException`, qualified names (`builtins.Exception`), tuple handlers (any broad member), `TryStar` dedup (guarded for <3.11). Message: `"WL004 [advisory] broad exception handler"`. 7 tests.

### Task 6: WL005 — Silent Exception Handlers

Body is single `pass`, `...` (Ellipsis), `continue`, or `break`. Message: `"WL005 [advisory] silent exception handler"`. 6 tests.

### Task 7: Integration Tests

Entry point registration test (`importlib.metadata`). flake8 runner test with all-rules fixture. Verify codes, `[advisory]` tag, line numbers. 5 tests.

### Task 8: README

Installation, usage, error code table, **prominent "Evidence Pack Warning" section** (flake8 output is NOT authoritative — use `wardline scan` for compliance), CI integration notes (`--select=WL` for opt-in, `--extend-ignore=WL` for global runs), known limitations.

### Dependency Graph

```
Task 1 (scaffold) → Tasks 2-6 (parallel) → Task 7 (integration) → Task 8 (README)
```
