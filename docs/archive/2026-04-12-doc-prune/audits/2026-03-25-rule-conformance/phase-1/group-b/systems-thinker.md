# Group B — Systems Thinker Assessment

**Rules:** PY-WL-004 (WL-003: broad exception handlers), PY-WL-005 (WL-004: silent exception handling), PY-WL-006 (WL-005: audit-critical writes in broad handlers)

**Date:** 2026-03-25

---

## Inter-Rule Interaction

### Detection Surface Overlap

The three rules share the exception-handler AST surface but partition it along **orthogonal behavioral axes**:

- **PY-WL-004** fires on the **handler declaration** — the `except` clause catches too broadly (bare `except:`, `except Exception`, `except BaseException`, tuples containing broad types, `contextlib.suppress(Exception)`).
- **PY-WL-005** fires on the **handler body** — the body does nothing meaningful (`pass`, `...`, `continue`, `break`). It checks `len(handler.body) == 1` and inspects the single statement.
- **PY-WL-006** fires on the **interaction between handler breadth and body content** — specifically, audit-critical calls inside broad handlers, plus a secondary pass detecting success paths that bypass audit.

### Co-Firing Analysis

**PY-WL-004 + PY-WL-005 can co-fire on the same handler.** A handler like `except Exception: pass` is both broad (PY-WL-004) and silent (PY-WL-005). Both rules walk `ExceptHandler` nodes independently and apply their own predicates. There is no mutual exclusion.

**This co-firing is intentional and correct.** The two findings diagnose distinct failures: breadth (the handler catches too much) and silence (the handler does nothing). A broad handler that logs is less dangerous than a broad handler that swallows silently. The two findings produce different governance signals — PY-WL-004 flags the catch surface, PY-WL-005 flags evidence destruction. A reviewer addressing PY-WL-005 (adding logging) does not automatically resolve PY-WL-004 (the handler still catches too broadly). The findings are independently actionable.

**PY-WL-004 + PY-WL-006 can co-fire on the same handler.** A broad handler containing an audit call fires PY-WL-004 (broad catch) and PY-WL-006 (audit write in broad handler). Again, these diagnose distinct risks: PY-WL-004 flags the catch breadth generally; PY-WL-006 flags the specific danger that the audit write's own failure is masked by the broad catch.

**PY-WL-005 + PY-WL-006 cannot co-fire.** PY-WL-005 requires a single-statement body that is `pass`, `...`, `continue`, or `break`. PY-WL-006 requires the handler body to contain an audit-critical call. A handler with only `pass` cannot also contain an `audit()` call. These are mutually exclusive by construction.

**Summary of co-firing matrix:**

| Pair | Co-fire possible? | Intentional? |
|------|-------------------|-------------|
| 004 + 005 | Yes | Yes — distinct findings (breadth vs silence) |
| 004 + 006 | Yes | Yes — distinct findings (breadth vs audit masking) |
| 005 + 006 | No | N/A — mutually exclusive by handler body shape |

### PY-WL-006's Dependency on PY-WL-004's Detection Surface

PY-WL-006 reimplements broad-handler detection via `_is_broad_handler()` (lines 65-79 of `py_wl_006.py`) rather than depending on PY-WL-004's output. Both rules define the same `_BROAD_NAMES = frozenset({"Exception", "BaseException"})` and check the same patterns: bare `except:`, `ast.Name` in `_BROAD_NAMES`, `ast.Attribute` with `.attr` in `_BROAD_NAMES`, and tuples containing broad types.

**The detection surfaces are nearly identical but not perfectly aligned:**

1. PY-WL-004's `_resolve_broad_name()` handles `ast.Name`, `ast.Attribute`, and `ast.Tuple` containing broad members — this covers `except (Exception, ValueError):`.
2. PY-WL-006's `_is_broad_handler()` handles the same three cases with equivalent logic.
3. PY-WL-004 additionally checks `contextlib.suppress(Exception)` calls via `_check_suppress_call()`. PY-WL-006 does not check `contextlib.suppress` at all.
4. PY-WL-004 excludes immediate-reraise handlers (`_is_immediate_reraise`). PY-WL-006 does not — a broad handler that immediately re-raises but also contains an audit call on the re-raise path would fire PY-WL-006 but not PY-WL-004.

**Point 3 is a minor gap:** `contextlib.suppress(Exception)` around audit-critical code would fire PY-WL-004 but not PY-WL-006. The `suppress` context manager silently swallows exceptions, so an audit call inside `with suppress(Exception): audit_write()` has exactly the masking risk PY-WL-006 targets, but the rule does not detect it. This is a detection gap, not a systemic design flaw — it is addressable by extending PY-WL-006's handler scan to include `suppress` blocks.

**Point 4 is correct behavior:** A handler that immediately re-raises does not mask exceptions (PY-WL-004 correctly excludes it), but if the handler body contains only `raise exc` and somehow also an audit call, the re-raise would still propagate. In practice, PY-WL-004's `_is_immediate_reraise` requires `len(handler.body) == 1` with that single statement being a `Raise`, so no audit call can coexist. The asymmetry is harmless.

---

## Feedback Dynamics

### Governance Load per Rule

**PY-WL-004 matrix row (WL-003):**
`E/U, E/St, W/St, W/R, E/St, W/St, W/St, E/St`

- 1 UNCONDITIONAL (AUDIT_TRAIL)
- 4 STANDARD (PIPELINE, UNKNOWN_RAW, MIXED_RAW, and SHAPE_VALIDATED at W/St)
- Actually: AUDIT_TRAIL=E/U, PIPELINE=E/St, SHAPE_VALIDATED=W/St, EXTERNAL_RAW=W/R, UNKNOWN_RAW=E/St, UNKNOWN_SHAPE_VALIDATED=W/St, UNKNOWN_SEM_VALIDATED=W/St, MIXED_RAW=E/St
- Breakdown: 1 UNCONDITIONAL, 4 STANDARD, 1 RELAXED, 0 TRANSPARENT
- Wait — correcting: 4 cells are E/St or W/St (both STANDARD), 1 is W/R (RELAXED), 1 is E/U (UNCONDITIONAL). Total 8 cells: 1 U + 6 St + 1 R.
- **12.5% unconditional, 75% standard, 12.5% relaxed.** This is a light governance footprint — only AUDIT_TRAIL is non-negotiable.

**PY-WL-005 matrix row (WL-004):**
`E/U, E/St, E/St, E/St, E/St, E/St, E/St, E/St`

- 1 UNCONDITIONAL (AUDIT_TRAIL) + 7 STANDARD = **12.5% unconditional, 87.5% standard.**
- All cells are ERROR severity. Silent exception handling is always wrong, but governable outside AUDIT_TRAIL.

**PY-WL-006 matrix row (WL-005):**
`E/U, E/U, E/St, E/St, E/St, E/St, E/St, E/St`

- 2 UNCONDITIONAL (AUDIT_TRAIL, PIPELINE) + 6 STANDARD = **25% unconditional, 75% standard.**
- PIPELINE is UNCONDITIONAL because audit writes in pipeline handlers mask transformation errors that propagate downstream (spec 7.4(e)). This is the heaviest governance load in Group B.

**Aggregate Group B load:** Across 24 cells: 4 UNCONDITIONAL (16.7%), 19 STANDARD (79.2%), 1 RELAXED (4.2%), 0 TRANSPARENT. Compare to Group A's 7 UNCONDITIONAL (29%) — Group B is lighter on unconditional constraints, reflecting that exception handling is more context-dependent than value fabrication.

### False-Positive Pressure

**PY-WL-004 has the highest false-positive risk in Group B.** Broad exception handlers are common in legitimate Python code — top-level error handlers in CLI tools, retry decorators, task runners, and web request handlers. The spec acknowledges this by granting RELAXED governance in EXTERNAL_RAW and WARNING severity in SHAPE_VALIDATED, UNKNOWN_SHAPE_VALIDATED, and UNKNOWN_SEM_VALIDATED. The immediate-reraise exclusion (`_is_immediate_reraise`) is a critical false-positive reduction mechanism — handlers that catch broadly but immediately re-raise (a common logging/cleanup pattern) do not fire.

However, `_is_immediate_reraise` requires exactly one statement in the handler body, and that statement must be a bare `raise` or `raise <bound_name>`. A handler that logs and then re-raises (`except Exception as e: logger.error(e); raise`) does **not** qualify for the exclusion and will fire PY-WL-004. This is technically correct (the handler does more than re-raise), but generates findings on a common, low-risk pattern. The governance pathway (STANDARD in most contexts) handles this, but it contributes to exception register volume.

**PY-WL-005 has low false-positive risk.** The detection surface is narrow: exactly one statement in the handler body, and that statement must be `pass`, `...`, `continue`, or `break`. Legitimate uses of `except: pass` are rare in well-architected code. The rule is precise by construction.

**PY-WL-006 has moderate false-positive risk from heuristic audit detection.** The `_looks_audit_scoped()` function uses name-based heuristics: any call whose attribute starts with `audit`, `record`, or `emit`, or whose receiver contains `audit` or `ledger`. This could match non-audit calls (e.g., `record_count()`, `emit_event()` for telemetry). The `_AUDIT_FUNC_NAMES` set (`audit`, `record`, `emit`) is broad. The false positives are governable (STANDARD in most contexts), but they dilute the signal. The `_AUDIT_DECORATORS` mechanism (`@audit_writer`, `@audit_critical`) provides a precision path — teams can explicitly mark audit functions rather than relying on name heuristics.

### PY-WL-006's Dual Finding Mode

PY-WL-006 emits two distinct finding types:

1. **Audit-in-broad-handler** (lines 210-227): Audit-critical calls found inside broad exception handlers.
2. **Audit-bypass on success path** (lines 229-254): Success/fallback branches that can bypass audit calls on the normal path.

These serve different purposes. Type 1 addresses audit masking (the spec's stated concern for WL-005). Type 2 addresses audit completeness — a related but distinct property. Both use the same rule ID (PY-WL-006) and the same severity matrix row. This is a minor concern: the two finding types have different risk profiles and arguably warrant different governance treatment. A success-path audit bypass is a design-level concern; an audit call inside a broad handler is a code-level error. Combining them under one rule ID means governance cannot differentiate.

---

## Cross-Group Interaction

### Interaction with Group A (Fallback Defaults)

**Group A evasion into Group B is a well-documented cascade** (per the Group A systems-thinker assessment). The key dynamics:

1. **PY-WL-001/002 evasion via try/except enters PY-WL-004 territory.** Replacing `d.get("key", default)` with `try: val = d["key"] except KeyError: val = default` evades PY-WL-001 but enters PY-WL-004's scope if the except clause is broad. If the except clause is narrow (`except KeyError`), PY-WL-004 does not fire. This is the narrow-except evasion seam identified in the Group A assessment.

2. **Severity gradient from Group A to Group B in EXTERNAL_RAW:** PY-WL-001 is E/St, PY-WL-004 is W/R. An agent replacing `.get()` with try/except achieves a two-step downgrade (ERROR to WARNING, STANDARD to RELAXED). This is intentional per spec rationale — explicit exception handling is less dangerous than silent default fabrication — but it creates an exploitable gradient.

3. **PY-WL-003 evasion via try/except.** Replacing `if "key" in d:` with `try: val = d["key"] except KeyError: ...` evades PY-WL-003 but the handler may or may not fire PY-WL-004 depending on breadth. With a narrow `except KeyError`, none of the Group B rules fire. This is the same evasion seam.

**The narrow-except evasion seam is the primary cross-group gap.** An agent can evade all nine rules by using narrow exception handlers with fallback defaults in the except body. This requires: (a) knowing which specific exception to catch (agent capability), (b) substituting a default in the except body (the same fabrication risk as PY-WL-001), and (c) the handler being non-silent (avoiding PY-WL-005). The result is functionally identical to a `.get()` default but matches no rule's detection surface. The spec's "living pattern catalogue" principle (7.0) anticipates this — language bindings must extend detection as evasion variants emerge.

### Interaction with Group C (Structural Verification)

**PY-WL-007 (boundary rejection path) creates indirect pressure on Group B.** Validation boundaries are the primary contexts where broad exception handling is legitimate (parsing external data). PY-WL-004 in EXTERNAL_RAW is W/R — the lightest finding in Group B. Inside declared boundaries, the need for broad catches during parsing is recognized by the severity gradient. PY-WL-007 ensures those boundaries are structurally sound, preventing "fake boundary" declarations that exist solely to shift code into the EXTERNAL_RAW context for lighter PY-WL-004 findings.

**PY-WL-008/009 (validation ordering) have no direct interaction with Group B.** Exception handling rules are orthogonal to validation ordering constraints. However, a validation boundary that processes external data will legitimately contain both broad exception handlers (PY-WL-004) and audit-critical writes (PY-WL-006). The co-firing of PY-WL-004 + PY-WL-006 inside validation boundaries is the expected pattern — and it correctly flags the risk that audit writes inside broad handlers can be masked.

---

## Systemic Risk

### Reinforcing Loops

1. **Exception register growth from PY-WL-004.** Broad exception handlers are common in Python. PY-WL-004 at STANDARD governance in 6 of 8 taint states generates a steady flow of exception requests. Log-and-reraise handlers (not excluded by `_is_immediate_reraise` due to the multi-statement body) are a major contributor. Over time, the exception register for PY-WL-004 grows, reviewers treat PY-WL-004 exceptions as routine, and governance scrutiny declines. The spec's exception recurrence tracking (9.4) and age-based expiry are the prescribed balancing mechanisms. **This loop is adequately controlled if those mechanisms are implemented.**

2. **PY-WL-006 heuristic scope creep.** As the `_looks_audit_scoped()` heuristic flags non-audit calls (false positives), teams may respond by: (a) granting STANDARD exceptions for the false positives, or (b) refactoring away from naming conventions that trigger the heuristic. Path (a) erodes governance; path (b) is a healthy response but may push teams away from descriptive naming (`record_event` renamed to avoid triggering the heuristic). The `@audit_writer` / `@audit_critical` decorator mechanism provides the correct escape: teams that adopt explicit audit marking can rely on the decorator path rather than the name heuristic, reducing false positives without renaming. **This loop is self-correcting if the decorator mechanism is adopted.**

### Balancing Loops

1. **Co-firing as graduated signal.** The 004+005 and 004+006 co-firing pairs produce graduated severity signals. A handler that is broad AND silent fires two rules (maximum governance load). A handler that is broad but logs fires only PY-WL-004 (lower load). A handler that is narrow but silent fires only PY-WL-005 (no PY-WL-004 involvement). This creates a natural severity gradient that matches risk: the most dangerous pattern (broad + silent) generates the most governance pressure.

2. **PY-WL-005's narrow detection surface limits governance volume.** Only single-statement silent bodies fire. A handler with `pass; # intentional` (two statements) does not fire — but this is a potential evasion via comment insertion. More importantly, the narrow surface means PY-WL-005 findings are high-signal: when it fires, the handler is genuinely doing nothing. This makes PY-WL-005 the most trustworthy rule in Group B from a governance perspective.

3. **PY-WL-006's dual mode creates architectural pressure.** The audit-bypass finding (type 2) pushes functions toward having audit calls on all success paths. This is a healthy architectural forcing function — it promotes audit completeness as a structural property rather than an afterthought. The pressure is proportional: functions without any audit calls on the normal path do not fire (the `_has_normal_path_audit` gate ensures this), so the rule only applies to functions that have started doing audit but have incomplete coverage.

### Steady-State Behavior

Under sustained enforcement, a codebase will converge toward:

1. **Narrow exception handlers with explicit error handling.** PY-WL-004 pushes handlers from broad to narrow types. PY-WL-005 pushes handlers from silent to logging/re-raising. The intersection of these pressures produces the intended pattern: `except SpecificError as e: logger.error(...); raise` rather than `except Exception: pass`.

2. **Audit writes outside exception handlers or in dedicated finally blocks.** PY-WL-006 pushes audit-critical writes out of broad handlers. The natural refactoring is to move audit writes to `finally` blocks (which execute regardless of exception state) or to narrow handlers that catch only specific expected failures. This is the correct architectural response.

3. **Exception register dominated by PY-WL-004 log-and-reraise patterns.** The most common legitimate broad-handler pattern — `except Exception as e: logger.error(e); raise` — fires PY-WL-004 but not PY-WL-005 (non-silent) and not PY-WL-006 (no audit call). These will be the majority of PY-WL-004 exceptions. The recurrence tracking mechanism (spec 9.4) will flag these as patterns, potentially motivating a future `_is_log_and_reraise` exclusion similar to `_is_immediate_reraise`.

4. **PY-WL-006 heuristic findings declining as teams adopt `@audit_writer` / `@audit_critical` decorators.** The name-based heuristic generates initial volume; explicit decorator marking provides a precision path that reduces false positives over time. Teams that invest in decorator marking see declining PY-WL-006 noise, creating a positive incentive loop.

---

## Verdict: PASS

**Group B's three rules form a coherent, well-layered enforcement surface with intentional co-firing, adequate governance load distribution, and healthy convergence dynamics.**

Key strengths:
- Co-firing between 004+005 and 004+006 produces graduated severity signals that match actual risk levels. The mutual exclusion of 005+006 is structurally guaranteed.
- PY-WL-006's independent reimplementation of broad-handler detection is nearly identical to PY-WL-004's and correctly aligned with the spec's `_BROAD_NAMES` set.
- The immediate-reraise exclusion on PY-WL-004 is a well-designed false-positive reduction mechanism.
- PY-WL-005's narrow detection surface (single-statement silent bodies) produces high-signal, low-noise findings.
- PY-WL-006's `@audit_writer` / `@audit_critical` decorator mechanism provides a precision path that reduces heuristic false positives over time.
- The governance load distribution (16.7% UNCONDITIONAL across Group B) is lighter than Group A (29%), correctly reflecting that exception handling is more context-dependent than value fabrication.

Residual concerns (not sufficient for CONCERN or FAIL):
- **`contextlib.suppress` gap in PY-WL-006.** PY-WL-004 detects `contextlib.suppress(Exception)` but PY-WL-006 does not check suppress blocks for audit calls. An audit write inside `with suppress(Exception):` has the same masking risk PY-WL-006 targets. This is a detection gap addressable by extending PY-WL-006.
- **Narrow-except evasion seam (cross-group).** The path through narrow `except` clauses with fallback defaults in the handler body evades both Group A and Group B rules. This is the same gap identified in the Group A assessment and is the primary evasion vector across the combined enforcement surface.
- **PY-WL-004 log-and-reraise volume.** Multi-statement handlers that log and re-raise are a common legitimate pattern not excluded by `_is_immediate_reraise`. These will dominate PY-WL-004's exception register. A future `_is_log_and_reraise` exclusion would reduce governance load without weakening detection.
- **PY-WL-006 dual finding modes under one rule ID.** Audit-in-broad-handler and audit-bypass-on-success-path are distinct risk types sharing one governance identity. This limits the ability to apply different governance treatment to fundamentally different finding classes.
