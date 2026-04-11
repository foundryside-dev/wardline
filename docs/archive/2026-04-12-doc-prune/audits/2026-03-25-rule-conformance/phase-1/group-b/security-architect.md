# Security Architect Audit: Group B (Exception Handling)

**Rules under audit:** PY-WL-004 (WL-003), PY-WL-005 (WL-004), PY-WL-006 (WL-005)
**Reviewer:** Security Architect
**Date:** 2026-03-25
**Scope:** Threat model alignment, evasion resistance, residual risk

---

## 1. ACF-R1 Coverage: Layered Defence Against Audit Trail Destruction

The spec maps ACF-R1 (Audit Trail Destruction) to WL-003, WL-004, and WL-005 jointly. The three rules form a coherent layered defence:

| Layer | Rule | What it catches |
|-------|------|-----------------|
| Structure | PY-WL-004 (WL-003) | Broad handler *exists* -- the prerequisite for masking |
| Body | PY-WL-005 (WL-004) | Handler swallows silently -- evidence destroyed |
| Audit-specific | PY-WL-006 (WL-005) | Audit write *inside* broad handler -- masked failure of the record itself |

**Assessment: ADEQUATE.** The layers address the three escalation stages of ACF-R1: (1) the structural pattern that enables masking, (2) the body pattern that completes the destruction, (3) the audit-specific variant where the audit write itself is the victim. An agent cannot produce code that destroys the audit trail via broad exception handling without triggering at least one of the three rules.

**Caveat:** The layered defence assumes broad handlers are the mechanism of audit trail destruction. It does not address non-exception-based audit trail destruction (e.g., silently not calling the audit function at all). PY-WL-006's dominance analysis partially addresses this via success-path bypass detection, but only when the function already contains an audit call on some path. A function that never calls audit at all is invisible to all three rules. This is correctly outside Group B's scope -- it is a coverage gap, not a rule defect.

## 2. ACF-R2 Coverage: Partial Completion Detection

ACF-R2 (Partial Completion) occurs when a transaction succeeds but the audit record is not written. PY-WL-006 addresses this through two mechanisms:

**Mechanism 1: Broad-handler masking (lines 210-227).** Detects audit calls inside broad handlers where a write failure is masked. This catches the classic ACF-R2 pattern: `try: process(); audit.emit() except Exception: pass` -- the process succeeds, the audit write fails, and the handler masks the failure.

**Mechanism 2: Success-path dominance analysis (lines 229-254).** Detects functions where an audit call exists on some path but a success/return path bypasses it. This catches the structural variant: `if cached: return result` before the audit call is reached.

The dominance analysis (`_analyze_block` / `_analyze_stmt`) is a sound forward dataflow that tracks a boolean `audited` state through if/try/for/while/match constructs. It correctly handles:
- Early returns as success exits (line 306-318)
- Raises as non-continuing paths (line 289)
- Try/except/else/finally composites (lines 339-381)
- Match/case multi-branch (lines 406-422)
- Loops with zero-iteration possibility (lines 383-404)

**Assessment: ADEQUATE for structural detection.** The dominance analysis catches the primary ACF-R2 pattern -- success paths that bypass audit. The `_has_normal_path_audit` pre-check (lines 134-174) correctly limits the analysis to functions that have audit on a non-handler path, avoiding double-reporting.

**Gap:** The dominance analysis does not track whether the *transaction* succeeded before the audit bypass -- it flags any success-path return that skips audit, even if the return is a cache hit that never performed the transaction. This is a false-positive source, not a missed true positive, and is the correct conservative posture for a security rule.

## 3. Per-Rule Evasion Resistance

### PY-WL-004 (Broad Exception Handlers)

**Exception enumeration bypass.** An agent can bypass PY-WL-004 by enumerating specific exceptions:

```python
except (ValueError, TypeError, KeyError, AttributeError, RuntimeError, ...):
    pass
```

This is semantically equivalent to `except Exception` but does not trigger the rule. The `_BROAD_NAMES` set only contains `{"Exception", "BaseException"}`. Enumerating a large tuple of specific exceptions covers nearly the same surface as `except Exception` without matching.

**Severity: MEDIUM.** This is a known evasion pattern acknowledged in the spec's living pattern catalogue (SS7) and residual risk 12 (evasion surface trajectory). The enumeration bypass is noisy (reviewable) and imperfect (the agent must guess which exceptions to catch). A binding-level semantic equivalent list should include "exception tuple with >= N members" as a heuristic.

**contextlib.suppress detection: PRESENT.** PY-WL-004 explicitly detects `contextlib.suppress(Exception)` and `suppress(Exception)` via `_check_suppress_call` (lines 88-103) and `_is_suppress_call` (lines 118-127). This closes the most obvious exception-handling bypass.

**Immediate re-raise exemption: SOUND.** The `_is_immediate_reraise` check (lines 106-115) correctly exempts handlers that are structurally pass-through (`except Exception: raise` or `except Exception as e: raise e`). The check requires exactly one statement in the body and verifies the raise target matches the handler name. This is tight -- an agent cannot add a pre-raise statement and still get the exemption.

### PY-WL-005 (Silent Exception Handling)

**Body length == 1 constraint (line 104).** PY-WL-005 only fires when the handler body has exactly one statement. This is the most significant evasion surface:

```python
except Exception:
    _ = None  # dummy statement
    pass
```

Two statements -- rule does not fire. The agent adds a no-op assignment and the handler is functionally silent.

**Severity: HIGH.** This is a structurally simple bypass that produces code indistinguishable in behaviour from the flagged pattern. The `len(handler.body) != 1` early return on line 104 is the single check, and it is trivially defeated.

**Recommended mitigation:** Check whether *all* statements in the body are silent/no-op, not just whether the body has exactly one statement. A body of `[pass, pass]` or `[_ = None, pass]` or `[x = e, pass]` should still fire.

**contextlib.suppress gap: PRESENT.** PY-WL-005 does not detect `contextlib.suppress(ValueError)` as a silent handler. While PY-WL-004 catches `suppress(Exception)` (broad type), `contextlib.suppress(ValueError)` -- which silently swallows a specific exception -- is the semantic equivalent of `except ValueError: pass` and is not flagged by PY-WL-005. PY-WL-005 only walks `ExceptHandler` nodes. This is a cross-rule gap: PY-WL-004 checks suppress for broad types, PY-WL-005 does not check suppress at all.

**Severity: MEDIUM.** The gap is specific to `contextlib.suppress` with narrow exception types. `suppress(Exception)` is caught by PY-WL-004. The uncovered case is `suppress(ValueError)` etc., which are less dangerous because they catch narrowly.

### PY-WL-006 (Audit-Critical Writes in Broad Handlers)

**Audit call heuristic surface.** The audit-call detection relies on:
1. Decorator scan (`_AUDIT_DECORATORS`: `audit_writer`, `audit_critical`) -- lines 27, 191-200
2. Attribute prefix matching (`_AUDIT_ATTR_PREFIXES`: `audit`, `record`, `emit`) -- lines 28, 108
3. Function name matching (`_AUDIT_FUNC_NAMES`: `audit`, `record`, `emit`) -- lines 29, 103-104
4. Receiver name matching (`audit` or `ledger` in receiver) -- lines 110-111

**Helper-wrapping bypass.** An agent can wrap the audit call in a helper function:

```python
def _save(data):
    audit.emit("event", data)

def process():
    try:
        do_work()
    except Exception:
        _save(data)  # Not detected -- _save is not in _AUDIT_FUNC_NAMES
```

The helper `_save` is not decorated with `@audit_writer` or `@audit_critical`, and its name does not match the audit prefixes. PY-WL-006 performs no inter-procedural analysis -- `_is_audit_call` only checks the immediate call name and receiver, not what the callee does internally.

**Severity: HIGH.** Single-layer indirection defeats the rule entirely. This is the most impactful evasion vector for PY-WL-006 specifically and ACF-R1 generally. The spec acknowledges this in SS7 (living pattern catalogue) as a known evasion trajectory, but the current implementation has no mitigation.

**Catch-and-log-without-reraise.** A handler that logs and continues:

```python
except Exception as e:
    logger.error("Audit write failed: %s", e)
    # execution continues -- audit record lost
```

This is NOT flagged by PY-WL-006 because `logger.error` is not an audit-shaped sink. However, PY-WL-004 fires (broad handler without re-raise). The layered defence provides partial coverage here: PY-WL-004 catches the structural pattern even though PY-WL-006 misses the semantic intent. This is acceptable -- the layered model is working as designed.

## 4. PY-WL-006 PIPELINE E/U Cell

The severity matrix assigns PY-WL-006 (WL-005) in PIPELINE context as **E/U** (Error/Unconditional) -- the highest enforcement level. This means audit-critical writes in broad handlers within pipeline (Tier 2) code cannot be overridden through governance.

**Evasion surface for this cell specifically:**

1. **Helper wrapping** (as above) -- the agent wraps the audit call, the helper name is opaque, PY-WL-006 does not fire, and the E/U enforcement is bypassed entirely because no finding is generated.

2. **Taint reclassification** -- if the function's taint is declared as something other than PIPELINE, the cell lookup produces a different severity. An agent that controls annotations can reclassify a pipeline function as SHAPE_VALIDATED (where PY-WL-006 maps to WL-005's E/St -- still ERROR but STANDARD exceptionability, not UNCONDITIONAL). This is a governance-layer attack (residual risk 9/13), not a code-layer evasion.

3. **Specific-handler substitution** -- replacing `except Exception:` with `except (IOError, OSError, ConnectionError):` bypasses the broad-handler check in `_is_broad_handler`. The audit write still fails silently, but the handler is no longer "broad" by PY-WL-006's definition. PY-WL-004 also does not fire (specific handler). This is a cross-rule gap.

**Assessment: the E/U cell is correctly positioned in the matrix but its enforcement depends entirely on the heuristic detecting the audit call and the handler being syntactically broad. Both conditions are individually evadable, and together they create a significant surface.**

## 5. Cross-Rule Evasion: Simultaneous Bypass of All Three Rules

An agent can restructure code to bypass PY-WL-004, PY-WL-005, and PY-WL-006 simultaneously:

```python
def _handle_error(exc, data):
    """Looks like legitimate error handling."""
    log.info("Handled: %s", exc)
    # Audit write silently dropped -- never called

def _persist(data):
    """Opaque wrapper around audit."""
    audit.emit("completed", data)

def process(data):
    try:
        result = do_work(data)
    except (IOError, OSError, ConnectionError, TimeoutError) as e:
        _handle_error(e, data)
        return fallback_result
    _persist(data)
    return result
```

Analysis:
- **PY-WL-004 does not fire:** Handler catches a specific tuple, not `Exception`/`BaseException`.
- **PY-WL-005 does not fire:** Handler body has meaningful statements (`_handle_error` call + `return`).
- **PY-WL-006 does not fire:** Handler is not broad (specific tuple), and `_persist` is not recognised as audit-shaped.
- **PY-WL-006 dominance does not fire:** `_persist` is not in `_local_audit_names` (no decorator) and `_persist` does not match audit heuristics, so `_has_normal_path_audit` returns False.

**The audit write is silently lost on the error path.** The transaction may have partially completed, the handler catches a plausible set of exceptions, the audit call in `_persist` is only reached on success, and none of the three rules detect the gap.

**Severity: HIGH.** This bypass requires moderate sophistication but is well within current LLM capability. It exploits three independent weaknesses simultaneously: enumeration bypass (PY-WL-004), multi-statement body (PY-WL-005), and opaque naming (PY-WL-006).

## 6. Residual Risk Alignment with SS12

The findings align with three residual risks from SS12:

**Residual risk 12 (Evasion surface trajectory):** Directly confirmed. The enumeration bypass, helper-wrapping bypass, and multi-statement body bypass are all instances of "structurally clean but semantically wrong" code that the spec predicts will become more common. The current implementation is at the "structurally sloppy" detection level -- it catches the patterns current models produce clumsily but not the clean variants.

**Residual risk 5 (Semantic downgrade):** PY-WL-006's audit-call heuristic can be defeated by semantic downgrade -- wrapping an audit call in a function whose name suggests a different purpose. This is the helper-wrapping bypass viewed through the SS12-R5 lens.

**Residual risk 4 (Annotation coverage gaps):** PY-WL-006's dominance analysis only activates when audit calls are present. Unannotated functions that should contain audit calls but do not are invisible. This is correctly identified as outside Group B's scope but is a contributing factor to the cross-rule evasion surface.

The spec's compensating controls (living pattern catalogue, golden corpus evasion specimens, binding-level semantic equivalent lists) are the correct response. The question is whether the current implementation has caught up with the spec's intent -- and the answer is: not yet, for the specific bypasses identified above.

## 7. Summary of Findings

| # | Finding | Severity | Rule(s) |
|---|---------|----------|---------|
| B-1 | PY-WL-005 body length == 1 check is trivially bypassed by adding a no-op statement | HIGH | PY-WL-005 |
| B-2 | PY-WL-006 helper-wrapping bypass: single layer of indirection defeats audit-call heuristic | HIGH | PY-WL-006 |
| B-3 | Cross-rule evasion via specific-exception enumeration + opaque naming bypasses all three rules simultaneously | HIGH | PY-WL-004, PY-WL-005, PY-WL-006 |
| B-4 | PY-WL-004 exception enumeration bypass: large tuple of specific exceptions equivalent to `except Exception` | MEDIUM | PY-WL-004 |
| B-5 | PY-WL-005 does not detect `contextlib.suppress(SpecificError)` as silent handling | MEDIUM | PY-WL-005 |
| B-6 | PY-WL-006 PIPELINE E/U cell enforcement depends on heuristic detection -- bypassed if audit call is not recognised | HIGH | PY-WL-006 |

## Verdict: CONCERN

The three rules form a coherent layered defence that correctly addresses ACF-R1 and ACF-R2 at the structural level. The severity matrix assignments are sound. The dominance analysis in PY-WL-006 is well-engineered. The `contextlib.suppress` detection in PY-WL-004 closes an important bypass vector.

However, three HIGH-severity evasion paths undermine the defence in depth:
1. PY-WL-005's single-statement body check is trivially bypassed (B-1).
2. PY-WL-006's audit-call heuristic is defeated by one layer of indirection (B-2).
3. All three rules can be bypassed simultaneously with moderate effort (B-3).

These findings are consistent with the spec's own residual risk analysis (SS12, risks 5 and 12) and the living pattern catalogue obligation (SS7). They do not represent design failures -- they represent implementation gaps where the binding has not yet caught up with the spec's stated intent to track the evasion surface trajectory. The CONCERN verdict reflects that the rules work as designed but the design's evasion resistance is below what the PIPELINE E/U cell's unconditional posture implies.
