# Group B -- Static Analysis Specialist Assessment

**Audit date:** 2026-03-25
**Rules under review:** PY-WL-004, PY-WL-005, PY-WL-006
**Spec mapping:** PY-WL-004 implements framework WL-003 (catching all exceptions broadly). PY-WL-005 implements framework WL-004 (catching exceptions silently). PY-WL-006 implements framework WL-005 (audit-critical writes in broad exception handlers).

---

## False Positive Analysis

### PY-WL-004: Broad Exception Handlers

**FP-004-1: Broad catch with cleanup-then-reraise (multi-statement body).**
The `_is_immediate_reraise` method requires `len(handler.body) == 1` and that single statement to be a `raise`. This correctly suppresses:
- `except Exception: raise` (bare re-raise)
- `except Exception as e: raise e` (named re-raise)

But it fires on cleanup-then-reraise patterns:
```python
except Exception as e:
    cleanup_resources()
    raise
```
This has `len(handler.body) == 2`, so `_is_immediate_reraise` returns False and the rule fires.

**Verdict:** By-design. The spec's concern (WL-003) is that broad catches "prevent errors from being recorded." A cleanup-then-reraise handler DOES re-raise, but the cleanup code could itself throw and mask the original exception. The finding is defensible, though the severity could be debated. The immediate-reraise suppression is correctly narrow.

**Frequency estimate:** MODERATE. Cleanup-then-reraise is a common pattern (resource cleanup, lock release, transaction rollback). Expect 5-15 findings per project in code with resource management.

**FP-004-2: `contextlib.suppress` with broad type fires even when usage is genuinely scoped.**
```python
with contextlib.suppress(Exception):
    optional_cache.invalidate(key)
```
The rule fires on `suppress(Exception)` regardless of what the suppressed block does. If the suppressed operation is genuinely non-critical (cache invalidation, optional metrics), this is a false positive in the human sense but correct per the spec -- the spec says broad exception catching is wrong because it prevents error recording. `contextlib.suppress` is explicitly a silencing mechanism.

**Verdict:** By-design. The spec does not distinguish "acceptable silencing contexts." Governance (STANDARD exceptionability in most taint states) is the intended resolution.

**Frequency estimate:** LOW-MODERATE. `contextlib.suppress(Exception)` is less common than bare `except Exception`.

**FP-004-3: `suppress()` name collision with non-contextlib functions.**
The `_is_suppress_call` method matches ANY function named `suppress` with a broad exception arg:
```python
def suppress(exc_type):
    """Custom function unrelated to exception handling."""
    ...
suppress(Exception)  # Flagged as broad suppression
```
The check matches `ast.Name` with `id == "suppress"` without verifying it is `contextlib.suppress`.

**Frequency estimate:** NEGLIGIBLE. `suppress` as a bare function name is uncommon outside contextlib imports.

**FP-004-4: Broad catch in test fixtures / test helpers.**
Test code commonly uses `except Exception` for cleanup in fixtures:
```python
except Exception:
    test_db.rollback()
    raise
```
This specific pattern (cleanup + reraise) IS suppressed by the two-statement check failure described in FP-004-1. Whether test code should be excluded is a policy question, not a scanner question.

**Frequency estimate:** LOW. Depends on test structure.

### PY-WL-005: Silent Exception Handling

**FP-005-1: `pass` in exception handler where silence is the correct semantic.**
The rule fires on ALL single-statement `pass`/`...`/`continue`/`break` handlers regardless of exception type:
```python
except FileNotFoundError:
    pass  # File doesn't exist, that's fine
```
This fires PY-WL-005 even for narrow, specific exception types where silencing may be intentional.

**Verdict:** By-design. The spec (WL-004) says "the exception and its diagnostic context are lost" -- this applies to specific exceptions too. Governance through STANDARD exceptionability handles legitimate cases. The rule correctly does not distinguish broad vs narrow exception types because silent handling of ANY exception destroys evidence.

**Frequency estimate:** MODERATE. Expect 5-20 legitimate `except SpecificError: pass` patterns per project, particularly around file operations, optional imports, and cleanup.

**FP-005-2: Two-statement body with `pass` does not fire.**
```python
except ValueError:
    pass
    logging.info("x")
```
The rule checks `len(handler.body) != 1` and returns early. This is correct -- the handler DOES take action (the logging call). The `pass` is syntactically redundant but the body is not silent.

**Verdict:** Correct behaviour. Not a false positive concern.

**FP-005-3: Docstring-only handler is not detected as silent.**
```python
except Exception:
    """This exception is expected and intentionally swallowed."""
```
A single-statement handler whose body is a string expression (docstring) is NOT flagged. `_silent_message` only checks for `ast.Pass`, `ast.Continue`, `ast.Break`, and Ellipsis. A string constant is `ast.Expr(value=ast.Constant(value=<str>))`, which does not match any of these.

**Verdict:** This is arguably a false NEGATIVE (see FN-005-1 below), not a false positive. The handler takes no action -- the string literal is a no-op at runtime. However, one could argue the string documents intent, making it a "comment" rather than silence.

### PY-WL-006: Audit-Critical Writes in Broad Exception Handlers

**FP-006-1: "emit" as an audit function name is overly broad.**
`_AUDIT_FUNC_NAMES = frozenset({"audit", "record", "emit"})` and `_AUDIT_ATTR_PREFIXES = ("audit", "record", "emit")`. The prefix `"emit"` matches:
- `event_bus.emit("user_clicked", data)` -- event-driven architecture, not audit
- `signal.emit(value)` -- Qt/PyQt signals
- `emitter.emit("metric_name", 42)` -- metrics/telemetry
- `socket.emit("event", payload)` -- Socket.IO

The `_looks_audit_scoped` check fires when `attr == prefix or attr.startswith(prefix + "_")`. So `emit` matches exactly, and `emit_event`, `emit_signal`, `emit_metric` all match via the prefix check.

**Frequency estimate:** MODERATE. In event-driven codebases (PyQt, Socket.IO, asyncio event systems), `emit()` calls inside exception handlers will generate false positives. In a typical event-driven project, expect 5-15 false positive findings.

**Mitigation:** The receiver name check (`"audit" in receiver_lower or "ledger" in receiver_lower`) provides partial filtering -- `signal.emit()` will NOT fire because `"signal"` contains neither `"audit"` nor `"ledger"`. The issue is the bare function name `emit` in `_AUDIT_FUNC_NAMES` and the attribute prefix match when `attr == "emit"` exactly.

Tracing the code path: `_looks_audit_scoped` first checks `isinstance(call.func, ast.Name)` and returns `call.func.id in _AUDIT_FUNC_NAMES`. A bare `emit(data)` call IS flagged. For `isinstance(call.func, ast.Attribute)`, the check `any(attr == prefix or attr.startswith(prefix + "_") for prefix in _AUDIT_ATTR_PREFIXES)` fires for `obj.emit(data)` regardless of receiver. This returns True before the receiver check runs.

**Verdict:** CONCERN. The `emit` prefix matches non-audit patterns in event-driven code. The prefix check at line 108 short-circuits before the receiver-name check at line 110-111, so `signal.emit()` DOES fire despite `signal` not containing `audit` or `ledger`. The receiver-name check only runs for attributes that DON'T match the prefix list.

**FP-006-2: "record" as an audit function name is moderately broad.**
`record()` and `record_*()` match:
- `db.record_metric(name, value)` -- metrics recording
- `cache.record_hit()` -- cache statistics
- `history.record_change(delta)` -- change tracking (may or may not be audit)

**Frequency estimate:** LOW-MODERATE. Less common than `emit` but still generates noise in instrumentation-heavy code.

**FP-006-3: Dominance analysis false positives on legitimate early returns.**
The success-path bypass analysis flags returns that precede audit calls:
```python
def process(data):
    if data is None:
        return None  # <-- flagged as "bypass audit"
    result = transform(data)
    audit.emit("processed", data)
    return result
```
The `return None` IS flagged because `_analyze_return` sees `audited=False` (no audit call has occurred yet) and emits a bypass finding.

**Assessment:** This is a genuine precision concern. Guard-clause returns (null checks, validation failures, cache hits) that occur BEFORE the point where audit is meaningful should not be flagged as "bypassing audit." The analysis does not distinguish between:
- (a) A success path that produces a meaningful result without auditing (dangerous)
- (b) A guard clause that rejects invalid input before the auditable operation begins (benign)

Both produce `_BlockAnalysis(bypass_nodes=(stmt,))` when `audited=False`.

**Frequency estimate:** HIGH. Guard clauses are extremely common. A function with 2-3 guard clauses before an audit call will produce 2-3 false positive bypass findings.

**Verdict:** CONCERN. The dominance analysis conflates "early rejection before audit-worthy work" with "success path that skips audit." This will generate significant false positive volume in functions with guard clauses.

**FP-006-4: `_has_normal_path_audit` gate correctness.**
The dominance analysis only runs if `_has_normal_path_audit(node.body, ...)` returns True -- i.e., the function must contain an audit call on a non-handler path. This gate correctly prevents the dominance analysis from running on functions that have no audit calls at all. It also correctly prevents it from running on functions where audit calls only appear in exception handlers (which is the handler-masking pattern, not the bypass pattern).

**Verdict:** The gate is correctly designed. The false positive issue in FP-006-3 is downstream of this gate.

---

## False Negative Analysis

### PY-WL-004: Broad Exception Handlers

**FN-004-1: `contextlib.suppress` imported under alias.**
```python
from contextlib import suppress as s
with s(Exception):
    risky()
```
The `_is_suppress_call` checks for `ast.Name` with `id == "suppress"`. An alias `s` does not match. Import alias tracking is not implemented.

**Agent production likelihood:** LOW. AI agents typically use the canonical import form.

**FN-004-2: Dynamic exception types.**
```python
exc_type = Exception
try:
    risky()
except exc_type:
    handle()
```
`_resolve_broad_name` checks `ast.Name.id` directly against `_BROAD_NAMES`. A variable reference like `exc_type` resolves to a Name node with `id="exc_type"`, not `id="Exception"`. The rule does not perform constant propagation.

**Agent production likelihood:** LOW. AI agents rarely introduce indirection for exception types.

**FN-004-3: Exception class from module attribute.**
```python
import builtins
try:
    risky()
except builtins.Exception:
    handle()
```
This IS detected. `_resolve_broad_name` handles `ast.Attribute` where `.attr in _BROAD_NAMES`. The `builtins.Exception` form is correctly caught.

**Detection status:** DETECTED. Not a false negative.

**FN-004-4: Exception type constructed via `type()` or metaclass.**
```python
BroadCatch = type("BroadCatch", (Exception,), {})
try:
    risky()
except BroadCatch:
    handle()
```
Not detected. The `BroadCatch` name is not in `_BROAD_NAMES`. Detecting dynamically constructed exception types requires type inference.

**Agent production likelihood:** NEGLIGIBLE.

**FN-004-5: Exception aliasing via assignment.**
```python
E = Exception
try:
    risky()
except E:
    handle()
```
Not detected. Same constant-propagation limitation as FN-004-2.

**Agent production likelihood:** LOW-MODERATE. AI agents occasionally alias exception types for readability.

**FN-004-6: `contextlib.suppress` used as decorator (rare but valid).**
```python
@contextlib.suppress(Exception)
def risky():
    ...
```
This is invalid Python (`suppress` is a context manager, not a decorator), so it is not a real concern.

**FN-004-7: Nested `suppress` call inside expression.**
```python
result = (contextlib.suppress(Exception).__enter__(), risky(), None)
```
This would match because the rule walks all `ast.Call` nodes in the function body via `walk_skip_nested_defs`. The `suppress(Exception)` call is found regardless of position in an expression.

**Detection status:** DETECTED. Not a false negative.

### PY-WL-005: Silent Exception Handling

**FN-005-1: Docstring-only handler body.**
```python
except Exception:
    """Intentionally swallowed."""
```
Not detected. The body has `len == 1` and the statement is `ast.Expr(ast.Constant(value="..."))`. `_silent_message` does not check for string constants. At runtime, this is a no-op -- functionally identical to `pass`.

**Agent production likelihood:** MODERATE. AI agents sometimes produce docstring-style comments in exception handlers when instructed to "document why the exception is suppressed."

**FN-005-2: `None` expression as handler body.**
```python
except Exception:
    None
```
Not detected. Same gap as FN-005-1 -- a bare `None` expression is a no-op.

**Agent production likelihood:** LOW.

**FN-005-3: Multi-statement all-silent body.**
```python
except Exception:
    pass
    pass
```
Not detected. `len(handler.body) == 2`, so the early return triggers. The body is entirely silent (two `pass` statements) but the length check prevents detection.

**Agent production likelihood:** NEGLIGIBLE.

**FN-005-4: Comment-only handler body (syntactically impossible in Python).**
Python cannot have a handler body consisting solely of comments -- a `pass` or other statement is required. This is not a real gap.

**FN-005-5: Lambda-body silence via assignment to throwaway variable.**
```python
except Exception as e:
    _ = e
```
Not detected. The assignment IS a statement, so `len(handler.body) == 1` passes, but `_silent_message` returns None for `ast.Assign`. The underscore convention signals intent to discard, but the rule does not interpret variable naming conventions.

**Agent production likelihood:** LOW-MODERATE. Some AI agents produce `_ = e` as a "use the variable" pattern to avoid linter warnings.

**FN-005-6: `contextlib.suppress` as silent handler.**
```python
with contextlib.suppress(ValueError):
    risky()
```
PY-WL-005 does not check for `contextlib.suppress` at all -- it only examines `ExceptHandler` nodes. `suppress()` is semantically identical to `except ValueError: pass`. Note that PY-WL-004 DOES check for `suppress` with broad types, but PY-WL-005 does not check for `suppress` with ANY types.

**Agent production likelihood:** HIGH. AI agents frequently use `contextlib.suppress` as a "cleaner" way to silence exceptions. This is the most significant recall gap for PY-WL-005.

**Verdict:** CONCERN. `contextlib.suppress()` with specific exception types is a semantic equivalent of `except SpecificType: pass` and is not detected by PY-WL-005. PY-WL-004 only catches the broad-type variant.

### PY-WL-006: Audit-Critical Writes in Broad Exception Handlers

**FN-006-1: Audit call wrapped in helper function.**
```python
def log_audit(event, data):
    audit.emit(event, data)

def process(data):
    try:
        transform(data)
    except Exception:
        log_audit("failed", data)
```
`log_audit` is not in `_local_audit_names` (no `@audit_writer` decorator) and `_looks_audit_scoped` checks the call name `log_audit`, which does not match `_AUDIT_FUNC_NAMES` or `_AUDIT_ATTR_PREFIXES`. The indirect audit call is missed.

**Agent production likelihood:** MODERATE. AI agents extract helper functions naturally, especially when told to "reduce duplication" in exception handlers.

**FN-006-2: Audit call via f-string or format method.**
```python
except Exception:
    audit_log.write(f"Event {event_id} failed at {timestamp}")
```
`audit_log.write()` -- the method name `write` does not match any prefix in `_AUDIT_ATTR_PREFIXES`. However, the receiver `audit_log` contains `"audit"` in its lowercased form, so `_looks_audit_scoped` returns True via the receiver check at line 111.

**Detection status:** DETECTED. Not a false negative (the receiver name heuristic catches it).

**FN-006-3: Audit call through class method invocation.**
```python
except Exception:
    AuditService.create_entry(data)
```
`_call_name` returns `"create_entry"`. `_looks_audit_scoped` checks `attr == "create_entry"` -- does not match any `_AUDIT_ATTR_PREFIXES`. Then checks receiver: `_receiver_name` returns `"AuditService"`, lowercased to `"auditservice"`, which contains `"audit"`. Returns True.

**Detection status:** DETECTED. The receiver-name heuristic catches class-level audit calls.

**FN-006-4: Audit through external library with non-audit naming.**
```python
except Exception:
    structlog.get_logger().bind(event="audit").msg("record_created")
```
The chained call has `_call_name` returning `"msg"`. `_looks_audit_scoped` checks `attr == "msg"` -- no match. Receiver chain: `_receiver_name` tries to resolve `structlog.get_logger().bind(event="audit")`, but `call.func.value` is another `ast.Call` (the `.bind()` call), and `_receiver_name` returns None for `ast.Call` nodes.

**Detection status:** NOT DETECTED. Chained method calls on audit-shaped loggers evade the receiver heuristic.

**Agent production likelihood:** LOW-MODERATE. Structured logging with chained calls is growing but not yet dominant.

**FN-006-5: Audit call in a different except clause of the same try block.**
```python
try:
    process(data)
except ValueError:
    audit.emit("validation_failed", data)  # specific handler -- not broad
except Exception:
    cleanup()  # broad handler -- no audit here
```
The broad handler (`except Exception`) contains `cleanup()` but no audit call. The specific handler has the audit call. PY-WL-006 only flags audit calls INSIDE broad handlers, not the absence of audit calls in broad handlers when other handlers audit. This is correct behaviour -- the rule's concern is "audit write may fail silently inside broad handler," not "broad handler lacks audit."

**Detection status:** Correctly not flagged. Not a false negative per the rule's definition.

**FN-006-6: Dominance bypass via `finally` block audit.**
```python
def process(data):
    try:
        result = transform(data)
        return result  # <-- bypass finding?
    finally:
        audit.emit("processed", data)
```
The `_has_normal_path_audit` function recurses into `stmt.finalbody` and finds the audit call there. `_analyze_try` passes the combined states through `_analyze_block(stmt.finalbody, ...)`. The `finally` block audit IS recognized, and the early return should not produce a bypass finding because the finally block's audit call sets `audited=True` for all exit paths.

**Detection status:** Correctly handled. The dominance analysis accounts for `finally` blocks.

---

## Semantic Equivalent Catalogue

The spec (SS7 para 2) requires: "Language bindings MUST maintain version-tracked lists of semantic equivalents for each pattern rule." No such catalogue exists for these rules. Below is the initial catalogue.

### PY-WL-004 Semantic Equivalents (Broad Exception Handling)

| ID | Pattern | Detection Status | Priority |
|----|---------|-----------------|----------|
| PY-WL-004-SE-001 | `except Exception:` / `except BaseException:` | DETECTED | -- |
| PY-WL-004-SE-002 | Bare `except:` | DETECTED | -- |
| PY-WL-004-SE-003 | `except (Exception, ValueError):` (tuple with broad member) | DETECTED | -- |
| PY-WL-004-SE-004 | `contextlib.suppress(Exception)` | DETECTED | -- |
| PY-WL-004-SE-005 | Imported `suppress(Exception)` (bare name) | DETECTED | -- |
| PY-WL-004-SE-006 | `except*` (TryStar) with broad type | DETECTED | -- |
| PY-WL-004-SE-007 | `suppress` imported under alias (`from contextlib import suppress as s; s(Exception)`) | NOT DETECTED | LOW |
| PY-WL-004-SE-008 | Exception type aliased via assignment (`E = Exception; except E:`) | NOT DETECTED | LOW |
| PY-WL-004-SE-009 | Exception type from `type()` call or metaclass | NOT DETECTED | NEGLIGIBLE |
| PY-WL-004-SE-010 | `sys.excepthook` override (global broad catch) | NOT DETECTED | LOW |
| PY-WL-004-SE-011 | `asyncio.get_event_loop().set_exception_handler(lambda loop, ctx: None)` | NOT DETECTED | LOW |

### PY-WL-005 Semantic Equivalents (Silent Exception Handling)

| ID | Pattern | Detection Status | Priority |
|----|---------|-----------------|----------|
| PY-WL-005-SE-001 | `except: pass` | DETECTED | -- |
| PY-WL-005-SE-002 | `except: ...` (Ellipsis) | DETECTED | -- |
| PY-WL-005-SE-003 | `except: continue` | DETECTED | -- |
| PY-WL-005-SE-004 | `except: break` | DETECTED | -- |
| PY-WL-005-SE-005 | `contextlib.suppress(SpecificError)` -- silent suppression of specific types | NOT DETECTED | HIGH |
| PY-WL-005-SE-006 | Docstring-only handler body (`except: "reason"`) | NOT DETECTED | MEDIUM |
| PY-WL-005-SE-007 | `None`-expression handler body (`except: None`) | NOT DETECTED | LOW |
| PY-WL-005-SE-008 | Multi-statement all-no-op body (`except: pass; pass`) | NOT DETECTED | NEGLIGIBLE |
| PY-WL-005-SE-009 | Underscore assignment (`except Exception as e: _ = e`) | NOT DETECTED | LOW |
| PY-WL-005-SE-010 | `logging.debug()` as near-silent handler (logs at lowest level) | NOT DETECTED (by design) | -- |
| PY-WL-005-SE-011 | `warnings.warn()` as only handler action (no raise, no log) | NOT DETECTED | LOW |

### PY-WL-006 Semantic Equivalents (Audit-Critical Writes in Broad Handlers)

| ID | Pattern | Detection Status | Priority |
|----|---------|-----------------|----------|
| PY-WL-006-SE-001 | `audit.emit(event, data)` in broad handler | DETECTED | -- |
| PY-WL-006-SE-002 | `db.record_failure(data)` in broad handler | DETECTED | -- |
| PY-WL-006-SE-003 | `@audit_writer` decorated function called in broad handler | DETECTED | -- |
| PY-WL-006-SE-004 | `@audit_critical` decorated function called in broad handler | DETECTED | -- |
| PY-WL-006-SE-005 | Receiver name containing "audit" or "ledger" | DETECTED | -- |
| PY-WL-006-SE-006 | Audit call wrapped in undecorated helper function | NOT DETECTED | MEDIUM |
| PY-WL-006-SE-007 | Audit call through chained method invocation (`structlog.get_logger().bind().msg()`) | NOT DETECTED | LOW |
| PY-WL-006-SE-008 | Audit via database ORM create (`AuditEntry.objects.create(...)`) | PARTIALLY (receiver check may catch if class name contains "audit") | MEDIUM |
| PY-WL-006-SE-009 | Audit via queue/message publish (`audit_queue.publish(event)`) | DETECTED (receiver heuristic) | -- |
| PY-WL-006-SE-010 | Audit via `open("audit.log").write()` -- file-based audit | NOT DETECTED | LOW |

---

## PY-WL-006 Dominance Analysis Precision

The dominance analysis (`_analyze_block` / `_analyze_stmt` family) implements a forward dataflow pass tracking a boolean `audited` state. The analysis is sound in principle but has a specific precision problem.

### Guard-clause false positives (detailed)

The analysis tracks whether an audit call has been encountered on the current execution path. A `return` statement where `audited=False` emits a bypass finding. This produces false positives on:

1. **Null-check guard clauses:**
   ```python
   def process(data):
       if data is None:
           return None      # <- bypass finding (audited=False)
       result = transform(data)
       audit.emit("processed", data)
       return result
   ```

2. **Cache-hit early returns:**
   ```python
   def process(data):
       cached = cache.get(data.id)
       if cached is not None:
           return cached     # <- bypass finding (audited=False)
       result = expensive_transform(data)
       audit.emit("processed", data)
       return result
   ```

3. **Input validation guards:**
   ```python
   def process(data):
       if not data.is_valid():
           raise ValueError("bad data")  # NOT a bypass (raise = no continue)
       if data.is_noop():
           return data       # <- bypass finding (audited=False)
       result = transform(data)
       audit.emit("processed", data)
       return result
   ```

The analysis correctly handles `raise` (no continue states, so no bypass), but ALL early returns before the audit call are flagged, regardless of whether they represent rejection (benign) or success-without-audit (dangerous).

**Volume estimate:** A function with N guard clauses before an audit call will produce N false positive bypass findings. Functions with 2-3 guards are common; 5+ guards exist in validation-heavy code.

### Correctly handled patterns

- **`finally` blocks:** Audit calls in `finally` correctly mark all paths as audited.
- **`try/except` with audit in body:** The body's audit state propagates through the `else` clause correctly.
- **`raise` in branches:** Raise terminates the path (empty continue_states), producing no bypass finding. Correct.
- **`match/case`:** All case bodies are analyzed independently. Correct.
- **Loops:** Conservative analysis preserves the incoming `audited=False` state alongside any loop-body results. Correct (may over-report on loop bodies but does not miss bypasses).

### Structural soundness

The `_BlockAnalysis` dataclass with `continue_states: frozenset[bool]` correctly models the two possible states (audited/not-audited) at each program point. The set-based merge at branch joins (if/else, try/except) is sound. The deduplication via `seen: set[tuple[int, int, ...]]` prevents duplicate findings at the same location.

---

## Evasion Surface Summary

### PY-WL-004: Broad Exception Handlers

**Accidental evasion difficulty:** HARD. The canonical broad-catch patterns (`except Exception`, `except:`, `suppress(Exception)`) are the patterns AI agents naturally produce. There is no common "accidental alternative" -- agents reaching for broad exception handling will use one of the detected forms.

**Deliberate evasion difficulty:** MODERATE. Aliasing the exception type (`E = Exception; except E:`) evades detection. This requires one extra line and is straightforward. However, code review would immediately flag this as suspicious.

**Compensating controls:** The immediate-reraise suppression is correctly scoped. The `contextlib.suppress` detection provides coverage for the primary idiom alternative.

### PY-WL-005: Silent Exception Handling

**Accidental evasion difficulty:** EASY. `contextlib.suppress(ValueError)` is the natural Python idiom for "silently ignore this specific exception." AI agents and human developers both use it frequently. It is semantically identical to `except ValueError: pass` but is not detected by PY-WL-005.

**Deliberate evasion difficulty:** TRIVIAL. A docstring-only handler body (`except: "intentional"`) evades detection. A two-statement body with two `pass` statements evades. Adding any no-op expression evades.

**Compensating controls:** PY-WL-004 catches `contextlib.suppress(Exception)` (broad types only). There is no compensating control for `suppress` with specific types.

### PY-WL-006: Audit-Critical Writes in Broad Exception Handlers

**Accidental evasion difficulty:** MODERATE. The heuristic-based detection (name prefixes, receiver names) covers the common audit call patterns. An agent would have to use an audit library with non-standard naming to accidentally evade.

**Deliberate evasion difficulty:** EASY. Wrapping the audit call in an undecorated helper function immediately evades detection. Adding one level of indirection is sufficient:
```python
def _do_audit(data):
    audit.emit("event", data)

except Exception:
    _do_audit(data)  # Not detected
```

**Compensating controls:** The `@audit_writer` / `@audit_critical` decorator mechanism provides a declaration-based detection path that survives indirection. If the helper is decorated, it IS detected. The gap is undecorated helpers.

---

## Cross-Rule Interaction Analysis

### PY-WL-004 + PY-WL-005 overlap

A `except Exception: pass` handler triggers BOTH PY-WL-004 (broad catch) and PY-WL-005 (silent handler). This is intentional -- the patterns are independently concerning and the findings carry different messages. However, the question is whether dual findings on the same handler create governance noise. The spec's severity matrix shows WL-003 (broad catch) and WL-004 (silent handler) as distinct rows with different severity/exceptionability in several taint states, so dual findings are by-design.

### PY-WL-004 + PY-WL-006 overlap

A `except Exception: audit.emit("failed", data)` handler triggers BOTH PY-WL-004 (broad catch) and PY-WL-006 (audit write in broad handler). Again, this is intentional -- the two concerns are distinct (the handler catches too broadly AND the audit write is at risk of silent failure). PY-WL-004's immediate-reraise suppression does NOT apply here (the handler body has an audit call, not a raise).

### PY-WL-005 not detecting `contextlib.suppress` while PY-WL-004 does

There is an asymmetry: PY-WL-004 detects `contextlib.suppress(Exception)` but PY-WL-005 does NOT detect `contextlib.suppress(ValueError)`. This means:
- `except ValueError: pass` fires PY-WL-005 (silent handler)
- `contextlib.suppress(ValueError)` does NOT fire anything

These are semantically identical. The gap is specific to PY-WL-005.

---

## Verdict: CONCERN

### Evidence

**Precision concerns (2 significant):**

1. **PY-WL-006 "emit" prefix over-breadth (FP-006-1).** The `_AUDIT_ATTR_PREFIXES` tuple includes `"emit"`, which matches event-bus, signal, and Socket.IO patterns that are not audit-critical. Critically, the prefix check at `_looks_audit_scoped` line 108 short-circuits before the receiver-name filter at lines 110-111, so `signal.emit()` IS incorrectly flagged. This will generate moderate false positive volume in event-driven codebases.

2. **PY-WL-006 dominance analysis guard-clause false positives (FP-006-3).** The success-path bypass analysis flags ALL early returns before an audit call, including null-check guards, cache-hit returns, and input validation short-circuits. These are not "success paths bypassing audit" -- they are rejection/optimization paths that occur before the auditable operation. A function with N guard clauses before an audit call produces N false positive bypass findings. This directly threatens the 80% precision floor for the dominance analysis sub-finding.

**Recall concerns (1 significant, 1 moderate):**

1. **PY-WL-005 missing `contextlib.suppress` for specific types (FN-005-6).** `contextlib.suppress(ValueError)` is semantically identical to `except ValueError: pass` but is not detected. PY-WL-004 only catches the broad-type variant. This is the single most common silent-exception idiom in modern Python and is produced frequently by AI agents. Given the HIGH agent-production likelihood, this represents a material recall gap.

2. **PY-WL-005 missing docstring-only handler (FN-005-1).** A handler body consisting solely of a string literal is a runtime no-op but is not detected. AI agents sometimes produce this pattern when prompted to document why an exception is swallowed.

**Working correctly:**

- **PY-WL-004 immediate-reraise suppression** is correctly scoped (single-statement `raise` only) and handles both bare re-raise and named re-raise.
- **PY-WL-004 `contextlib.suppress` detection** covers the primary idiom including both qualified and imported forms.
- **PY-WL-004 tuple-with-broad-member detection** correctly flags `except (Exception, ValueError)`.
- **PY-WL-005 detection of `pass`, `...`, `continue`, `break`** is complete for single-statement bodies.
- **PY-WL-006 handler-masking detection** correctly identifies audit calls inside broad exception handlers.
- **PY-WL-006 `_has_normal_path_audit` gate** correctly prevents dominance analysis from running on functions without non-handler audit calls.
- **PY-WL-006 `finally`-block handling** in the dominance analysis is correct.
- **PY-WL-006 `@audit_writer` / `@audit_critical` decorator detection** correctly extends the audit-call heuristic to locally declared audit targets.
- **Cross-rule dual findings** (PY-WL-004 + PY-WL-005, PY-WL-004 + PY-WL-006) are by-design per the spec's distinct severity matrix rows.

**Semantic equivalent catalogue:** Absent. Initial catalogue provided above should be adopted and version-tracked per spec SS7 para 2 (MUST).

**Overall:** The three rules correctly detect the canonical forms of their target patterns. PY-WL-004 has the strongest coverage with `contextlib.suppress` and tuple handling. PY-WL-005 has a material recall gap on `contextlib.suppress` with specific types. PY-WL-006 has two precision concerns: the `emit` prefix over-breadth and the dominance analysis guard-clause false positives. Neither concern rises to FAIL -- the core detection logic is sound and the issues are addressable -- but they prevent a clean PASS.
