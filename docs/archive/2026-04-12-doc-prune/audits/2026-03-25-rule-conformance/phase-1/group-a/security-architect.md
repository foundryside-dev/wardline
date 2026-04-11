# Group A — Security Architect Assessment

**Auditor:** Security Architect
**Date:** 2026-03-25
**Scope:** PY-WL-001 (dict key access with fallback default), PY-WL-002 (attribute access with fallback default), PY-WL-003 (existence-checking as structural gate)
**Focus:** Threat model alignment, evasion resistance, attack surface analysis

---

## ACF Coverage Completeness

### ACF-S1 (Competence Spoofing) — WL-001 via PY-WL-001

**Claimed coverage:** `.get("security_classification", "OFFICIAL")` fabricates evidence that looks competent.

**Implementation verification:** PY-WL-001 detects three AST patterns:
1. `d.get(key, default)` — fires when `len(call.args) >= 2` on a `.get()` method call (line 87)
2. `d.setdefault(key, default)` — fires when `len(call.args) >= 2` on a `.setdefault()` method call (line 92)
3. `defaultdict(factory)` — fires when constructor has >= 1 arg (line 97)

**Assessment: ADEQUATE.** All three are the canonical Python expressions of the ACF-S1 pattern. The `.get()` detection correctly requires the second argument (the default), so `d.get(key)` (which raises no default and returns None) is not flagged — this is correct, as None-returning `.get()` does not fabricate a competent-looking value. The `defaultdict` detection covers both bare `defaultdict(int)` and `collections.defaultdict(int)` via the attribute check (line 122). The `setdefault` catch is important — it is often overlooked but is a more dangerous variant because it mutates the dict, making the fabrication persistent.

**Gap noted:** PY-WL-001 does not detect `d.get(key)` (1-arg form returning None). While None is not "competent spoofing" per se, in a context where None is later coerced (e.g., `str(d.get("field"))` producing `"None"`), this becomes a coercion vector. This is acknowledged as outside the rule's scope but worth noting as a potential future semantic equivalent.

### ACF-S2 (Hallucinated Field Access) — WL-002 via PY-WL-003

**Claimed coverage:** Existence-checking conceals hallucinated access.

**Implementation verification:** PY-WL-003 detects:
1. `in` / `not in` operators via `ast.Compare` (line 108-109)
2. `hasattr(obj, "name")` via `ast.Call` (line 126)
3. `match/case` with `MatchMapping` (line 68)
4. `match/case` with `MatchClass` (line 76)

**Assessment: ADEQUATE.** The `in` operator detection catches the canonical `if "field" in record:` pattern that an agent uses to "safely" access a field it hallucinated. The `hasattr` detection is critical for attribute-level hallucination concealment. The `match/case` detection is forward-looking — structural pattern matching is increasingly used by agents and is a natural concealment pattern for hallucinated field access.

**Strength:** The `not in` detection (line 109) is important. An agent writing `if "field" not in record: record["field"] = default` is performing existence-checking-then-fabrication, which is a compound ACF-S1+S2 pattern. PY-WL-003 catches the gate; PY-WL-001 would catch the fabrication if done via `.get()`.

### ACF-S3 (Structural Identity Spoofing) — WL-002 via PY-WL-003

**Claimed coverage:** Existence-checking substitutes structural probing for proper type identity.

**Implementation verification:** The `hasattr()` detection (line 126) directly addresses S3. Duck-typing via `hasattr(obj, "process")` to determine if an object is a "processor" is the canonical Python expression of structural identity spoofing — it substitutes attribute probing for type system guarantees.

**Assessment: ADEQUATE.** The `hasattr` detection fires regardless of what attribute is being checked. The `in` detection covers the dict-side equivalent (`"type" in record`). The match/case `MatchClass` detection (line 76) catches the pattern-matching equivalent of structural probing.

### ACF-T2 (Silent Coercion) — WL-001 via PY-WL-001

**Claimed coverage:** Defaults as implicit type coercion.

**Implementation verification:** PY-WL-001's `.get()` detection fires on any default value, including type-coercing defaults like `.get("count", 0)` (int default for potentially string field) or `.get("items", [])` (list default for potentially None field).

**Assessment: PARTIAL.** PY-WL-001 catches the case where a default value *is* a coercion (fabricating a value of a specific type). It does not catch explicit coercion patterns like `int(d["field"])` or `str(d.get("field"))`. The spec acknowledges this gap (footnote on ACF-T2): "Covers default-based coercion only. Broader coercion surface... is not addressed by the current pattern rule set." The rule covers the intersection of T2 and S1 but not the full T2 surface. This is a documented limitation, not a defect.

---

## schema_default() Attack Surface

### Mechanism Summary

`schema_default(d.get("field", value))` triggers a three-condition suppression gate (PY-WL-001 lines 210-214):

1. **Overlay declaration match:** An `OptionalFieldEntry` exists for the field name with an `overlay_scope` that contains the current file path
2. **Value match:** The literal default in the code matches `optional_field.approved_default` exactly (via `ast.literal_eval` comparison)
3. **Boundary context:** The current function is declared as a governance-relevant boundary (`shape_validation`, `external_validation`, `combined_validation`, `validates_shape`, `validates_external`) with a matching overlay scope

All three conditions must be true simultaneously for SUPPRESS. Failure produces ERROR-severity findings.

### Can an attacker abuse schema_default() to silence legitimate findings?

**Attack vector 1: Modify code to use schema_default() wrapper.**
An agent or human wraps a bare `.get()` in `schema_default()`. Without a matching overlay declaration, this produces `PY-WL-001-UNGOVERNED-DEFAULT` at ERROR severity (line 237-265). The wrapping alone does not suppress — it escalates the signal by indicating the developer *intended* governance but didn't secure it. **This vector is self-defeating.**

**Attack vector 2: Modify the overlay to add a matching declaration.**
An attacker adds an `OptionalFieldEntry` to the overlay YAML with the correct field name, approved default, and overlay scope. This is a manifest modification — a governance surface change tracked in the fingerprint baseline per spec 7.2.1 and 9.2. **This vector is governable but relies on review quality.** If a reviewer rubber-stamps the overlay change, the suppression succeeds.

**Attack vector 3: Modify both code AND overlay in the same PR.**
This is the highest-risk scenario. An agent generates a `.get("security_classification", "OFFICIAL")` wrapped in `schema_default()` and simultaneously adds the overlay entry declaring `security_classification` as optional with approved default `"OFFICIAL"`. Both changes appear in the same diff. If reviewed together by a non-domain-expert, the structural coherence of the code+overlay may mask the semantic danger.

**Compensating controls assessment:**
- The fingerprint baseline flags overlay changes as a distinct category, but only if the reviewer looks at that signal
- The boundary context requirement (condition 3) limits suppression to declared validation boundaries — the default cannot be suppressed in arbitrary code locations
- The value-match requirement (condition 2) prevents suppressing a `.get("field", "wrong_value")` when the overlay declares `"correct_value"` — mismatches produce UNCONDITIONAL findings (line 249), which cannot be overridden

**Verdict on schema_default():** The three-condition gate is structurally sound. The weakest link is the governance process around overlay modifications, not the technical mechanism. The value-mismatch escalation to UNCONDITIONAL is a strong design choice — it means an attacker must get the *exact* declared value right, not just any value. The residual risk is that the declared value itself may be wrong (convergence with residual risk #1, declaration correctness).

### Additional finding: Non-literal default bypass

The `_extract_default_value` method (line 158-165) uses `ast.literal_eval` and returns `_UNPARSEABLE_DEFAULT` for non-literal expressions. If the code uses `schema_default(d.get("field", SOME_CONSTANT))`, the default value is unparseable, and the comparison `default_value == optional_field.approved_default` will fail (since `_UNPARSEABLE_DEFAULT` is a unique object sentinel). This means the suppression gate correctly rejects non-literal defaults — they produce the ungoverned-default finding. **This is secure behaviour.** An attacker cannot evade the value-match check by indirecting through a variable.

---

## Evasion Resistance

### PY-WL-001: Dict key access with fallback default

**Accidental evasion (HIGH likelihood):**
- `value = d[key] if key in d else default` — ternary with existence check. Evades PY-WL-001 entirely. An agent producing "safe" code naturally gravitates to this pattern. However, this enters PY-WL-003's detection surface (the `key in d` is an existence check). See Cross-Rule Evasion Dynamics below.
- `try: value = d[key] except KeyError: value = default` — try/except pattern. Evades PY-WL-001. Also evades PY-WL-003. However, this may enter PY-WL-004 (broad exception catching) if the except clause is bare, or PY-WL-005 if in an audit context. A targeted `except KeyError` evades all three rules.
- `value = d.pop(key, default)` — `.pop()` with default. PY-WL-001 only checks `.get()` and `.setdefault()`. This is an evasion gap. `.pop()` with a default argument is semantically identical to `.get()` with a default for the purpose of value fabrication (with the additional side effect of mutation). **This is a detection gap.**
- `value = next(iter(d.get(key, [default])), default)` — obfuscated patterns. Unlikely in practice but possible under adversarial conditions.

**Deliberate evasion (MODERATE difficulty):**
A determined attacker has multiple paths: ternary expressions, try/except KeyError, helper functions wrapping `.get()`, `.pop()` with default, `collections.ChainMap` with a fallback dict, or operator-module patterns. The spec acknowledges this in the "living pattern catalogue" concept (section 7) — the pattern list must evolve.

**Critical gap: `.pop(key, default)`** — This method has the same two-argument signature as `.get()` and identical value-fabrication semantics. It should be added to PY-WL-001's detection surface.

### PY-WL-002: Attribute access with fallback default

**Accidental evasion (MODERATE likelihood):**
- `value = obj.attr if hasattr(obj, "attr") else default` — ternary with hasattr. Evades PY-WL-002 but enters PY-WL-003 (hasattr detection).
- `try: value = obj.attr except AttributeError: value = default` — targeted except. Evades PY-WL-002 and PY-WL-003.
- `value = vars(obj).get("attr", default)` — dict-based attribute access. Evades PY-WL-002 but enters PY-WL-001 (dict .get() with default).

**Deliberate evasion (LOW difficulty):**
`try/except AttributeError` is clean, idiomatic, and evades all three rules. However, the try/except pattern is less natural for agents than `getattr()` with a default — agents tend to prefer concise expressions.

**Strength:** PY-WL-002 detects the `obj.attr or default` pattern (line 66-72), which is a common agent-produced pattern. This catches a fallback-via-truthiness-check that many SAST tools miss.

### PY-WL-003: Existence-checking as structural gate

**Accidental evasion (LOW likelihood):**
The `in` operator detection is very broad — it fires on any `ast.Compare` containing `ast.In` or `ast.NotIn`. This is hard to accidentally evade because `in` is the canonical Python existence check. An agent would need to use:
- `try/except KeyError` — targeted exception handling, evades PY-WL-003
- `d.keys().__contains__(key)` — dunder method, evades PY-WL-003 (no `in` operator in AST)
- `any(k == key for k in d)` — generator expression, evades PY-WL-003

**Deliberate evasion (LOW difficulty):**
`try/except KeyError` or `try/except AttributeError` cleanly evades PY-WL-003. `dict.__contains__()` direct call also evades.

**Suppression boundary strength:** PY-WL-003's `_is_structural_validation_boundary` method (line 85-99) correctly suppresses findings inside declared validation boundaries where existence-checking is expected. This is important — without it, every shape validator would generate false positives.

---

## Cross-Rule Evasion Dynamics

### The .get() to ternary rewrite

If an agent rewrites `d.get(key, default)` as `d[key] if key in d else default`:
- **PY-WL-001:** Evaded (no `.get()`, `.setdefault()`, or `defaultdict` call)
- **PY-WL-003:** Triggered (`key in d` is an `in` operator existence check)

PY-WL-003's severity matrix is more restrictive than PY-WL-001's: PY-WL-003 has 5 UNCONDITIONAL cells (AUDIT_TRAIL, PIPELINE, SHAPE_VALIDATED, UNKNOWN_SHAPE_VALIDATED, UNKNOWN_SEM_VALIDATED) versus PY-WL-001's 1 (AUDIT_TRAIL only). **This evasion is self-defeating in 5 of 8 taint contexts** — the agent escapes a STANDARD-exceptionability finding and enters an UNCONDITIONAL one. In the remaining 3 contexts (EXTERNAL_RAW, UNKNOWN_RAW, MIXED_RAW), PY-WL-003 is ERROR/STANDARD, same as PY-WL-001. The evasion transfers laterally without benefit.

**This is a strong design property.** The asymmetric exceptionability distribution between PY-WL-001 and PY-WL-003 means the most natural syntactic evasion of PY-WL-001 worsens the governance posture in most contexts.

### The try/except escape hatch

The pattern `try: value = d[key] except KeyError: value = default` evades all three rules simultaneously:
- PY-WL-001: No `.get()` call
- PY-WL-002: No `getattr()` call
- PY-WL-003: No `in` operator or `hasattr()` call

This is the **primary all-rule evasion path** for Group A. The except clause targets `KeyError` specifically, so it also evades PY-WL-004 (broad exception catching, which would require a bare `except:` or `except Exception:`).

**Risk assessment:** This evasion path is syntactically heavier than `.get()`, which reduces accidental occurrence — agents prefer concise idioms. However, a model specifically trained to avoid wardline patterns, or one that has learned from codebases with wardline enforcement, would naturally produce this pattern.

**Mitigation path:** The spec's "living pattern catalogue" concept (section 7) anticipates this. A future semantic-equivalent extension detecting `try/except KeyError` with assignment in the except body would close this gap. The pattern is AST-detectable: a `Try` node with a single `ExceptHandler` targeting `KeyError` containing an `Assign` node.

### The helper-function escape

Wrapping `.get()` in a helper function (`def safe_get(d, k, default): return d.get(k, default)`) evades PY-WL-001 at the call site. PY-WL-001 would fire inside the helper definition, but if the helper is in a utility module with a different taint context (or no wardline annotations), it may produce a lower-severity finding or no finding at all.

**Risk assessment:** This is the "annotation coverage gap" attack (residual risk #4). The helper function moves the violation outside the annotated surface. The spec's coverage metrics requirement (residual risk #4) is the compensating control — unannotated utility modules should be visible in coverage reports.

---

## Residual Risk Alignment

### Risk 9: Adversarial Annotation Injection

**Interaction with Group A rules:**

The primary injection vector for Group A is the `schema_default()` suppression path. An adversarial agent can:

1. Generate code using `schema_default(d.get("field", value))`
2. Generate an overlay entry declaring the field as optional with that exact value
3. Generate a boundary declaration for the enclosing function

If all three artefacts pass review, the suppression succeeds and the fabricated default becomes invisible to the scanner.

The three-condition gate makes this attack harder than a simple annotation injection because the attacker must coordinate three separate declarations (code wrapper + field declaration + boundary declaration) across two artefacts (source code + overlay manifest). A reviewer who examines either artefact in isolation sees a structurally valid declaration. The attack succeeds when the reviewer fails to question the *semantic* appropriateness of the optional-field classification.

**Assessment:** The governance surface correctly converts this from a technical bypass to a social engineering problem. The technical controls are sound; the risk is in governance quality. This aligns with the spec's analysis in residual risk #9.

### Risk 12: Evasion Surface Trajectory

**Current state:** Current-generation LLMs produce `.get()` with defaults naturally and frequently. PY-WL-001's detection surface is well-matched to current model output patterns.

**Trajectory assessment:**

As models improve:
- **Short term (current):** Models produce `.get()` and `getattr()` patterns naturally. Detection rate is high. The try/except evasion path exists but is less idiomatic.
- **Medium term:** Models learn to avoid `.get()` with defaults in wardline-annotated codebases (through RLHF on wardline-enforced code reviews). They shift to ternary expressions (`d[k] if k in d else default`), which transfers into PY-WL-003's stronger enforcement surface. Net effect: evasion attempt worsens governance posture.
- **Long term:** Models produce helper-function abstractions, schema-level defaults (e.g., Pydantic model defaults, dataclass field defaults), or configuration-driven defaults that operate outside the AST-pattern detection surface. This is the trajectory the spec warns about — "structurally clean but semantically wrong" code.

**Assessment:** The Group A rules' evasion surface will grow in the long term as models route around AST patterns through abstraction. The cross-rule evasion dynamics provide a medium-term buffer (ternary rewrite is self-defeating), but the try/except and helper-function paths will become the dominant evasion patterns. The "living pattern catalogue" requirement is the correct compensating control, but it requires active maintenance — the pattern list must be updated faster than models learn to avoid it.

**Schema-level defaults deserve attention.** Pydantic `Field(default=...)`, dataclass `field(default=...)`, and SQLAlchemy `Column(default=...)` all fabricate defaults at the schema layer rather than the access layer. These are semantically identical to `.get()` defaults but entirely outside PY-WL-001's detection surface. This is not a current Group A concern (Group A covers access-time patterns, not declaration-time patterns), but it is the most likely long-term evasion trajectory and should be tracked as a future rule candidate.

---

## Verdict: PASS

**Rationale:**

The three rules collectively cover the claimed ACF failure modes with adequate fidelity for their stated scope. The specific findings:

1. **ACF coverage is adequate.** All four claimed ACF failure modes (S1, S2, S3, T2) are detected by the corresponding AST patterns. The T2 coverage is partial but documented.

2. **schema_default() is well-gated.** The three-condition suppression mechanism is sound. The value-mismatch escalation to UNCONDITIONAL is a particularly strong design choice. The residual risk is governance quality, not technical bypass.

3. **Cross-rule evasion dynamics are a strength.** The asymmetric exceptionability distribution between PY-WL-001 (1 UNCONDITIONAL cell) and PY-WL-003 (5 UNCONDITIONAL cells) makes the most natural syntactic evasion self-defeating. This is deliberate and effective.

4. **Two concrete gaps require attention:**
   - **`.pop(key, default)` is not detected by PY-WL-001.** Same value-fabrication semantics as `.get()` with default. Should be added to the detection surface.
   - **`try/except KeyError` with default assignment evades all three rules.** This is the primary all-rule evasion path and should be prioritized as a semantic-equivalent extension.

5. **Residual risk alignment is correct.** The rules' interaction with risks #9 and #12 matches the spec's analysis. The governance surface is the weakest link, which is the expected residual for pattern-based enforcement.

**The PASS verdict is contingent on the `.pop()` gap being tracked for remediation.** It does not represent a current exploitable vulnerability (`.pop()` is less common than `.get()` in agent-generated code), but it is a detection surface gap that should not persist.
