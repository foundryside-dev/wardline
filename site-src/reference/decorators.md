# Decorator Vocabulary Reference

## Overview

Wardline decorators are semantic annotations that mark functions with trust-boundary metadata. The scanner reads these annotations to enforce data-flow rules: which functions introduce tainted data, which functions validate and promote it, and which carry operational contracts that must be structurally verifiable.

Decorators are grouped by concern. Group 1 decorators directly affect taint propagation — they set `_wardline_tier_source` or `_wardline_transition` on the decorated function, causing the scanner to treat return values as carrying a specific taint state. All other groups are operational or contextual markers that enforce supplementary contracts without altering taint assignments.

All decorators are importable from `wardline.decorators`.

The four taint states used by Group 1 transitions, from least to most trusted:

- `EXTERNAL_RAW` — raw untrusted external input (Tier 4)
- `GUARDED` — shape-validated but not semantically verified (Tier 3)
- `ASSURED` — structurally and semantically validated (Tier 2)
- `INTEGRAL` — authoritative internal data (Tier 1)

---

## Group 1: Authority Tier Flow

These decorators mark functions that introduce or transform taint state. Functions decorated with `external_boundary`, `integral_read`, or `integral_writer` set `_wardline_tier_source`, which stamps their return values with a fixed taint state regardless of inputs. Functions decorated with the `validates_*` or `integral_construction` decorators set `_wardline_transition`, declaring the taint states they consume and produce.

### `@external_boundary`

**Purpose:** Marks a function as the entry point for untrusted external data, tainting its return value as `EXTERNAL_RAW` (Tier 4).
**Sets:** `_wardline_tier_source = EXTERNAL_RAW`
**Enforced by:** SCN-021 (contradictory combinations)
**Usage:**
```python
from wardline.decorators import external_boundary

@external_boundary
def read_request_body(request: HttpRequest) -> dict:
    return json.loads(request.body)
```

### `@validates_shape`

**Purpose:** Marks a function that performs structural (schema) validation on `EXTERNAL_RAW` input, promoting the result to `GUARDED` (Tier 3). The function body must contain a rejection path — a branch that raises or returns early on invalid input.
**Sets:** `_wardline_transition = (EXTERNAL_RAW, GUARDED)`
**Enforced by:** PY-WL-008 (missing rejection path), PY-WL-009 (semantic check without prior shape check — this decorator satisfies the shape-check requirement for `@validates_semantic`), SCN-021 (contradictory combinations)
**Usage:**
```python
from wardline.decorators import validates_shape

@validates_shape
def check_payload_structure(data: dict) -> dict:
    if "user_id" not in data or "action" not in data:
        raise ValueError("Missing required fields")
    return data
```

### `@validates_semantic`

**Purpose:** Marks a function that performs domain-logic validation on `GUARDED` input (already shape-validated), promoting the result to `ASSURED` (Tier 2). Must be preceded by shape validation; the scanner enforces this ordering via PY-WL-009.
**Sets:** `_wardline_transition = (GUARDED, ASSURED)`
**Enforced by:** PY-WL-008 (missing rejection path), PY-WL-009 (semantic check without prior shape validation), SCN-021 (contradictory combinations)
**Usage:**
```python
from wardline.decorators import validates_semantic

@validates_semantic
def verify_user_action_permitted(data: dict) -> dict:
    if data["action"] not in ALLOWED_ACTIONS:
        raise PermissionError(f"Action {data['action']!r} is not permitted")
    return data
```

### `@validates_external`

**Purpose:** Marks a function that performs both structural and semantic validation in a single pass, promoting `EXTERNAL_RAW` input directly to `ASSURED` (Tier 2). Subsumes both `@validates_shape` and `@validates_semantic` — do not combine them.
**Sets:** `_wardline_transition = (EXTERNAL_RAW, ASSURED)`
**Enforced by:** PY-WL-008 (missing rejection path), SCN-021 (contradictory combinations)
**Usage:**
```python
from wardline.decorators import validates_external

@validates_external
def parse_and_validate_config(raw: dict) -> Config:
    if "host" not in raw or not isinstance(raw["host"], str):
        raise ValueError("Config missing required 'host' string")
    if raw.get("port", 0) not in range(1, 65536):
        raise ValueError("Config 'port' out of range")
    return Config(**raw)
```

### `@integral_read`

**Purpose:** Marks a function that reads from a Tier 1 authoritative data source, tainting its return value as `INTEGRAL`. Use this for functions that retrieve data from trusted stores such as databases or signed configuration.
**Sets:** `_wardline_tier_source = INTEGRAL`
**Enforced by:** SCN-021 (contradictory combinations)
**Usage:**
```python
from wardline.decorators import integral_read

@integral_read
def load_policy_record(policy_id: str) -> PolicyRecord:
    return db.query(PolicyRecord).filter_by(id=policy_id).one()
```

### `@integral_writer`

**Purpose:** Marks a function that writes authoritative audit records. Return values carry `INTEGRAL` taint. The scanner treats calls to this function as audit writes, enforcing audit-completeness rules (PY-WL-006) and identity threading (SUP-001 via `@requires_identity`).
**Sets:** `_wardline_tier_source = INTEGRAL`, `_wardline_integral_writer = True`
**Enforced by:** PY-WL-006 (audit bypass detection), SCN-021 (contradictory combinations), SUP-001 (`@requires_identity` threading)
**Usage:**
```python
from wardline.decorators import integral_writer

@integral_writer
def record_access_event(actor: str, resource: str, outcome: str) -> AuditEntry:
    entry = AuditEntry(actor=actor, resource=resource, outcome=outcome)
    audit_log.append(entry)
    return entry
```

### `@integral_construction`

**Purpose:** Marks a function that constructs a Tier 1 authoritative object from `ASSURED` (Tier 2) validated input. This is the final step in the validation pipeline: input has passed structural and semantic checks and is now promoted to `INTEGRAL`.
**Sets:** `_wardline_transition = (ASSURED, INTEGRAL)`
**Enforced by:** SCN-021 (contradictory combinations)
**Usage:**
```python
from wardline.decorators import integral_construction

@integral_construction
def build_order(validated_data: dict) -> Order:
    return Order(
        customer_id=validated_data["customer_id"],
        items=validated_data["items"],
    )
```

---

## Group 2: Audit

### `@integrity_critical`

**Purpose:** Marks a function as performing an audit-critical operation. The scanner treats calls to this function the same as calls to `@integral_writer` when checking for audit-bypass paths: any code path that can succeed without reaching this function is flagged.
**Enforced by:** PY-WL-006 (audit-critical call inside broad exception handler or bypassable path), SCN-021 (contradictory combinations), SUP-001 (`@requires_identity` threading)
**Usage:**
```python
from wardline.decorators import integrity_critical

@integrity_critical
def emit_security_event(event_type: str, details: dict) -> None:
    security_ledger.write(event_type, details)
```

---

## Group 3: Plugin

### `@system_plugin`

**Purpose:** Marks a function or class as a system plugin — a component that receives external input and operates within the system boundary. The scanner uses this to flag contradictions with decorators that imply Tier 1 authority.
**Enforced by:** SCN-021 (contradictory combinations)
**Usage:**
```python
from wardline.decorators import system_plugin

@system_plugin
def process_webhook_event(payload: dict) -> None:
    ...
```

---

## Group 4: Internal Data Provenance

### `@int_data`

**Purpose:** Marks a function as sourcing or returning internal (non-external) data. Contradicts `@external_boundary`, because a function cannot simultaneously be an external entry point and an internal data source.
**Enforced by:** SCN-021 (contradictory combinations)
**Usage:**
```python
from wardline.decorators import int_data

@int_data
def get_default_settings() -> dict:
    return DEFAULT_SETTINGS.copy()
```

---

## Group 5: Schema

### `@all_fields_mapped`

**Purpose:** Declares that a function maps every field from a source type. When called with `source="ClassName"`, the scanner (SCN-022) verifies that every annotated field of that class is accessed via attribute on the function's first parameter. Prevents silent data loss in DTO conversion functions.
**Enforced by:** SCN-022 (field-completeness verification)
**Usage:**
```python
from wardline.decorators import all_fields_mapped

@all_fields_mapped(source="UserDTO")
def user_dto_to_domain(dto: UserDTO) -> User:
    return User(name=dto.name, email=dto.email, role=dto.role)
```

### `@output_schema`

**Purpose:** Marks a function as having a declared output schema. Used to assert that the function's return structure is governed by a schema definition.
**Usage:**
```python
from wardline.decorators import output_schema

@output_schema
def serialize_response(record: Record) -> dict:
    return {"id": record.id, "status": record.status}
```

### `schema_default`

**Purpose:** A utility function (not a decorator) that marks a value as an explicit schema default. Returns its argument unchanged. The scanner detects calls to `schema_default()` at call sites where PY-WL-001 would otherwise flag a `.get(key, default)` pattern inside a boundary with a matching overlay declaration — the call signals that the default is intentional and governed.
**Enforced by:** PY-WL-001 (suppresses the finding when used inside a governed boundary)
**Usage:**
```python
from wardline.decorators import schema_default

timeout = data.get("timeout", schema_default(30))
```

---

## Group 6: Trust Boundaries

### `@trust_boundary`

**Purpose:** Marks a function as a general trust boundary crossing — a point where data moves between trust zones. Used as a lightweight annotation when the specific direction of taint transition does not need to be declared.
**Usage:**
```python
from wardline.decorators import trust_boundary

@trust_boundary
def accept_partner_data(data: dict) -> dict:
    ...
```

### `@tier_transition`

**Purpose:** Marks a function as a tier transition point — a crossing between authority tiers that does not fit the standard validate/construct pattern. Used when the transition semantics are defined elsewhere (for example, in the manifest).
**Usage:**
```python
from wardline.decorators import tier_transition

@tier_transition
def promote_to_internal(record: dict) -> InternalRecord:
    ...
```

---

## Group 7: Template Safety

### `@parse_at_init`

**Purpose:** Marks a function that parses or compiles a template or pattern at initialisation time. SUP-001 enforces that calls to `@parse_at_init` functions only appear inside `__init__`, `__post_init__`, or `setup` methods — preventing repeated parse overhead at call time and ensuring that parse failures surface at startup rather than at runtime.
**Enforced by:** SUP-001 (call-site placement enforcement)
**Usage:**
```python
from wardline.decorators import parse_at_init

@parse_at_init
def compile_template(template_str: str) -> Template:
    return Template(template_str)
```

---

## Group 8: Secrets

### `@handles_secrets`

**Purpose:** Marks a function that processes secret material (passwords, tokens, API keys). SUP-001 checks that secret-bearing parameters and variables do not flow into logging sinks, persistence sinks, or exception payloads without a protective transformation (hashing, masking, redaction).
**Enforced by:** SUP-001 (secret sink leak detection)
**Usage:**
```python
from wardline.decorators import handles_secrets

@handles_secrets
def authenticate(username: str, password: str) -> Session:
    hashed = bcrypt.hash(password)
    return db.verify(username, hashed)
```

---

## Group 9: Operations

### `@idempotent`

**Purpose:** Declares that a function produces the same result when called multiple times with the same arguments. Contradicts `@compensatable` (idempotent operations do not need rollback) and is suspicious in combination with `@time_dependent`.
**Enforced by:** SCN-021 (contradictory combinations)
**Usage:**
```python
from wardline.decorators import idempotent

@idempotent
def upsert_record(record_id: str, data: dict) -> None:
    db.upsert(record_id, data)
```

### `@atomic`

**Purpose:** Declares that a function performs multiple state-modifying operations that must succeed or fail together. SUP-001 checks that multiple state-mutating calls within the function body are enclosed in a transaction context (a `with` block whose context manager name contains "atomic", "transaction", or "begin").
**Enforced by:** SUP-001 (transaction wrapping verification)
**Usage:**
```python
from wardline.decorators import atomic

@atomic
def transfer_funds(src: Account, dst: Account, amount: Decimal) -> None:
    with db.transaction():
        src.debit(amount)
        dst.credit(amount)
```

### `@compensatable`

**Purpose:** Marks a function that has a corresponding rollback function. The `rollback` argument must name a function defined in the same module, and that function must accept either one parameter or the same number of parameters as the decorated function. Contradicts `@idempotent` and `@integral_writer`.
**Enforced by:** SCN-021 (contradictory combinations), SUP-001 (rollback discoverability and arity)
**Usage:**
```python
from wardline.decorators import compensatable

def _rollback_create_order(order_id: str) -> None:
    db.delete_order(order_id)

@compensatable(rollback="rollback_create_order")
def create_order(order_id: str, items: list) -> None:
    db.insert_order(order_id, items)
```

---

## Group 10: Failure Mode

### `@fail_closed`

**Purpose:** Declares that the function raises an exception on any failure — it never silently degrades or returns a fallback value. Contradicts `@fail_open`, `@emits_or_explains`, and all Tier 1 authority decorators.
**Enforced by:** SCN-021 (contradictory combinations)
**Usage:**
```python
from wardline.decorators import fail_closed

@fail_closed
def load_required_config(path: str) -> Config:
    with open(path) as f:
        return Config.parse(f.read())
```

### `@fail_open`

**Purpose:** Declares that the function returns a safe fallback value rather than raising on failure. Contradicts Tier 1 decorators (`@integral_read`, `@integral_writer`, `@integral_construction`), `@integrity_critical`, and `@fail_closed`.
**Enforced by:** SCN-021 (contradictory combinations)
**Usage:**
```python
from wardline.decorators import fail_open

@fail_open
def get_optional_feature_config(key: str) -> dict:
    return cache.get(key) or {}
```

### `@emits_or_explains`

**Purpose:** Declares that the function produces structured diagnostic output on failure rather than raising a bare exception. Contradicts `@fail_closed`.
**Enforced by:** SCN-021 (contradictory combinations)
**Usage:**
```python
from wardline.decorators import emits_or_explains

@emits_or_explains
def validate_with_report(data: dict) -> ValidationResult:
    errors = collect_errors(data)
    return ValidationResult(ok=not errors, errors=errors)
```

### `@exception_boundary`

**Purpose:** Marks a function that catches and translates exceptions — converting internal exceptions into a public error representation. Contradicts `@must_propagate` and `@preserve_cause`.
**Enforced by:** SCN-021 (contradictory combinations)
**Usage:**
```python
from wardline.decorators import exception_boundary

@exception_boundary
def call_external_service(url: str) -> Response:
    try:
        return http_client.get(url)
    except ConnectionError as exc:
        raise ServiceUnavailableError(str(exc)) from exc
```

### `@must_propagate`

**Purpose:** Declares that the function must re-raise or forward any exception it receives — it must not swallow or absorb exceptions. Contradicts `@exception_boundary`.
**Enforced by:** SCN-021 (contradictory combinations)
**Usage:**
```python
from wardline.decorators import must_propagate

@must_propagate
def run_with_tracing(fn: Callable, *args: object) -> object:
    with tracer.span(fn.__name__):
        return fn(*args)
```

### `@preserve_cause`

**Purpose:** Declares that the function preserves the original exception cause when raising a new exception (using `raise X from Y`). Contradicts `@exception_boundary`.
**Enforced by:** SCN-021 (contradictory combinations)
**Usage:**
```python
from wardline.decorators import preserve_cause

@preserve_cause
def parse_config(raw: str) -> Config:
    try:
        return Config.from_yaml(raw)
    except yaml.YAMLError as exc:
        raise ConfigParseError("Invalid YAML") from exc
```

---

## Group 11: Data Sensitivity

### `@handles_pii`

**Purpose:** Marks a function that processes personally identifiable information. The `fields` argument names the PII field identifiers. SUP-001 checks that those fields do not flow into logging sinks, persistence sinks, or exception messages without a protective transformation. Requires at least one field name.
**Enforced by:** SUP-001 (PII sink/error/persistence checks)
**Usage:**
```python
from wardline.decorators import handles_pii

@handles_pii(fields=["email", "phone_number"])
def send_notification(user_id: str, email: str, phone_number: str) -> None:
    notification_service.send(user_id, contact=mask(email))
```

### `@handles_classified`

**Purpose:** Marks a function that processes data at a declared classification level. SUP-001 checks that the function does not pass classified data to a lower-classification function without going through a `@declassifies` boundary.
**Enforced by:** SUP-001 (downgrade checks)
**Usage:**
```python
from wardline.decorators import handles_classified

@handles_classified(level="SECRET")
def process_intelligence_report(report: Report) -> Summary:
    return summarise(report)
```

### `@declassifies`

**Purpose:** Marks a function that formally lowers the classification level of data from `from_level` to `to_level`. SUP-001 verifies that `to_level` is genuinely lower than `from_level` and that the function body contains a rejection path.
**Enforced by:** SUP-001 (rejection-path and downgrade-shape checks), SCN-021 (contradictory combinations)
**Usage:**
```python
from wardline.decorators import declassifies

@declassifies(from_level="SECRET", to_level="INTERNAL")
def redact_for_internal_use(report: Report) -> Report:
    if not report.is_approved_for_internal:
        raise PermissionError("Report not approved for internal release")
    return report.redacted_copy()
```

---

## Group 12: Determinism

### `@deterministic`

**Purpose:** Declares that the function always produces the same output for the same inputs. SUP-001 checks the function body for calls to non-deterministic APIs (`random.*`, `uuid.uuid4`, `datetime.now`, etc.) and flags any it finds. Suppressed when `@time_dependent` is also present.
**Enforced by:** SCN-021 (contradictory combinations with `@time_dependent` and `@external_boundary`), SUP-001 (non-deterministic API ban)
**Usage:**
```python
from wardline.decorators import deterministic

@deterministic
def compute_checksum(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
```

### `@time_dependent`

**Purpose:** Declares that the function's output depends on the current time or other time-varying state. Contradicts `@deterministic`. Suppresses SUP-001's non-deterministic API checks when stacked with `@deterministic`.
**Enforced by:** SCN-021 (contradictory combinations)
**Usage:**
```python
from wardline.decorators import time_dependent

@time_dependent
def generate_session_token(user_id: str) -> str:
    return f"{user_id}-{datetime.now().timestamp()}"
```

---

## Group 13: Concurrency

### `@thread_safe`

**Purpose:** Declares that the function is safe to call concurrently from multiple threads without external synchronisation.
**Usage:**
```python
from wardline.decorators import thread_safe

@thread_safe
def get_cached_value(key: str) -> object:
    return _cache[key]
```

### `@ordered_after`

**Purpose:** Declares that calls to this function must always be ordered after calls to the named function at shared call sites. SUP-001 checks that wherever both functions are called in the same function body, the named predecessor is called first.
**Enforced by:** SUP-001 (lexical call-site ordering)
**Usage:**
```python
from wardline.decorators import ordered_after

@ordered_after("acquire_lock")
def modify_shared_state(value: int) -> None:
    _shared.value = value
```

### `@not_reentrant`

**Purpose:** Declares that the function must not be called recursively or from within its own call chain. SUP-001 performs a local call-graph cycle detection to flag re-entrant patterns.
**Enforced by:** SUP-001 (local call-graph cycle detection)
**Usage:**
```python
from wardline.decorators import not_reentrant

@not_reentrant
def flush_event_queue() -> None:
    while _queue:
        process(_queue.pop())
```

---

## Group 14: Access

### `@requires_identity`

**Purpose:** Declares that the function requires a caller identity for audit threading. SUP-001 checks that the function has a parameter whose name contains an identity hint ("actor", "user", "principal", "subject", or "identity") and that this parameter is passed into any `@integral_writer` or `@integrity_critical` call within the body.
**Enforced by:** SUP-001 (audit identity threading)
**Usage:**
```python
from wardline.decorators import requires_identity

@requires_identity
def delete_record(record_id: str, actor: str) -> None:
    audit_log.record_deletion(record_id, actor=actor)
    db.delete(record_id)
```

### `@privileged_operation`

**Purpose:** Marks a function as performing a privileged state-mutating operation. SUP-001 checks that an authorization call (a function whose name contains "auth", "authorize", "permit", "allow", "can_", or similar) appears before the first state-modifying call in the function body.
**Enforced by:** SUP-001 (authorization-before-mutation)
**Usage:**
```python
from wardline.decorators import privileged_operation

@privileged_operation
def purge_tenant_data(tenant_id: str, actor: str) -> None:
    authorize(actor, "purge", tenant_id)
    db.delete_all(tenant_id)
```

---

## Group 15: Lifecycle

### `@test_only`

**Purpose:** Marks a function as intended for use in test code only. SUP-001 checks that production modules (those not inside a `test/`, `tests/`, or `testing/` directory, and not named `test_*.py` or `*_test.py`) do not import symbols decorated with `@test_only`.
**Enforced by:** SUP-001 (production import ban)
**Usage:**
```python
from wardline.decorators import test_only

@test_only
def create_test_user(name: str) -> User:
    return User(name=name, role="test")
```

### `@deprecated_by`

**Purpose:** Marks a function as scheduled for deprecation, specifying the deprecation date and a replacement. SUP-001 emits a warning if the date has not yet passed, and an error if it has.
**Enforced by:** SUP-001 (expiry and advisory checks)
**Usage:**
```python
from wardline.decorators import deprecated_by

@deprecated_by(date="2026-06-01", replacement="new_auth_flow")
def legacy_authenticate(username: str, password: str) -> Session:
    ...
```

### `@feature_gated`

**Purpose:** Marks a function as controlled by a named feature flag. SUP-001 checks that the flag name appears at least once in the project as a static string reference (beyond the decorator itself), detecting stale flags that have been cleaned up in the rest of the code but not removed from the decorator.
**Enforced by:** SUP-001 (stale flag detection)
**Usage:**
```python
from wardline.decorators import feature_gated

@feature_gated(flag="new_checkout_flow")
def process_checkout_v2(cart: Cart) -> Order:
    ...
```

---

## Group 17: Restoration Boundaries

### `@restoration_boundary`

**Purpose:** Marks a function that reconstructs a previously-known data object from a raw serialised representation (for example, deserialising from a database blob or a message queue). Unlike `@external_boundary`, restoration boundaries handle data that was originally authoritative — the `restored_tier` argument declares what tier level the reconstruction claims to achieve. The scanner uses the combination of `structural_evidence`, `semantic_evidence`, `integrity_evidence`, and `institutional_provenance` arguments to determine whether the claimed tier is warranted.

Restoration boundaries do not stamp a runtime output tier; taint assignment is scanner-only via `max_restorable_tier()`. This decorator is mutually exclusive with all other Group 1 decorators.

**Enforced by:** SCN-021 (contradictory combinations with `@integral_read`, `@integral_writer`, `@external_boundary`, `@validates_shape`, `@validates_semantic`, `@validates_external`, `@integral_construction`)
**Usage:**
```python
from wardline.decorators import restoration_boundary

@restoration_boundary(
    restored_tier=2,
    structural_evidence=True,
    semantic_evidence=True,
    integrity_evidence="hmac",
)
def restore_order_from_snapshot(blob: bytes) -> Order:
    data = json.loads(blob)
    verify_hmac(data)
    validate_order_schema(data)
    return Order(**data)
```
