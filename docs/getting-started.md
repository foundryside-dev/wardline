# Getting Started with Wardline

Wardline is a semantic boundary enforcement framework for Python. It statically
verifies that data flows respect trust-tier boundaries — catching untrusted input
that reaches privileged code before it ships.

This guide takes you from installation to a working CI check in about fifteen minutes.

---

## Installation

Wardline requires Python 3.12 or later.

```bash
pip install wardline
```

Or with uv:

```bash
uv add wardline
```

The scanner extras (pyyaml, jsonschema, click) are included in the default install.

---

## The Trust Hierarchy

Wardline models data as carrying a taint state that reflects how much it has been
validated. Four tiers map onto four taint states:

| Tier | Taint state    | Meaning                                              |
|------|----------------|------------------------------------------------------|
| 1    | `INTEGRAL`     | Audit-critical, highest trust. DB writes, compliance logs. |
| 2    | `ASSURED`      | Validated internal data. Business logic on checked inputs. |
| 3    | `GUARDED`      | Shape-validated but not semantically verified.       |
| 4    | `EXTERNAL_RAW` | Untrusted external input. API payloads, file reads.  |

Data flows freely from Tier 1 down to Tier 4. Flowing upward — from
`EXTERNAL_RAW` toward `INTEGRAL` — requires an explicit validation boundary.
Without one, the scanner reports a violation.

---

## Creating a Manifest

Wardline reads a `wardline.yaml` file to understand which modules belong to which
tier. Place this at your project root:

```yaml
$id: "https://wardline.dev/schemas/1.0/wardline.schema.json"

tiers:
  - id: "primary_db"
    tier: 1
  - id: "partner_api"
    tier: 4

module_tiers:
  - path: "src/myapp/core/"
    default_taint: "ASSURED"
  - path: "src/myapp/adapters/"
    default_taint: "EXTERNAL_RAW"

metadata:
  organisation: "My Company"
```

`module_tiers` sets the default taint for every symbol in that package. Individual functions can be overridden with decorators.

---

## Applying Decorators

Wardline decorators annotate functions with trust-boundary semantics. The scanner
reads these annotations — they are not just documentation.

```python
from wardline.decorators import integrity_critical, validates_shape, external_boundary
```

### Marking an entry point from an external system

`@external_boundary` tells the scanner that this function receives input from
outside your trust perimeter. Data flowing out of it carries `EXTERNAL_RAW` taint.

```python
@external_boundary
def receive_webhook(payload: dict) -> dict:
    """Accept raw JSON from the partner API."""
    return payload
```

### Marking a structural validation boundary

`@validates_shape` tells the scanner that this function checks the structure of
its input. Data flowing out carries `GUARDED` taint — it has been inspected but
not yet semantically verified.

```python
@validates_shape
def parse_webhook(raw: dict) -> WebhookEvent:
    """Validate field presence and types. Raise on malformed input."""
    if "event_type" not in raw:
        raise ValueError("missing event_type")
    return WebhookEvent(
        event_type=raw["event_type"],
        payload=raw.get("payload", {}),
    )
```

### Marking an audit-critical function

`@integrity_critical` tells the scanner this function operates at Tier 1. The
scanner will reject any `EXTERNAL_RAW` or `GUARDED` data reaching it without
passing through a validation boundary first.

```python
@integrity_critical
def record_audit_event(event: WebhookEvent) -> None:
    """Write a validated event to the compliance log."""
    db.write_audit(event)
```

---

## Running a Scan

```bash
wardline scan src/myapp/
```

The scanner walks the source tree, parses every `.py` file, propagates taint
through the call graph, and evaluates rules against the result.

Output is SARIF JSON written to stdout. Exit codes:

- `0` — no findings
- `1` — one or more findings
- `2` — configuration error (bad manifest, parse failure on config)

To point the scanner at a specific manifest:

```bash
wardline scan src/myapp/ --manifest wardline.yaml
```

---

## Reading a Finding

A typical finding looks like this in SARIF output:

```json
{
  "ruleId": "PY-WL-001",
  "level": "error",
  "message": {
    "text": "dict.get() with fallback default on EXTERNAL_RAW data at line 34 of adapters/webhook.py. The fallback silently masks a missing key — taint state is not promoted by the default value."
  },
  "locations": [{
    "physicalLocation": {
      "artifactLocation": { "uri": "src/myapp/adapters/webhook.py" },
      "region": { "startLine": 34 }
    }
  }]
}
```

`PY-WL-001` fires when `dict.get()` is called with a fallback default on data
that has not been validated. The fallback silently masks a missing key — the
caller receives a default instead of an error, but the taint state is not
promoted. The fix is to call `dict.get()` without a fallback and handle the
`None` case explicitly, or to route the data through a `@validates_shape`
function first.

---

## CI Integration

Add wardline to your GitHub Actions workflow to gate merges on a clean scan:

```yaml
- name: Wardline Scan
  run: |
    pip install wardline
    wardline scan src/ --manifest wardline.yaml
```

A non-zero exit code fails the step. Exit code `1` means trust-boundary
violations were found; fix those before merging. Exit code `2` means the
manifest or scanner configuration is broken — also a blocking error.

---

## Worked Examples

### Example 1: Untrusted input reaching an audit log

This is the most common violation wardline catches. An HTTP handler passes
request data directly to a compliance-logging function.

```python
# adapters/api.py
@external_boundary
def handle_request(request_body: dict) -> None:
    # BUG: request_body is EXTERNAL_RAW — no validation boundary crossed
    record_audit_event(request_body)

@integrity_critical
def record_audit_event(data: dict) -> None:
    db.write_audit(data)
```

The scanner reports PY-WL-001 or similar: `EXTERNAL_RAW` data reached an
`@integrity_critical` function without passing through `@validates_shape` or
`@validates_semantic`.

Fix: insert a validation boundary.

```python
@external_boundary
def handle_request(request_body: dict) -> None:
    validated = parse_request(request_body)   # GUARDED after this
    record_audit_event(validated)

@validates_shape
def parse_request(raw: dict) -> AuditRecord:
    if "action" not in raw or "actor_id" not in raw:
        raise ValueError("malformed request")
    return AuditRecord(action=raw["action"], actor_id=raw["actor_id"])

@integrity_critical
def record_audit_event(record: AuditRecord) -> None:
    db.write_audit(record)
```

### Example 2: Deterministic utility called with raw input

Some violations are subtle. A utility function is pure and has no side effects,
but it is called with unvalidated data and its output flows into a privileged
path.

```python
# core/transform.py
@deterministic
def normalize_action(action: str) -> str:
    return action.strip().lower()

# adapters/api.py
@external_boundary
def handle_request(request_body: dict) -> None:
    action = normalize_action(request_body["action"])  # still EXTERNAL_RAW
    record_audit_event({"action": action})
```

`@deterministic` marks the function as side-effect free, but it does not elevate
taint. The output of `normalize_action` is still `EXTERNAL_RAW` because the
input was not validated. Wardline reports a violation at `record_audit_event`.

Fix: validate the full record before calling the utility, or add `@validates_shape`
to a wrapper that validates and transforms together.

### Example 3: Fail-safe error handling at a trust boundary

An adapter function receives external data and must fail closed — it should
never return a partial result that could be mistaken for validated data.

```python
from wardline.decorators import external_boundary, validates_shape, fail_closed

@external_boundary
@validates_shape
@fail_closed
def load_partner_record(raw_json: str) -> PartnerRecord:
    """
    Parse and validate a partner record from the API.

    @fail_closed ensures the scanner verifies this function raises on
    any invalid input rather than returning a degraded value.
    """
    data = json.loads(raw_json)
    if "partner_id" not in data:
        raise ValueError("partner_id required")
    if not isinstance(data["partner_id"], str):
        raise TypeError("partner_id must be a string")
    return PartnerRecord(partner_id=data["partner_id"], metadata=data.get("metadata"))
```

Using all three decorators together communicates the full contract: this function
is the entry point (`@external_boundary`), it validates structure
(`@validates_shape`), and it never swallows errors (`@fail_closed`). The scanner
uses all three annotations when evaluating data flow through this function.

---

## Next Steps

- Read the rule reference (`wardline explain PY-WL-001`) to understand each
  finding type and its remediation.
- Use `wardline manifest validate` to check your `wardline.yaml` against the
  JSON Schema.
- Use `wardline scan --sarif-output findings.sarif` to write SARIF output to a
  file for upload to GitHub Code Scanning or another SAST platform.
