# Adopting Wardline in an Existing Project

This guide walks you through adding Wardline to a codebase that already has code.
It assumes you have read [Getting Started](../getting-started.md) and understand
the basic concepts (tiers, taint states, decorators).

## Overview

Adoption is incremental. You do not need to annotate every function on day one.
The recommended sequence:

1. Install and create a manifest
2. Run a baseline scan
3. Triage findings — fix, except, or defer
4. Add decorators to key boundaries
5. Wire into CI
6. Iterate: reduce unknowns, increase analysis level

## Step 1: Install and Create a Manifest

```bash
pip install wardline
```

Create a minimal `wardline.yaml` at your project root:

```yaml
$id: "https://wardline.dev/schemas/1.0/wardline.schema.json"

module_tiers:
  - path: "src/myapp/"
    default_taint: "UNKNOWN_RAW"

metadata:
  organisation: "My Company"
```

Starting with `UNKNOWN_RAW` is honest — you are declaring that no validation
assumptions exist yet. The scanner will report findings against this baseline,
and you will promote modules as you add decorators.

Validate the manifest:

```bash
wardline manifest validate
```

## Step 2: Run a Baseline Scan

```bash
wardline scan src/myapp/ -o baseline.sarif
```

Expect many findings. This is normal. The baseline tells you where your
boundaries are missing.

Review the summary:

```bash
# Count findings by rule
cat baseline.sarif | jq '[.runs[0].results[].ruleId] | group_by(.) | map({rule: .[0], count: length})'
```

## Step 3: Triage Findings

For each finding, decide:

- **Fix**: Change the code to satisfy the rule. This is the right choice for
  real violations.
- **Except**: Grant an exception for findings that are intentional or deferred.
  Use `wardline exception add`.
- **Suppress via module_tiers**: Promote a module's default taint (e.g., from
  `UNKNOWN_RAW` to `GUARDED`) if you are confident the module's code is at
  that trust level.

Start with the highest-severity findings (ERROR at INTEGRAL/ASSURED) — these
represent the most significant trust violations.

## Step 4: Add Decorators to Key Boundaries

Identify your trust boundaries — the functions where external data enters and
where validation happens. Decorate them:

```python
from wardline.decorators import external_boundary, validates_shape, integrity_critical

@external_boundary
def receive_api_request(request):
    ...

@validates_shape
def parse_request(raw):
    if "required_field" not in raw:
        raise ValueError("missing required_field")
    ...

@integrity_critical
def write_audit_log(validated_data):
    ...
```

After adding decorators, promote the module in your manifest:

```yaml
module_tiers:
  - path: "src/myapp/adapters/"
    default_taint: "EXTERNAL_RAW"
  - path: "src/myapp/core/"
    default_taint: "ASSURED"
  - path: "src/myapp/audit/"
    default_taint: "INTEGRAL"
```

Re-scan and compare:

```bash
wardline scan src/myapp/ -o after-decorators.sarif
```

## Step 5: Wire into CI

See [CI Integration Guide](ci-integration.md) for detailed examples.

Quick GitHub Actions setup:

```yaml
- name: Wardline Scan
  run: |
    pip install wardline
    wardline scan src/ --verification-mode
```

## Step 6: Iterate

- **Reduce unknowns**: Add `module_tiers` entries and decorators until
  `UNKNOWN_RAW` findings are near zero.
- **Increase analysis level**: Move from L1 to L2 or L3 as your annotation
  coverage improves. See [Analysis Levels](analysis-levels.md).
- **Choose governance profile**: Once decorators are in place, consider moving
  from `lite` to `assurance`. See [Profiles](profiles.md).

## Common Mistakes

| Mistake | Why It's Wrong | Fix |
|---------|---------------|-----|
| Setting everything to `INTEGRAL` | Triggers ERROR on every pattern rule | Start with `UNKNOWN_RAW` and promote as you add decorators |
| Excepting everything | Defeats the purpose; exceptions accumulate governance debt | Only except findings you have reviewed and accepted |
| Skipping `@validates_shape` | Data flows from T4 to T2 without structural validation | Add shape validation before semantic validation |
| One big `module_tiers` entry | Blanket assignment triggers `GOVERNANCE-MODULE-TIERS-BLANKET` | Use per-package entries with appropriate taint levels |

## Further Reading

- [Getting Started](../getting-started.md) — 15-minute introduction
- [Rule Quick Reference](../reference/rules.md) — what each finding means
- [Severity Matrix](../reference/severity-matrix.md) — severity per rule per taint
- [Governance Walkthrough](governance.md) — managing exceptions
