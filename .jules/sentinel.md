## 2025-02-14 - Prevent Git Config Code Execution
**Vulnerability:** Invoking `git` via `subprocess` against untrusted directories without overriding config can allow malicious repositories to execute code via `.git/config` hooks like `core.fsmonitor`.
**Learning:** `git` uses configurations from the `.git/config` file in the current working directory or `cwd` argument, which could be controlled by an attacker when analyzing untrusted codebases.
**Prevention:** Explicitly pass `("-c", "core.fsmonitor=false")` as `_SAFE_GIT_CONFIG` to all `git` subprocess commands in the codebase.

## 2026-06-21 - [Add Unsafe PyYAML Loaders to Taint Tracking]
**Vulnerability:** The static analyzer was missing `yaml.unsafe_load` and `yaml.full_load` in its `_SERIALISATION_SINKS` mapping, potentially leading to false negatives when tracking untrusted data flowing into these dangerous deserialization functions.
**Learning:** Even if functions are listed in rule specifications (like `_SINK_SPECS`), they also need to be properly categorized in the core taint propagation logic (`_SERIALISATION_SINKS`) to ensure the analyzer correctly sheds validation provenance (converting output to `UNKNOWN_RAW`).
**Prevention:** When adding new sinks to rule definitions, always verify if they need to be added to core propagation mappings like `_SERIALISATION_SINKS` or `_PROPAGATING_BUILTINS`.

## 2026-06-28 - Parameter Default Expression Taint Resolution Leak
**Vulnerability:** Untrusted data could leak into `@trusted` functions without triggering `PY-WL-101` because parameter default value expressions were defaulting to the `function_taint` (which is `ASSURED` for trusted functions), masking their true taint in L2 analysis.
**Learning:** Default parameter expressions are evaluated at runtime in the caller's scope when an argument is omitted, not as part of the function body itself. Inheriting the `function_taint` for defaults creates a blind spot where `EXTERNAL_RAW` expressions inside parameter defaults bypass taint checks.
**Prevention:** When evaluating parameter default expressions in static analysis (`_seed_parameters`), always resolve them with a clean base state (`TaintState.INTEGRAL`) rather than inheriting `function_taint` to ensure accurate taint propagation.
