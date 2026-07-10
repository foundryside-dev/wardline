## 2025-02-14 - Prevent Git Config Code Execution
**Vulnerability:** Invoking `git` via `subprocess` against untrusted directories without overriding config can allow malicious repositories to execute code via `.git/config` hooks like `core.fsmonitor`.
**Learning:** `git` uses configurations from the `.git/config` file in the current working directory or `cwd` argument, which could be controlled by an attacker when analyzing untrusted codebases.
**Prevention:** Explicitly pass `("-c", "core.fsmonitor=false")` as `_SAFE_GIT_CONFIG` to all `git` subprocess commands in the codebase.

## 2026-06-21 - [Add Unsafe PyYAML Loaders to Taint Tracking]
**Vulnerability:** The static analyzer was missing `yaml.unsafe_load` and `yaml.full_load` in its `_SERIALISATION_SINKS` mapping, potentially leading to false negatives when tracking untrusted data flowing into these dangerous deserialization functions.
**Learning:** Even if functions are listed in rule specifications (like `_SINK_SPECS`), they also need to be properly categorized in the core taint propagation logic (`_SERIALISATION_SINKS`) to ensure the analyzer correctly sheds validation provenance (converting output to `UNKNOWN_RAW`).
**Prevention:** When adding new sinks to rule definitions, always verify if they need to be added to core propagation mappings like `_SERIALISATION_SINKS` or `_PROPAGATING_BUILTINS`.
## 2024-05-24 - Static Analysis Evasion via nested helper functions and lambdas
**Vulnerability:** A developer can bypass static analysis sink rules (like picking untrusted data) by nesting the dangerous call inside a lambda expression or an inner function without decorators, as the static analyzer failed to traverse lambda bodies or inherit the trust tier properly for nested functions.
**Learning:** AST iterators must explicitly traverse lambda bodies, and scope tier resolution needs a robust fallback to the parent scope's tier when encountering an undeclared `<locals>` segment.
**Prevention:** Always traverse lambda bodies in call iterators (`iter_calls_in_function_body`). For tier lookups over nested scopes (`enclosing_declared_tier`), explicitly fallback to the outermost declared function name instead of the raw, untrusted full qualname.
