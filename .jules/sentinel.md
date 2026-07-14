## 2025-02-14 - Prevent Git Config Code Execution
**Vulnerability:** Invoking `git` via `subprocess` against untrusted directories without overriding config can allow malicious repositories to execute code via `.git/config` hooks like `core.fsmonitor`.
**Learning:** `git` uses configurations from the `.git/config` file in the current working directory or `cwd` argument, which could be controlled by an attacker when analyzing untrusted codebases.
**Prevention:** Explicitly pass `("-c", "core.fsmonitor=false")` as `_SAFE_GIT_CONFIG` to all `git` subprocess commands in the codebase.

## 2026-06-21 - [Add Unsafe PyYAML Loaders to Taint Tracking]
**Vulnerability:** The static analyzer was missing `yaml.unsafe_load` and `yaml.full_load` in its `_SERIALISATION_SINKS` mapping, potentially leading to false negatives when tracking untrusted data flowing into these dangerous deserialization functions.
**Learning:** Even if functions are listed in rule specifications (like `_SINK_SPECS`), they also need to be properly categorized in the core taint propagation logic (`_SERIALISATION_SINKS`) to ensure the analyzer correctly sheds validation provenance (converting output to `UNKNOWN_RAW`).
**Prevention:** When adding new sinks to rule definitions, always verify if they need to be added to core propagation mappings like `_SERIALISATION_SINKS` or `_PROPAGATING_BUILTINS`.

## 2025-10-09 - [Add Missing Deserialization Sinks to Core Taint Propagation]
**Vulnerability:** The static analyzer was missing `shelve.open`, `dill.load`, `dill.loads`, `jsonpickle.decode`, `joblib.load`, `torch.load`, and `numpy.load` in its `_SERIALISATION_SINKS` mapping, potentially leading to false negatives when tracking untrusted data flowing into these dangerous deserialization functions.
**Learning:** Even if functions are listed in rule specifications (like `_SINK_SPECS` in `untrusted_to_deserialization.py`), they also need to be properly categorized in the core taint propagation logic (`_SERIALISATION_SINKS`) to ensure the analyzer correctly sheds validation provenance (converting output to `UNKNOWN_RAW`).
**Prevention:** When adding new sinks to rule definitions, always verify if they need to be added to core propagation mappings like `_SERIALISATION_SINKS` or `_PROPAGATING_BUILTINS`.
