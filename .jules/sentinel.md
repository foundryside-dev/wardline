## 2024-06-28 - Local Code Execution via Git Config
**Vulnerability:** Invoking `git` via `subprocess` against potentially untrusted directories can lead to local code execution via malicious `.git/config` files (e.g., via `core.fsmonitor`).
**Learning:** While some modules (e.g., `attest.py`) were correctly mitigating this by using `_SAFE_GIT_CONFIG = ("-c", "core.fsmonitor=false")`, others (e.g., `delta.py`, `legis.py`) were not, leaving gaps in security posture when interacting with untrusted git repos.
**Prevention:** Always apply the `("-c", "core.fsmonitor=false")` configuration to all `subprocess.run(["git", ...])` calls when operating on potentially untrusted directories.
