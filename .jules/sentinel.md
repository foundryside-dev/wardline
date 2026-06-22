## 2024-06-22 - Prevent Local Code Execution via .git/config
**Vulnerability:** Invoking `git` via `subprocess.run` against potentially untrusted directories can lead to local code execution via malicious `.git/config` files (e.g. `core.fsmonitor`).
**Learning:** `git` executes configuration commands locally when run in a directory containing a `.git` structure, making seemingly safe operations like `git rev-parse` or `git diff` vulnerable to execution of arbitrary shell commands.
**Prevention:** Always append the configuration `("-c", "core.fsmonitor=false")` (typically defined as `_SAFE_GIT_CONFIG`) to the `git` command when invoking it via `subprocess.run` on user-controlled or arbitrary paths.
