## 2025-02-18 - Prevent Command Injection via git config

**Vulnerability:** Invoking `git` commands via `subprocess` against potentially untrusted directories can lead to local code execution via a malicious `.git/config` file (e.g., using a malicious `core.fsmonitor` script).
**Learning:** `subprocess.run` calls that execute `git` must be secured against malicious repository configurations, even for read-only commands like `rev-parse` or `ls-files`.
**Prevention:** Always apply the configuration `("-c", "core.fsmonitor=false")` (typically defined as `_SAFE_GIT_CONFIG`) to prevent local code execution when running `git` via `subprocess`.
