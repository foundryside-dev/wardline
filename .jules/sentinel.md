## 2026-06-24 - Prevent Git Config Local Code Execution
**Vulnerability:** Invoking `git` via `subprocess` against potentially untrusted directories can lead to local code execution via malicious `.git/config` files (for example using the `core.fsmonitor` configuration).
**Learning:** Even simple git operations like `git status` or `git rev-parse` can execute arbitrary code if run against an attacker-controlled directory containing a malicious `.git/config`.
**Prevention:** Always apply the configuration `("-c", "core.fsmonitor=false")` (typically defined as `_SAFE_GIT_CONFIG` in this codebase) when invoking `git` via `subprocess` against potentially untrusted directories.
