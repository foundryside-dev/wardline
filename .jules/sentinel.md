## 2024-05-18 - Prevent Command Injection via Malicious Git Configuration
**Vulnerability:** Subprocess calls to `git` without `core.fsmonitor=false` can execute arbitrary commands if a malicious `.git/config` is present in an untrusted directory.
**Learning:** Tools that scan or process untrusted directories must protect themselves against malicious local configuration files that tools like `git` might automatically load and execute.
**Prevention:** When invoking `git` via `subprocess` against potentially untrusted directories, always apply the configuration `("-c", "core.fsmonitor=false")` (defined as `_SAFE_GIT_CONFIG`) to prevent local code execution.
