## 2026-06-08 - _SAFE_GIT_CONFIG Required for git subprocesses
**Vulnerability:** Calling `git` via `subprocess` against potentially untrusted directories can lead to local code execution via malicious `.git/config` files (e.g., `core.fsmonitor` exploitation).
**Learning:** This codebase explicitly dictates that `("-c", "core.fsmonitor=false")` (typically defined as `_SAFE_GIT_CONFIG`) MUST be applied to all `git` subprocess calls to prevent this vulnerability class. Some files (e.g., `src/wardline/core/delta.py` and `src/wardline/core/legis.py`) were missed.
**Prevention:** Always verify `_SAFE_GIT_CONFIG` is prepended to `git` command arguments when using `subprocess.run` to call `git`.
