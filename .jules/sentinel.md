## 2024-06-27 - Local Code Execution via Git Configuration
**Vulnerability:** Untrusted repositories with malicious `.git/config` can execute arbitrary code when `subprocess.run(["git", ...])` is executed within their directory tree (specifically via settings like `core.fsmonitor`).
**Learning:** Git commands executed by `subprocess` without explicit isolation will respect local `.git/config` files, allowing an attacker to run arbitrary code on the scanning machine when an untrusted repository is parsed.
**Prevention:** Always explicitly disable dangerous config variables when executing `git` commands in Python by injecting `("-c", "core.fsmonitor=false")` (defined as `_SAFE_GIT_CONFIG`) into the argument list of `subprocess.run()`.
