## 2024-05-24 - Arbitrary code execution via git config in untrusted repositories
**Vulnerability:** Calling `git` without disabling `core.fsmonitor` allows local code execution from `.git/config` when run against an untrusted repository.
**Learning:** Python`s `subprocess.run(["git", ...])` is vulnerable to RCE if an attacker provides a malicious `.git/config` configuring `core.fsmonitor` to execute arbitrary shell scripts. Although `src/wardline/core/attest.py` properly safeguarded this with `_SAFE_GIT_CONFIG`, other files (`delta.py`, `legis.py`) were not using it.
**Prevention:** Always use `_SAFE_GIT_CONFIG = ("-c", "core.fsmonitor=false")` for any git invocations via `subprocess` against directories that might be untrusted, especially inside static analyzers.
