"""On a Rust parity failure, dump the freshly-captured ``actual`` to /tmp and emit
a unified-diff head (the Rust sibling of ``golden/identity/conftest.py`` — the
parent hook keys on the Python oracle's stash key and ignores these tests)."""

from __future__ import annotations

import difflib
from pathlib import Path

import pytest

_HERE = Path(__file__).parent


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item: pytest.Item, call: pytest.CallInfo):  # type: ignore[no-untyped-def]
    outcome = yield
    report = outcome.get_result()
    if report.when != "call" or report.passed:
        return
    from golden.identity.rust.test_rust_identity_parity import _ACTUAL_KEY  # type: ignore[import-not-found]

    stashed = item.stash.get(_ACTUAL_KEY, None)
    if stashed is None:
        return
    name, actual = stashed
    dump = Path("/tmp") / f"corpus_actual_rust_{name}.json"
    dump.write_text(actual, encoding="utf-8")
    golden_path = _HERE / "corpus" / f"{name}.json"
    golden = golden_path.read_text(encoding="utf-8") if golden_path.exists() else ""
    diff = "".join(
        difflib.unified_diff(
            golden.splitlines(keepends=True),
            actual.splitlines(keepends=True),
            fromfile=f"corpus/{name}.json (committed)",
            tofile=f"/tmp/corpus_actual_rust_{name}.json (now)",
            n=2,
        )
    )
    head = "\n".join(diff.splitlines()[:60])
    report.sections.append((f"rust identity corpus diff [{name}]", head or "(no line diff; check byte/encoding)"))
