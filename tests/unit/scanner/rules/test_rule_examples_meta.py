"""Meta-test: every builtin rule's documented examples actually behave.

The ``examples_violation`` / ``examples_clean`` snippets carried by each rule's
``RuleMetadata`` are agent-facing — they ship in ``wardline explain`` and feed
the docs. Without a contract they rot silently (we hit exactly this during the
T1.5 rule-breadth work: a PY-WL-101 example referenced an undefined helper, so
the engine fail-closed to a FACT and the example never fired). This test makes
the examples a verified contract and a forcing function: no rule can ship
without a violation example that *fires* it and a clean example that does *not*.

**Ambient imports.** Metadata snippets are concise illustrations that omit the
``from wardline.decorators import ...`` boilerplate every real module carries
(matching the convention in the per-rule unit tests). The harness prepends that
one import line so the decorator vocabulary resolves. This supplies ambient
context only — it cannot mask semantic rot (a missing ``@external_boundary`` on
a source, an unprovable taint path), which is the rot class this test exists to
catch.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from wardline.core.config import WardlineConfig
from wardline.scanner.analyzer import WardlineAnalyzer
from wardline.scanner.rules import BUILTIN_RULE_CLASSES

_IMPORTS = "from wardline.decorators import external_boundary, trust_boundary, trusted\n"


def _rule_ids(tmp_path: Path, snippet: str) -> set[str]:
    """Scan one example snippet as its own isolated module; return the rule ids fired."""
    src = tmp_path / "example.py"
    src.write_text(_IMPORTS + textwrap.dedent(snippet), encoding="utf-8")
    analyzer = WardlineAnalyzer()
    findings = analyzer.analyze([src], WardlineConfig(), root=tmp_path)
    return {f.rule_id for f in findings}


# (rule_id, snippet) pairs — flattened so a single failure names the exact example.
_VIOLATION_CASES = [
    pytest.param(cls.rule_id, ex, id=f"{cls.rule_id}-violation-{i}")
    for cls in BUILTIN_RULE_CLASSES
    for i, ex in enumerate(cls.metadata.examples_violation)
]
_CLEAN_CASES = [
    pytest.param(cls.rule_id, ex, id=f"{cls.rule_id}-clean-{i}")
    for cls in BUILTIN_RULE_CLASSES
    for i, ex in enumerate(cls.metadata.examples_clean)
]


@pytest.mark.parametrize(("rule_id", "snippet"), _VIOLATION_CASES)
def test_violation_example_fires_its_rule(tmp_path: Path, rule_id: str, snippet: str) -> None:
    fired = _rule_ids(tmp_path, snippet)
    assert rule_id in fired, f"{rule_id} violation example did not fire it; fired={sorted(fired)}"


@pytest.mark.parametrize(("rule_id", "snippet"), _CLEAN_CASES)
def test_clean_example_does_not_fire_its_rule(tmp_path: Path, rule_id: str, snippet: str) -> None:
    fired = _rule_ids(tmp_path, snippet)
    assert rule_id not in fired, f"{rule_id} clean example wrongly fired it; fired={sorted(fired)}"


@pytest.mark.parametrize("cls", BUILTIN_RULE_CLASSES, ids=[c.rule_id for c in BUILTIN_RULE_CLASSES])
def test_every_builtin_rule_ships_both_example_kinds(cls: type) -> None:
    # Forcing function: a rule with no working violation/clean example is undocumented.
    assert cls.metadata.examples_violation, f"{cls.rule_id} has no examples_violation"
    assert cls.metadata.examples_clean, f"{cls.rule_id} has no examples_clean"
