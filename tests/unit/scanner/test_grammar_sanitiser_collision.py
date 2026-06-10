# tests/unit/scanner/test_grammar_sanitiser_collision.py
"""WLN-CONFIG-SANITISER-SINK-COLLISION — a config sanitiser naming a built-in
serialisation sink can never take effect (the conservative sink override wins),
yet it still counts as "matched", suppressing WLN-CONFIG-UNUSED-SANITISER. The
collision must surface as an explicit config-diagnostic FACT, not a silent no-op.
"""

from __future__ import annotations

from wardline.core.finding import Kind, Severity
from wardline.scanner.grammar import build_sanitiser_collision_findings


def test_colliding_sanitiser_emits_diagnostic() -> None:
    findings = build_sanitiser_collision_findings(("json.loads",))
    assert [f.rule_id for f in findings] == ["WLN-CONFIG-SANITISER-SINK-COLLISION"]
    f = findings[0]
    assert f.kind is Kind.FACT
    assert f.severity is Severity.NONE  # diagnostic, not a gate-able defect
    assert f.location.path == "weft.toml"  # config diagnostics point at the config surface
    assert "json.loads" in f.message
    assert "serialisation sink" in f.message
    assert f.properties["sanitiser"] == "json.loads"


def test_non_colliding_sanitiser_is_silent() -> None:
    assert build_sanitiser_collision_findings(("mylib.clean",)) == []


def test_empty_config_is_silent() -> None:
    assert build_sanitiser_collision_findings(()) == []


def test_multiple_collisions_sorted_with_distinct_fingerprints() -> None:
    findings = build_sanitiser_collision_findings(("pickle.loads", "mylib.clean", "json.loads"))
    assert [f.properties["sanitiser"] for f in findings] == ["json.loads", "pickle.loads"]
    assert len({f.fingerprint for f in findings}) == 2
