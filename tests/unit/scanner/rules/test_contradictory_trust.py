from __future__ import annotations

import textwrap
from pathlib import Path

from wardline.core.config import WardlineConfig
from wardline.core.finding import Kind, Severity
from wardline.scanner.analyzer import WardlineAnalyzer
from wardline.scanner.rules.contradictory_trust import ContradictoryTrust


def _analyze(tmp_path: Path, src: str):
    p = tmp_path / "m.py"
    p.write_text(textwrap.dedent(src), encoding="utf-8")
    analyzer = WardlineAnalyzer()
    analyzer.analyze([p], WardlineConfig(), root=tmp_path)
    assert analyzer.last_context is not None
    return analyzer.last_context


def _run(ctx):
    return ContradictoryTrust().check(ctx)


def test_two_distinct_markers_fire_at_error(tmp_path) -> None:
    ctx = _analyze(
        tmp_path,
        """
        from wardline.decorators import trusted, external_boundary
        @trusted
        @external_boundary
        def f(p):
            return p
        """,
    )
    findings = _run(ctx)
    assert [(f.rule_id, f.qualname) for f in findings] == [("PY-WL-110", "m.f")]
    assert findings[0].kind == Kind.DEFECT
    assert findings[0].severity == Severity.WARN  # declaration-gated hygiene, not modulated


def test_single_marker_does_not_fire(tmp_path) -> None:
    ctx = _analyze(
        tmp_path,
        """
        from wardline.decorators import trusted
        @trusted
        def f(p):
            return p
        """,
    )
    assert _run(ctx) == []


def test_marker_plus_nontrust_decorator_does_not_fire(tmp_path) -> None:
    ctx = _analyze(
        tmp_path,
        """
        from wardline.decorators import trusted
        def deco(fn):
            return fn
        @deco
        @trusted
        def g(p):
            return p
        """,
    )
    assert [f for f in _run(ctx) if f.qualname == "m.g"] == []


def test_two_same_markers_do_not_fire(tmp_path) -> None:
    # Distinctness is by canonical name — two of the SAME marker is not contradictory.
    ctx = _analyze(
        tmp_path,
        """
        from wardline.decorators import trusted
        @trusted
        @trusted(level='ASSURED')
        def f(p):
            return p
        """,
    )
    assert _run(ctx) == []


def test_undecorated_does_not_fire(tmp_path) -> None:
    ctx = _analyze(tmp_path, "def f(p):\n    return p\n")
    assert _run(ctx) == []


def test_two_distinct_markers_with_call_form_fire(tmp_path) -> None:
    # Markers in their called form (@trust_boundary(...) + @trusted(...)) still count.
    ctx = _analyze(
        tmp_path,
        """
        from wardline.decorators import trusted, trust_boundary
        @trusted(level='ASSURED')
        @trust_boundary(to_level='ASSURED')
        def f(p):
            if not p:
                raise ValueError
            return p
        """,
    )
    assert [(x.rule_id, x.qualname) for x in _run(ctx)] == [("PY-WL-110", "m.f")]


def test_aliased_decorators_fire(tmp_path) -> None:
    # Test LOG-03 alias resolution fix. Aliased decorators must be resolved
    # to canonical names and detect contradictory annotations.
    ctx = _analyze(
        tmp_path,
        """
        from wardline.decorators import trusted as my_trusted, external_boundary as my_boundary
        @my_trusted
        @my_boundary
        def f(p):
            return p
        """,
    )
    findings = _run(ctx)
    assert [(f.rule_id, f.qualname) for f in findings] == [("PY-WL-110", "m.f")]


def test_weft_markers_namespace_fires(tmp_path) -> None:
    # wardline-d62845bb18: a contradictory stack imported from the renamed
    # `weft_markers` shim must fire identically to `wardline.decorators` — it is
    # a recognised boundary namespace in the builtin grammar (BUILTIN_BOUNDARY_TYPES).
    ctx = _analyze(
        tmp_path,
        """
        from weft_markers import external_boundary, trusted
        @trusted
        @external_boundary
        def conflicting(p):
            return p
        """,
    )
    findings = _run(ctx)
    assert [(f.rule_id, f.qualname) for f in findings] == [("PY-WL-110", "m.conflicting")]


def test_user_own_trust_named_decorators_do_not_fire(tmp_path) -> None:
    # A user's OWN @trusted / @external_boundary imported from a NON-grammar module must
    # not be mistaken for the builtin trust vocabulary. Here the engine never anchors the
    # entity (provenance source = "fallback", not "anchored"), so the rule's opt-in gate
    # (prov.source == "anchored") filters it before marker-counting. This guards the
    # system-level behaviour: foreign trust-named decorators don't trip PY-WL-110 at all.
    ctx = _analyze(
        tmp_path,
        """
        from myapp.security import trusted, external_boundary
        @trusted
        @external_boundary
        def f(p):
            return p
        """,
    )
    assert _run(ctx) == []


def test_anchored_entity_ignores_foreign_module_marker(tmp_path) -> None:
    # The isolating guard for the `_MARKER_MODULE_PREFIXES` check (contradictory_trust.py
    # line ~81). This entity DOES anchor (via the real `wardline.decorators.trust_boundary`
    # validator), so it passes the prov.source=="anchored" gate — but the coincidentally
    # named `myapp.security.trusted` must NOT be counted as a second marker, because its
    # module prefix is not in the grammar. Only `trust_boundary` counts, so len(markers) < 2
    # and nothing fires. If the prefix check regressed (keying on the bare name), the foreign
    # `trusted` would be counted, yielding a FALSE PY-WL-110 on legitimate user code.
    # (Verified empirically: without this guard the foreign marker is counted and it fires.)
    ctx = _analyze(
        tmp_path,
        """
        from wardline.decorators import trust_boundary
        from myapp.security import trusted
        @trust_boundary(to_level='ASSURED')
        @trusted
        def f(p):
            if not p:
                raise ValueError
            return p
        """,
    )
    assert _run(ctx) == []


def test_weft_markers_call_form_fires(tmp_path) -> None:
    # The called form (@trusted(level=...) + @external_boundary) over weft_markers.
    ctx = _analyze(
        tmp_path,
        """
        from weft_markers import external_boundary, trusted
        @trusted(level='ASSURED')
        @external_boundary
        def conflicting(p):
            return p
        """,
    )
    findings = _run(ctx)
    assert [(f.rule_id, f.qualname) for f in findings] == [("PY-WL-110", "m.conflicting")]


def test_nested_path_marker_engine_rejects_does_not_fire(tmp_path) -> None:
    # wardline-09c09f14df: PY-WL-110 must not count a marker the engine's seeding
    # (`_is_builtin_decorator_fqn`) rejects. `wardline.decorators.sub.external_boundary`
    # is an arbitrarily-nested path the engine does NOT recognise as a builtin export,
    # so it is never seeded; only `wardline.decorators.trust_boundary` anchors the
    # entity. With exactly one recognised marker there is no clash — the rule must stay
    # silent. (Before the fix the loose `startswith(prefix + ".")` test counted both,
    # firing a false PY-WL-110.)
    ctx = _analyze(
        tmp_path,
        """
        import wardline.decorators
        import wardline.decorators.sub
        @wardline.decorators.trust_boundary(to_level='ASSURED')
        @wardline.decorators.sub.external_boundary
        def f(p):
            if not p:
                raise ValueError
            return p
        """,
    )
    assert _run(ctx) == []

    # Control (false-negative guard): a GENUINE two-valid-marker clash — two EXACT
    # builtin exports the engine DOES both seed — must STILL fire PY-WL-110.
    ctx2 = _analyze(
        tmp_path,
        """
        from wardline.decorators import trusted, external_boundary
        @trusted
        @external_boundary
        def g(p):
            return p
        """,
    )
    assert [(x.rule_id, x.qualname) for x in _run(ctx2)] == [("PY-WL-110", "m.g")]
