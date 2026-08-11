# tests/unit/scanner/rules/test_invalid_decorator_level.py
"""Tests for PY-WL-114: invalid or out-of-range builtin trust decorator levels."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from wardline.core.config import WardlineConfig
from wardline.core.finding import Kind, Severity
from wardline.scanner.analyzer import WardlineAnalyzer
from wardline.scanner.marker_reader import alias_map_for_qualname
from wardline.scanner.rules.invalid_decorator_level import InvalidDecoratorLevel, _owning_module


def _analyze(tmp_path: Path, src: str) -> tuple[WardlineAnalyzer, object]:
    p = tmp_path / "m.py"
    p.write_text(textwrap.dedent(src), encoding="utf-8")
    analyzer = WardlineAnalyzer()
    analyzer.analyze([p], WardlineConfig(), root=tmp_path)
    assert analyzer.last_context is not None
    return analyzer, analyzer.last_context


def test_invalid_decorator_level_trusted_typo(tmp_path) -> None:
    _, ctx = _analyze(
        tmp_path,
        """
        from wardline.decorators import trusted

        @trusted(level='ASURED')
        def f(p):
            return p
        """,
    )
    findings = InvalidDecoratorLevel().check(ctx)
    assert [(f.rule_id, f.qualname) for f in findings] == [("PY-WL-114", "m.f")]
    assert findings[0].kind == Kind.DEFECT
    assert findings[0].severity == Severity.ERROR
    assert "ASURED" in findings[0].message


def test_invalid_decorator_level_boundary_out_of_range(tmp_path) -> None:
    _, ctx = _analyze(
        tmp_path,
        """
        from wardline.decorators import trust_boundary

        @trust_boundary(to_level='INTEGRAL')
        def g(p):
            if not p: raise ValueError
            return p
        """,
    )
    findings = InvalidDecoratorLevel().check(ctx)
    assert [(f.rule_id, f.qualname) for f in findings] == [("PY-WL-114", "m.g")]
    assert "INTEGRAL" in findings[0].message


def test_invalid_decorator_level_invalid_name(tmp_path) -> None:
    _, ctx = _analyze(
        tmp_path,
        """
        from wardline.decorators import trusted

        @trusted(level='BOGUS')
        def h(p):
            return p
        """,
    )
    findings = InvalidDecoratorLevel().check(ctx)
    assert [(f.rule_id, f.qualname) for f in findings] == [("PY-WL-114", "m.h")]


def test_invalid_decorator_level_clean_cases(tmp_path) -> None:
    # NOTE on the last case, renamed from ``clean_dynamic`` to ``unreadable_dynamic``
    # (declaration-surface-v2 P9): PY-WL-114's silence on ``@trusted(level=cfg.LEVEL)``
    # is CORRECT — ``cfg`` never alias-resolves to the exact known ``TaintState`` export,
    # so the value is UNREADABLE, not clean. The zero-findings assertion below is right
    # both at this commit and after the residual-FACT task. The name had to change
    # because a function called ``clean_*`` inside this fixture teaches that an
    # unreadable builtin LEVEL value is *clean*, which is the trap the shipped
    # ``examples_clean`` exemplar was deleted to remove.
    # ``WLN-ENGINE-UNREADABLE-MARKER-VALUE`` is the channel that speaks for it.
    _, ctx = _analyze(
        tmp_path,
        """
        from wardline.decorators import trusted, trust_boundary

        @trusted(level='INTEGRAL')
        def clean_1(p):
            return p

        @trusted(level='ASSURED')
        def clean_2(p):
            return p

        @trust_boundary(to_level='GUARDED')
        def clean_3(p):
            if not p: raise ValueError
            return p

        @trusted(level=cfg.LEVEL)
        def unreadable_dynamic(p):
            return p
        """,
    )
    findings = InvalidDecoratorLevel().check(ctx)
    assert len(findings) == 0


def test_invalid_decorator_level_aliased_builtin_fires(tmp_path) -> None:
    # The FN: an aliased builtin decorator with a typo'd level silently disables the gate
    # AND escaped the rule meant to catch it. Resolving through the alias map fixes it
    # (wardline-0267c31cd8).
    _, ctx = _analyze(
        tmp_path,
        """
        from wardline.decorators import trusted as t

        @t(level='ASURED')
        def f(p):
            return p
        """,
    )
    findings = InvalidDecoratorLevel().check(ctx)
    assert [(f.rule_id, f.qualname) for f in findings] == [("PY-WL-114", "m.f")]


def test_invalid_decorator_level_aliased_valid_does_not_fire(tmp_path) -> None:
    # Guard: the alias resolution must not over-fire on a VALID aliased level.
    _, ctx = _analyze(
        tmp_path,
        """
        from wardline.decorators import trusted as t

        @t(level='ASSURED')
        def f(p):
            return p
        """,
    )
    assert InvalidDecoratorLevel().check(ctx) == []


def test_invalid_decorator_level_foreign_same_name_does_not_fire(tmp_path) -> None:
    # The FP: a non-wardline decorator that merely happens to be spelled ``trusted`` is not
    # the builtin marker — an invalid level on it is out of scope (wardline-0267c31cd8).
    _, ctx = _analyze(
        tmp_path,
        """
        import other_pkg

        @other_pkg.trusted(level='BOGUS')
        def f(p):
            return p
        """,
    )
    assert InvalidDecoratorLevel().check(ctx) == []


def test_invalid_decorator_level_local_same_name_does_not_fire(tmp_path) -> None:
    # The FP: a locally-defined ``trusted`` decorator is not the builtin marker.
    _, ctx = _analyze(
        tmp_path,
        """
        def trusted(**kw):
            def deco(fn):
                return fn
            return deco

        @trusted(level='BOGUS')
        def f(p):
            return p
        """,
    )
    assert InvalidDecoratorLevel().check(ctx) == []


def test_foreign_taintstate_receiver_is_silent(tmp_path) -> None:
    # Behaviour delta (b), pinned as a UNIT ASSERTION rather than a shipped clean
    # exemplar: the old local reader accepted ANY receiver whose dotted text ended in
    # ``.TaintState``, so a foreign / re-exported ``myconfig.TaintState`` produced a
    # PY-WL-114 the provider never agreed with (the provider requires the receiver to
    # alias-resolve to the exact ``wardline.core.taints.TaintState`` export, so it drops
    # the seed WITHOUT reading a token). The shared reader is STRICT, so both sides now
    # agree: the value is UNREADABLE and this rule stays silent. Shipping this snippet as
    # an ``examples_clean`` entry instead would re-form the unreadable-is-clean trap.
    _, ctx = _analyze(
        tmp_path,
        """
        from wardline.decorators import trusted
        import myconfig

        @trusted(level=myconfig.TaintState.ASURED)
        def f(p):
            return p
        """,
    )
    assert InvalidDecoratorLevel().check(ctx) == []


def test_aliased_genuine_taintstate_typo_fires(tmp_path) -> None:
    # Behaviour delta (a), the FN direction the shared reader closes: an ALIASED genuine
    # ``TaintState`` with a typo alias-resolves to the exact known export, so the provider
    # reads the token, ``TaintState('ASURED')`` fails and the seed drops — the rule must
    # read it identically and FIRE. The old local reader keyed on the trailing text
    # ``TaintState`` and happened to fire here too, but for the wrong reason; this pins
    # the alias-resolved path explicitly so a later narrowing cannot ship green.
    _, ctx = _analyze(
        tmp_path,
        """
        from wardline.decorators import trusted
        from wardline.core.taints import TaintState as T

        @trusted(level=T.ASURED)
        def f(p):
            return p
        """,
    )
    assert [(f.rule_id, f.qualname) for f in InvalidDecoratorLevel().check(ctx)] == [("PY-WL-114", "m.f")]


def test_readable_typo_inside_a_literal_splat_fires(tmp_path) -> None:
    # Behaviour delta (c): ``@trusted(**{"level": "ASURED"})`` is a shape-VALID call whose
    # level token is statically readable and invalid. The old hand-written keyword loop
    # only looked at direct keywords, so it missed it entirely; the shared
    # ``extract_keywords`` normalises one literal dict before the level is read, so the
    # typo now reaches PY-WL-114 rather than nothing at all.
    _, ctx = _analyze(
        tmp_path,
        """
        from wardline.decorators import trusted

        @trusted(**{"level": "ASURED"})
        def f(p):
            return p
        """,
    )
    assert [(f.rule_id, f.qualname) for f in InvalidDecoratorLevel().check(ctx)] == [("PY-WL-114", "m.f")]


def test_shape_malformed_marker_is_silent(tmp_path) -> None:
    # SHAPE IS DECIDED FIRST AND SHORT-CIRCUITS. An undeclared keyword makes the call
    # shape malformed, so the engine drops the seed at the shape gate and never reads the
    # LEVEL value — PY-WL-114 must not claim to have read it. Between this commit and
    # PY-WL-130's arrival this site has no rule-side channel at all; that window is
    # intra-plan, pre-release, and the released reader already drops the seed.
    _, ctx = _analyze(
        tmp_path,
        """
        from wardline.decorators import trusted

        @trusted(level='ASURED', audit=True)
        def f(p):
            return p
        """,
    )
    assert InvalidDecoratorLevel().check(ctx) == []


def test_weft_markers_ghost_trust_submodule_is_silent(tmp_path) -> None:
    # The accepted-export table is ROOT-SPECIFIC: ``weft_markers`` has no ``trust``
    # submodule, so ``weft_markers.trust.trusted`` is a ghost export that seeding rejects.
    # The rule must reject it identically — firing here would report a typo on a marker
    # that anchors nothing (the provider-side twin lives in the decorator-provider tests).
    _, ctx = _analyze(
        tmp_path,
        """
        from weft_markers.trust import trusted

        @trusted(level='ASURED')
        def f(p):
            return p
        """,
    )
    assert InvalidDecoratorLevel().check(ctx) == []


def test_stacked_identical_decorators_have_distinct_fingerprints(tmp_path) -> None:
    # Soundness / fingerprint collision (wardline-377b896a87): two stacked identical invalid
    # decorators on ONE def are two distinct findings, but the fingerprint anchored at the
    # ENTITY line with taint_path=f"{name}:{token}" (no within-def discriminator) collapsed them
    # to one key — one silently masking the other on the baseline/waiver/judge/Filigree joins.
    # The decorators share name, token, AND entity line; the only thing that tells them apart is
    # their POSITION in the decorator_list, so the discriminator carries the decorator ordinal
    # (move-stable: invariant to the def moving and to column shifts; collision-complete since at
    # most one finding is emitted per decorator).
    _, ctx = _analyze(
        tmp_path,
        """
        from wardline.decorators import trust_boundary

        @trust_boundary(to_level='bogus')
        @trust_boundary(to_level='bogus')
        def handler(p):
            if not p: raise ValueError
            return p
        """,
    )
    findings = InvalidDecoratorLevel().check(ctx)
    assert len(findings) == 2, "both invalid decorators must be reported"
    fps = {f.fingerprint for f in findings}
    assert len(fps) == 2, "two distinct findings must not share a fingerprint (collision)"


def test_form5_resolvable_invalid_token_now_fires(tmp_path) -> None:
    # THE ONE VERDICT THAT MOVES when PY-WL-114 stops being form-5-blind. Until the
    # rule read the REAL per-module census it was handed an inert one, so a bare
    # ``Name`` in a builtin LEVEL slot resolved nothing and the typo was SILENTLY
    # SKIPPED — the fail-open direction, and the rule half of the one-sided widening
    # spec §4.2.1 names as a silent false green.
    #
    # ``_SVC_LEVEL`` satisfies form 5 in full: a BUILTIN marker, a reference site that
    # is a ``def`` DIRECTLY in ``Module.body``, exactly one qualifying unconditional
    # module-scope binding, lexically preceding the decorated ``def``. It resolves to
    # ``'ASURED'``, which is READ-then-rejected — PY-WL-114's DEFECT.
    #
    # ``_analyze`` runs the real ``WardlineAnalyzer.analyze``, so ``module_censuses``
    # is populated on the ANALYSER'S OWN construction path, not by a hand-built
    # context. The assertion is deliberately RULE-SIDE ONLY: the provider does not
    # resolve form 5 until the seeding task, so a ``declared_qualnames`` assertion
    # here would be a stale cross-reader claim. Both readers are asserted together,
    # on one scan, by ``test_form5_agreement``'s invalid-token row in the task that
    # owns it.
    _, ctx = _analyze(
        tmp_path,
        """
        from wardline.decorators import trusted

        _SVC_LEVEL = 'ASURED'

        @trusted(level=_SVC_LEVEL)
        def f(p):
            return p
        """,
    )
    assert [(f.rule_id, f.qualname) for f in InvalidDecoratorLevel().check(ctx)] == [("PY-WL-114", "m.f")]


def test_form5_on_a_method_is_keyed_by_the_owning_module_not_a_qualname_split(tmp_path) -> None:
    # THE KEYING PIN. ``AnalysisContext.module_censuses`` is keyed by MODULE, and a
    # naive ``qualname.rsplit('.', 1)[0]`` yields ``m.C`` for the method ``m.C.method``
    # — a MISS. A miss is the ABSENT sentinel, so the shared reader RAISES on
    # legitimate code, which the analyser turns into a gate-eligible
    # WLN-ENGINE-RULE-FAILED: fail-loud-and-WRONG on precisely the method shape spec
    # §4.2.1 spends a paragraph refusing.
    #
    # Correct longest-owning-module keying gives census-PRESENT, and the method's
    # ``def`` is not a direct element of ``Module.body``, so it is an ineligible
    # reference site -> ``None`` -> ordinary unreadable -> silence.
    #
    # ONE resolution serves BOTH module-keyed lookups (the alias map and the census),
    # so the fixture pins the shared key from the side that is observable: ``bad``
    # carries a plain string typo and MUST fire, which it can only do if the method's
    # alias map resolved through the same longest-owning-module key the census lookup
    # uses. Under a naive split both lookups miss together and this assertion reds.
    # ``form5`` then adds the census half: silence, and — load-bearing — no RAISE.
    _, ctx = _analyze(
        tmp_path,
        """
        from wardline.decorators import trusted

        _SVC_LEVEL = 'ASURED'

        class C:
            @trusted(level='ASURED')
            def bad(self, p):
                return p

            @trusted(level=_SVC_LEVEL)
            def form5(self, p):
                return p
        """,
    )
    assert [(f.rule_id, f.qualname) for f in InvalidDecoratorLevel().check(ctx)] == [("PY-WL-114", "m.C.bad")]


@pytest.mark.parametrize(
    ("qualname", "alias_maps"),
    [
        ("m.C.method", {"m": {"t": "wardline.decorators.trusted"}}),  # the method shape
        ("pkg.sub.mod.f", {"pkg": {"a": "pkg.a"}, "pkg.sub.mod": {"b": "pkg.b"}}),  # longest owner wins
        ("pkg.mod", {"pkg.mod": {"x": "pkg.x"}}),  # qualname IS a module name
        ("other.f", {"pkg": {"x": "pkg.x"}}),  # no owner at all
        ("pkgx.f", {"pkg": {"x": "pkg.x"}}),  # prefix-without-dot is NOT an owner
        ("m.f", {}),  # no modules at all
    ],
)
def test_owning_module_key_agrees_with_the_engine_floor_alias_map_lookup(qualname, alias_maps) -> None:
    # THE MIRROR ANTI-DRIFT PIN. This rule stopped calling the engine floor's
    # ``alias_map_for_qualname`` when it started needing the module KEY (the helper
    # returns the MAP), so ``_owning_module`` + a ``.get`` now stands in for it here
    # while ``contradictory_trust.py`` still calls the helper. Without this pin, a
    # future change to ``alias_map_for_qualname``'s resolution would be picked up by
    # one rule and silently missed by the other. Deriving the map through
    # ``_owning_module``'s key must give the shipped helper's answer, exactly.
    mod_name = _owning_module(qualname, alias_maps)
    derived = alias_maps.get(mod_name, {}) if mod_name is not None else {}
    assert derived == alias_map_for_qualname(qualname, alias_maps)
