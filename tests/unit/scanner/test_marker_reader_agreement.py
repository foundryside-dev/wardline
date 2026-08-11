"""P9 — one marker-reading grammar: the rule-side reader IS the provider-side reader."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from wardline.core.registry import MarkerCallForm
from wardline.core.run import run_scan
from wardline.core.taints import TaintState
from wardline.scanner.marker_reader import (
    BUILTIN_MARKER_ROOTS,
    CensusBinding,
    LevelVerdict,
    ModuleCensus,
    alias_map_for_qualname,
    call_shape_offences,
    level_token,
    read_level,
    shadowed_builtin_roots,
)

# A PRESENT but EMPTY census: no bindings, not poisoned, no eligible reference
# sites. Test-local on purpose — the engine floor ships no such constant, because a
# public inert census is the defaulted-empty affordance spec rev 6 §4.2.1 forbids.
_EMPTY_CENSUS = ModuleCensus(values={}, poisoned=False, reference_sites=frozenset())

CASES = [
    ("'ASSURED'", {}, "ASSURED"),
    ("TaintState.ASSURED", {"TaintState": "wardline.core.taints.TaintState"}, "ASSURED"),
    ("taints.TaintState.ASSURED", {"taints": "wardline.core.taints"}, "ASSURED"),
    ("T.ASSURED", {"T": "wardline.core.taints.TaintState"}, "ASSURED"),  # aliased import
    # Foreign/re-exported TaintState: NOT the exact known export — unreadable.
    ("shim.TaintState.ASSURED", {"shim": "myapp.shim"}, None),
    ("myconfig.TaintState.ASURED", {"myconfig": "myconfig"}, None),
    # A bare Name against an EMPTY census is form 5's UNBOUND case — NOT a blanket
    # refusal of bare names. Rev 6 admits form 5; FORM5_CASES below pins it.
    ("LEVEL", {}, None),
    ("get_level()", {}, None),
    ("f'{x}'", {}, None),
    ("cfg.ASSURED", {"cfg": "myapp.cfg"}, None),
]


@pytest.mark.parametrize(("expr", "alias_map", "expected"), CASES)
def test_level_token_is_the_single_reader(expr: str, alias_map: dict, expected: str | None) -> None:
    value = ast.parse(expr, mode="eval").body
    assert (
        level_token(
            value,
            alias_map,
            census=_EMPTY_CENSUS,
            reference_site=None,
            shadowed_roots=frozenset(),
            builtin=True,
        )
        == expected
    )


# --- P3 form 5: the value-reference verdicts, at reader level ----------------------
# SUPPLEMENTARY UNIT CHECK ONLY. The census here is HAND-BUILT, which spec rev 6
# §4.2.1 refuses as evidence for P9 — P9's property is that both callers agree when
# driven through the analyser's OWN construction path. See the P9 note after this
# step for where that half lands. What this table pins is the READER's verdict per
# case, so a one-sided implementation of any single case is caught at unit level.


def _decorated_def(tree: ast.Module) -> ast.stmt:
    """The def/async def carrying the marker, wherever in the module it sits."""
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.decorator_list:
            return node
    raise AssertionError("fixture has no decorated def")


def _level_value(tree: ast.Module) -> ast.expr:
    # BOTH builtin LEVEL keywords, not just ``level=``. The mechanism is argument-name-
    # agnostic (``level_token`` never sees the argument name), so ``to_level=`` must be
    # exercised POSITIVELY or a later narrowing of form 5 to ``@trusted`` ships green —
    # spec :83's "so no second frozen marker is left behind".
    for node in ast.walk(tree):
        if isinstance(node, ast.keyword) and node.arg in {"level", "to_level"}:
            return node.value
    raise AssertionError("fixture has no level=/to_level= keyword")


_BOUND = CensusBinding(token="ASSURED", unreadable_reason=None, line=1)
_TWICE = CensusBinding(token=None, unreadable_reason="bound more than once in module scope", line=1)
_GLOBAL = CensusBinding(token=None, unreadable_reason="declared global in this module", line=1)
# The LEXICAL-PRECEDENCE counterexample: a qualifying, perfectly resolvable binding whose
# LINE falls AFTER the decorated ``def``'s. Everything else about it reads — only form 5's
# fifth conjunct refuses it (spec §4.2.1: "the binding must precede the decorated ``def``/
# ``async def`` in source order"). Line 4 is _AFTER's REAL binding line; its ``def`` is at
# line 2 (measured, CPython 3.13.1: a decorated FunctionDef's ``lineno`` is the ``def``
# line, decorators excluded).
_LATE = CensusBinding(token="ASSURED", unreadable_reason=None, line=4)

_TOP = "_SVC_LEVEL = 'ASSURED'\n@trusted(level=_SVC_LEVEL)\ndef f(p):\n    return p\n"
# The OTHER builtin LEVEL keyword. ``level_token`` never sees the argument name, so this
# fixture is a RECEIPT that form 5 is argument-name-agnostic, not a second mechanism —
# without it a later narrowing of form 5 to ``@trusted`` ships green (spec :83).
_TOP_TB = "_SVC_LEVEL = 'ASSURED'\n@trust_boundary(to_level=_SVC_LEVEL)\ndef f(p):\n    return p\n"
# Binding placed AFTER the decorated ``def``: the ``def`` is at line 2, the binding line 4.
_AFTER = "@trusted(level=_SVC_LEVEL)\ndef f(p):\n    return p\n_SVC_LEVEL = 'ASSURED'\n"
_METHOD = "_SVC_LEVEL = 'ASSURED'\nclass C:\n    @trusted(level=_SVC_LEVEL)\n    def f(self, p):\n        return p\n"
_COND = "_SVC_LEVEL = 'ASSURED'\nif TYPE_CHECKING:\n    @trusted(level=_SVC_LEVEL)\n    def f(p):\n        return p\n"

# (label, module source, census values, poisoned, reference site eligible, builtin,
#  expected token). Spec rev 6 §4.2.1's EIGHT mandated cases FIRST, in its own order,
#  FOLLOWED BY the rows this plan adds. The eight are a spec MINIMUM, never a maximum:
#  append any further row BELOW the added block rather than re-cutting either group.
FORM5_CASES = [
    ("bound", _TOP, {"_SVC_LEVEL": _BOUND}, False, True, True, "ASSURED"),
    ("unbound", _TOP, {}, False, True, True, None),
    ("method reference site", _METHOD, {"_SVC_LEVEL": _BOUND}, False, False, True, None),
    ("conditional def reference site", _COND, {"_SVC_LEVEL": _BOUND}, False, False, True, None),
    ("two-occurrence census", _TOP, {"_SVC_LEVEL": _TWICE}, False, True, True, None),
    ("global-declared name", _TOP, {"_SVC_LEVEL": _GLOBAL}, False, True, True, None),
    ("star-import poisoned module", _TOP, {"_SVC_LEVEL": _BOUND}, True, True, True, None),
    ("custom BoundaryType LEVEL arg", _TOP, {"_SVC_LEVEL": _BOUND}, False, True, False, None),
    # --- rows this plan ADDS beyond spec §4.2.1's eight ------------------------------
    # LEXICAL PRECEDENCE. The census entry resolves and the reference site IS eligible;
    # the only thing refusing this row is ``_LATE.line`` (4) failing to be strictly less
    # than the decorated ``def``'s ``lineno`` (2). A reader built without the fifth
    # conjunct returns "ASSURED" here — a MINTED SEED where spec :133 requires
    # UNREADABLE + FACT, which is the seed-minting direction and the dangerous one.
    ("binding after the def", _AFTER, {"_SVC_LEVEL": _LATE}, False, True, True, None),
    # POSITIVE ``to_level=``: form 5 RESOLVES on @trust_boundary exactly as on @trusted.
    ("to_level resolving", _TOP_TB, {"_SVC_LEVEL": _BOUND}, False, True, True, "ASSURED"),
]


@pytest.mark.parametrize(
    ("label", "src", "values", "poisoned", "eligible", "builtin", "expected"),
    FORM5_CASES,
    ids=[case[0] for case in FORM5_CASES],
)
def test_level_token_form5_verdicts(label, src, values, poisoned, eligible, builtin, expected) -> None:
    # The reference-site set is what decides the method and conditional-def rows —
    # NOT the census's value entries, which resolve perfectly well in both. The
    # census task pins that the BUILDER actually produces this set (a def nested in a
    # module-level ``if`` is ABSENT from it); without that pin this table would beg
    # its own question.
    tree = ast.parse(src)
    site = _decorated_def(tree)
    census = ModuleCensus(
        values=values,
        poisoned=poisoned,
        reference_sites=frozenset({site}) if eligible else frozenset(),
    )
    assert (
        level_token(
            _level_value(tree),
            {},
            census=census,
            reference_site=site,
            shadowed_roots=frozenset(),
            builtin=builtin,
        )
        == expected
    )


def test_absent_census_on_a_bare_name_is_a_plumbing_defect() -> None:
    # An ABSENT census and an EMPTY one are DIFFERENT inputs (spec rev 6 §4.2.1).
    # Empty is an ordinary unreadable; absent means no census was built for this
    # module at all — a plumbing defect, which must never be a quiet None. Rule side
    # lands on per-rule isolation as a WLN-ENGINE-RULE-FAILED ERROR DEFECT. On the
    # PROVIDER side the raise does NOT propagate out of the parse pass: verified in
    # source, the parse loop's bare ``except Exception`` per-file isolation handler
    # (pipeline.py:221) catches it, emits a WLN-ENGINE-FILE-FAILED ERROR DEFECT naming
    # the file, and continues with that file dropped from the analysed set — the
    # SyntaxError/UnicodeDecodeError/OSError guard at pipeline.py:182 is a DIFFERENT
    # handler and never sees it. Either way the plumbing defect lands as a gate-eligible
    # ERROR on the unsuppressed population, so a baseline row or waiver ANNOTATES it
    # without clearing the secure gate absent ``--trust-suppressions``. A scan that
    # reports the failure loudly is acceptable here; a scan that returns green is the
    # failure this contract exists to forbid.
    tree = ast.parse(_TOP)
    with pytest.raises(ValueError):
        level_token(
            _level_value(tree),
            {},
            census=None,
            reference_site=_decorated_def(tree),
            shadowed_roots=frozenset(),
            builtin=True,
        )


def test_absent_census_is_harmless_for_a_non_name_value() -> None:
    # The raise triggers on what the reader was HANDED — a bare Name in a LEVEL slot —
    # never on whether some other component ran. A str literal reads with no census,
    # which is what makes a direct construction or a test that never presents a bare
    # Name safe.
    tree = ast.parse("@trusted(level='ASSURED')\ndef f(p):\n    return p\n")
    assert (
        level_token(
            _level_value(tree),
            {},
            census=None,
            reference_site=_decorated_def(tree),
            shadowed_roots=frozenset(),
            builtin=True,
        )
        == "ASSURED"
    )


def test_absent_census_on_a_custom_marker_bare_name_does_not_raise() -> None:
    # The raise is BUILTIN-ONLY, and this row pins the cell the unconditional reading
    # gets wrong. Form 5 is builtin-only (spec :119), so on a custom ``BoundaryType`` no
    # census could change the verdict: a bare ``Name`` is an ordinary unreadable ``None``
    # and the released WLN-ENGINE-UNPROVABLE-BOUNDARY + UNKNOWN_RAW contract is untouched.
    # Reading the raise unconditionally instead reds three shipped custom-boundary cases
    # in tests/grammar/test_provider_loop.py (:48, :57, :72) at Task 5's commit.
    tree = ast.parse(_TOP)
    assert (
        level_token(
            _level_value(tree),
            {},
            census=None,
            reference_site=_decorated_def(tree),
            shadowed_roots=frozenset(),
            builtin=False,
        )
        is None
    )


def test_shadowed_root_refuses_a_direct_form2_level_value() -> None:
    # ``shadowed_roots`` must reach the ATTRIBUTE branch of the reader. Every other row
    # in this module passes ``frozenset()``, so without this one the parameter ships
    # UNREAD and Task 3 Step 5's test_shadowed_root_refusal_is_applied_at_the_census_build
    # has nothing to stand on — and Task 3 declares marker_reader.py NOT modified, so it
    # could not repair the reader from there. This is form 2 written DIRECTLY in the LEVEL
    # slot (spec §4.2.1's pre-existing gap), NOT form 5: form 5's own right-hand-side
    # shadowed-root refusal is applied at the census build and never re-derived here.
    tree = ast.parse("@trusted(level=TaintState.ASSURED)\ndef f(p):\n    return p\n")
    alias_map = {"TaintState": "wardline.core.taints.TaintState"}
    assert (
        level_token(
            _level_value(tree),
            alias_map,
            census=_EMPTY_CENSUS,
            reference_site=_decorated_def(tree),
            shadowed_roots=frozenset({"wardline"}),
            builtin=True,
        )
        is None
    )
    # The SAME value with no shadow reads normally, so this row pins the SHADOW and not
    # the value shape.
    assert (
        level_token(
            _level_value(tree),
            alias_map,
            census=_EMPTY_CENSUS,
            reference_site=_decorated_def(tree),
            shadowed_roots=frozenset(),
            builtin=True,
        )
        == "ASSURED"
    )


_DECLARED = frozenset({"level"})
_REQUIRED_NONE: frozenset[str] = frozenset()
_TB_DECLARED = frozenset({"to_level"})
_TB_REQUIRED = frozenset({"to_level"})

SHAPE_CASES = [
    ("trusted(level='ASSURED')", MarkerCallForm.BARE_OR_CALL, _DECLARED, _REQUIRED_NONE, ()),
    ("trusted", MarkerCallForm.BARE_OR_CALL, _DECLARED, _REQUIRED_NONE, ()),
    ("external_boundary()", MarkerCallForm.BARE_ONLY, frozenset(), frozenset(), (("<call>", "call_not_allowed"),)),
    ("external_boundary(**{})", MarkerCallForm.BARE_ONLY, frozenset(), frozenset(), (("<call>", "call_not_allowed"),)),
    ("trust_boundary", MarkerCallForm.CALL_ONLY, _TB_DECLARED, _TB_REQUIRED, (("<bare>", "call_required"),)),
    (
        "trusted('ASSURED')",
        MarkerCallForm.BARE_OR_CALL,
        _DECLARED,
        _REQUIRED_NONE,
        (("<positional>", "positional_args"),),
    ),
    (
        "trusted(level='ASSURED', audit=True)",
        MarkerCallForm.BARE_OR_CALL,
        _DECLARED,
        _REQUIRED_NONE,
        (("audit", "undeclared_kwarg"),),
    ),
    ("trusted(**KW)", MarkerCallForm.BARE_OR_CALL, _DECLARED, _REQUIRED_NONE, (("<**splat>", "unreadable_splat"),)),
    (
        "trusted(**{1: 'ASSURED'})",
        MarkerCallForm.BARE_OR_CALL,
        _DECLARED,
        _REQUIRED_NONE,
        (("<**splat>", "invalid_splat_key"),),
    ),
    (
        "trusted(level='A', **{'level': 'B'})",
        MarkerCallForm.BARE_OR_CALL,
        _DECLARED,
        _REQUIRED_NONE,
        (("level", "duplicate_kwarg"),),
    ),
    # Within one literal dict, Python constructs the dict last-value-wins.
    ("trusted(**{'level': 'A', 'level': 'B'})", MarkerCallForm.BARE_OR_CALL, _DECLARED, _REQUIRED_NONE, ()),
    ("trust_boundary()", MarkerCallForm.CALL_ONLY, _TB_DECLARED, _TB_REQUIRED, (("to_level", "missing_kwarg"),)),
    ("trust_boundary(to_level='ASSURED')", MarkerCallForm.CALL_ONLY, _TB_DECLARED, _TB_REQUIRED, ()),
    (
        "trusted(audit_fn)",
        MarkerCallForm.BARE_OR_CALL,
        _DECLARED,
        _REQUIRED_NONE,
        (("<positional>", "positional_args"),),
    ),
    ("trusted(*ARGS)", MarkerCallForm.BARE_OR_CALL, _DECLARED, _REQUIRED_NONE, (("<*args>", "positional_args"),)),
    (
        "trusted(x, *ARGS)",
        MarkerCallForm.BARE_OR_CALL,
        _DECLARED,
        _REQUIRED_NONE,
        (("<positional>", "positional_args"), ("<*args>", "positional_args")),
    ),
    (
        "trusted(**{'lev' + 'el': 'ASSURED'})",
        MarkerCallForm.BARE_OR_CALL,
        _DECLARED,
        _REQUIRED_NONE,
        (("<**splat>", "unreadable_splat"),),
    ),
    # A computed key may BE the required name — missing_kwarg must stay suppressed.
    (
        "trust_boundary(**{'to_' + 'level': 'ASSURED'})",
        MarkerCallForm.CALL_ONLY,
        _TB_DECLARED,
        _TB_REQUIRED,
        (("<**splat>", "unreadable_splat"),),
    ),
    # A VALUE is never a shape offence, whichever way it later reads: this validator
    # looks at no value at all. Under rev 6 ``CFG`` RESOLVES when P3 form 5 is
    # satisfied in full, while ``get_level()`` stays unreadable and takes the
    # residual FACT — and BOTH return the empty offence tuple here.
    ("trusted(level=CFG)", MarkerCallForm.BARE_OR_CALL, _DECLARED, _REQUIRED_NONE, ()),
    ("trusted(level=get_level())", MarkerCallForm.BARE_OR_CALL, _DECLARED, _REQUIRED_NONE, ()),
]


@pytest.mark.parametrize(("src", "call_form", "declared", "required", "expected"), SHAPE_CASES)
def test_call_shape_offences_table(src: str, call_form, declared, required, expected) -> None:
    deco = ast.parse(f"@{src}\ndef f(): ...").body[0].decorator_list[0]
    assert call_shape_offences(deco, call_form=call_form, declared=declared, required=required) == expected


def test_multi_phase_call_pins_the_canonical_phase_order() -> None:
    # The COMPLETE offence tuple for one call carrying a positional argument, an
    # unreadable splat AND an undeclared direct keyword. Read the expected order off
    # ``call_shape_offences``' documented PHASE LIST, never off the source order of the
    # call: extraction offences are emitted by ``out.extend(extracted.offences)`` BEFORE
    # the keyword-classification loop, so the splat lands at index 1 and the undeclared
    # keyword at index 2 even though ``audit=True`` is written first. ``SHAPE_CASES``
    # varies one phase at a time and carries no multi-phase row, which is why this pin
    # is separate: it makes the canonical phase order a compatibility contract rather
    # than an incidental loop order.
    deco = ast.parse("@trusted('ASSURED', audit=True, **KW)\ndef f(): ...").body[0].decorator_list[0]
    assert call_shape_offences(
        deco,
        call_form=MarkerCallForm.BARE_OR_CALL,
        declared=frozenset({"level"}),
        required=frozenset(),
    ) == (
        ("<positional>", "positional_args"),
        ("<**splat>", "unreadable_splat"),
        ("audit", "undeclared_kwarg"),
    )


def test_rule_and_provider_agree_on_reexported_taintstate(tmp_path: Path) -> None:
    # A typo'd level behind a re-export: the provider cannot read it (no seed) and
    # PY-WL-114 must not claim to have read it either — consistent silence, pinned.
    src = (
        "from myapp.shim import TaintState\n"
        "from wardline.decorators import trusted\n"
        "@trusted(level=TaintState.ASURED)\n"
        "def f(p):\n"
        "    return p\n"
    )
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "svc.py").write_text(src, encoding="utf-8")
    result = run_scan(proj)
    assert not [f for f in result.findings if f.rule_id == "PY-WL-114"]
    assert result.context is not None
    assert "svc.f" not in result.context.declared_qualnames  # provider dropped the seed too


def test_rule_and_provider_agree_on_aliased_taintstate_typo(tmp_path: Path) -> None:
    # The FN direction closed: an aliased GENUINE TaintState with a typo is read
    # by the provider (seed drops) — the rule now reads it identically and fires.
    src = (
        "from wardline.core.taints import TaintState as T\n"
        "from wardline.decorators import trusted\n"
        "@trusted(level=T.ASURED)\n"
        "def f(p):\n"
        "    return p\n"
    )
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "svc.py").write_text(src, encoding="utf-8")
    result = run_scan(proj)
    assert [f for f in result.findings if f.rule_id == "PY-WL-114"]
    assert result.context is not None
    assert "svc.f" not in result.context.declared_qualnames


def test_no_rule_imports_provider_privates() -> None:
    # P9's structural half: rules read markers ONLY through marker_reader.
    import pathlib

    rules_dir = pathlib.Path("src/wardline/scanner/rules")
    offenders = [
        p.name for p in rules_dir.glob("*.py") if "taint.decorator_provider import" in p.read_text(encoding="utf-8")
    ]
    assert offenders == []


def test_builtin_marker_roots_covers_every_builtin_boundary_type_root() -> None:
    # The REPLACEMENT GUARD for the derivation ``marker_reader`` cannot perform itself.
    # ``BUILTIN_MARKER_ROOTS`` used to be derived from ``BUILTIN_BOUNDARY_TYPES`` so that
    # adding a builtin marker root automatically participated in shadow fail-closed
    # matching. The engine floor imports only ``core`` (``scanner.boundary_types`` pulls in
    # ``scanner.taint.provider``, this module's own consumer), so the constant is now
    # LISTED there and the equality is pinned HERE — a test may import ``boundary_types``
    # where the reader may not.
    #
    # This is a SECURITY pin, not a tidiness one, and nothing else enforces it: the
    # REGISTRY consistency tripwire in ``boundary_types`` constrains ``canonical_name``,
    # ``group``, ``kwargs`` and ``arg_kinds`` only — ``module_prefix`` is entirely
    # unconstrained by it. So a third builtin root added to ``BUILTIN_BOUNDARY_TYPES``
    # would pass that tripwire, be ABSENT from ``BUILTIN_MARKER_ROOTS``,
    # ``shadowed_builtin_roots`` would never report it, shadow fail-closed would silently
    # stop applying to that root, and a project shadowing it could spoof ``@trusted`` while
    # the gate stayed green — the exact false-green class this program exists to close.
    from wardline.scanner.boundary_types import BUILTIN_BOUNDARY_TYPES

    # Operand order is the linter's (ruff SIM300 reads a leading module constant as a Yoda
    # condition); equality is symmetric, so the pinned property is unchanged.
    grammar_roots = {bt.module_prefix.split(".")[0] for bt in BUILTIN_BOUNDARY_TYPES if bt.builtin}
    assert grammar_roots == BUILTIN_MARKER_ROOTS


def test_shadowed_builtin_roots_reports_every_builtin_root() -> None:
    # The same guard read through the FUNCTION the constant exists to serve, so the pin
    # covers the behaviour and not merely the literal. Every builtin root must be
    # shadow-detectable; a root missing from the constant is silently un-shadowable here.
    from wardline.scanner.boundary_types import BUILTIN_BOUNDARY_TYPES

    roots = {bt.module_prefix.split(".")[0] for bt in BUILTIN_BOUNDARY_TYPES if bt.builtin}
    for root in roots:
        assert shadowed_builtin_roots(frozenset({"app", root})) == {root}, (
            f"builtin marker root {root!r} is not shadow-detectable"
        )


def test_alias_map_for_qualname_uses_longest_owner() -> None:
    maps = {"pkg": {"x": "pkg.x"}, "pkg.mod": {"x": "pkg.mod.x"}}
    assert alias_map_for_qualname("pkg.mod.C.method", maps) == maps["pkg.mod"]


def test_alias_map_for_qualname_without_owner_is_empty() -> None:
    assert alias_map_for_qualname("other.f", {"pkg": {"x": "pkg.x"}}) == {}


def test_read_level_accepts_sibling_declared_keywords() -> None:
    # Deliberate widening vs the old provider-private reader (None on ANY
    # keyword other than the one being read): a DECLARED sibling keyword is
    # legal while reading one arg. Observable only for multi-level-arg
    # custom markers; none ship in the builtin grammar. BOTH values here are
    # ``str`` literals, so form 5 never engages — this exercises the sibling
    # rule and NOT the custom form-5 path.
    deco = ast.parse("@m(a='ASSURED', b='ASSURED')\ndef f(): ...").body[0].decorator_list[0]
    read = read_level(
        deco,
        "a",
        declared=frozenset({"a", "b"}),
        allowed=frozenset(TaintState),
        default=None,
        alias_map={},
        census=_EMPTY_CENSUS,
        reference_site=None,
        shadowed_roots=frozenset(),
        builtin=False,
    )
    assert read.verdict is LevelVerdict.RESOLVED
    assert read.level is TaintState.ASSURED
    assert read.unreadable_value is None


def _read(src: str, *, builtin: bool = True):
    deco = ast.parse(f"@{src}\ndef f(): ...").body[0].decorator_list[0]
    return read_level(
        deco,
        "level",
        declared=frozenset({"level"}),
        allowed=frozenset({TaintState.INTEGRAL, TaintState.ASSURED}),
        default=TaintState.INTEGRAL,
        alias_map={},
        census=_EMPTY_CENSUS,
        reference_site=None,
        shadowed_roots=frozenset(),
        builtin=builtin,
    )


def test_read_level_discriminates_rejected_from_unreadable() -> None:
    # spec rev 6 §4.2.1: READS-then-rejects and UNREADABLE must NOT collapse into one
    # bare None. A token READ and then rejected by the allowed check is PY-WL-114's
    # DEFECT and carries NO residual pair, so it never reaches the FACT; a value never
    # read carries the (argument name, ast.unparse(value)) pair the FACT is built from.
    rejected = _read("trusted(level='ASURED')")
    assert rejected.verdict is LevelVerdict.REJECTED
    assert rejected.unreadable_value is None

    unreadable = _read("trusted(level=get_level())")
    assert unreadable.verdict is LevelVerdict.UNREADABLE
    assert unreadable.unreadable_value == ("level", "get_level()")


def test_read_level_never_carries_a_residual_pair_for_a_custom_marker() -> None:
    # The residual channel is BUILTIN-ONLY. A custom BoundaryType's unreadable level
    # keeps WLN-ENGINE-UNPROVABLE-BOUNDARY and an UNKNOWN_RAW seed, and never also the
    # residual FACT — one unreadable value takes exactly one channel. Note also that on
    # the custom side REJECTED and UNREADABLE both take that released path: only the
    # builtin arm distinguishes them.
    custom = _read("sanitized(level=get_level())", builtin=False)
    assert custom.verdict is LevelVerdict.UNREADABLE
    assert custom.unreadable_value is None


@pytest.mark.parametrize("src", ["sanitized('ASSURED')", "sanitized(*ARGS)"])
def test_read_level_refuses_a_positional_argument_on_a_custom_marker(src: str) -> None:
    # The CUSTOM side's only positional guard, and the reason ``read_level`` keeps the
    # released ``deco.args`` check (decorator_provider.py:165-166) rather than delegating
    # to the shape gate. ``call_shape_offences`` is builtin-only by design (spec :105;
    # custom-pack compatibility is a hard gate), so nothing else in the pipeline ever
    # inspects ``deco.args`` for a custom ``BoundaryType``.
    #
    # ``_read`` supplies a NON-None ``default`` (TaintState.INTEGRAL), and that is what
    # makes these two rows discriminate: without the guard both fall through to
    # ``_defaulted()`` and return RESOLVED/INTEGRAL — a trusted seed, minted from a
    # declaration Wardline never read, with no diagnostic on any channel. Every custom
    # ``LevelArg`` in this tree happens to pass ``default=None`` (measured 2026-08-10),
    # and the one file Global Constraints names as a HARD GATE,
    # tests/grammar/test_thirdparty_pack_bridge.py, binds a pack whose BoundaryType
    # declares ``level_args=()`` and therefore never calls this reader at all — so the
    # restored guard moves no in-tree verdict and reds no gate. No shipped test reds if
    # the guard is DROPPED either; wardline's OWN builtins use the
    # defaulted shape (boundary_types.py:108, :125), which is the idiom a pack author
    # copies. Zero reds is the mechanism by which that regression would ship, not
    # evidence that it is hypothetical.
    read = _read(src, builtin=False)
    assert read.verdict is LevelVerdict.UNREADABLE
    assert read.level is None
    assert read.unreadable_value is None
