"""The builtin seed-drop coverage matrix (P10 / wardline-4928b75782,
wardline-2b2a6cddfa).

Every shape that makes a builtin marker's seed drop is enumerated with the ONE
diagnostic channel that owns it. There are exactly FOUR channels: PY-WL-130
(call SHAPE), PY-WL-114 (a value that READ but is not a legal token),
WLN-ENGINE-UNREADABLE-MARKER-VALUE (a Severity.NONE FACT — every builtin LEVEL
value that stays unreadable after P3 form 5), and the ONE remaining deliberate
silence, a shadowed builtin vocabulary root, which disables the marker candidate
so no builtin LEVEL slot exists at all. A statically-unreadable builtin LEVEL
value is NEVER silent.

THE SCOPE OF THAT CLAIM, WHICH IS NARROWER THAN IT READS. The partition covers
shapes in which the engine RECOGNISES A BUILTIN MARKER AT ALL — that is, the
decorator's resolved FQN lands under a builtin vocabulary root
(`wardline.decorators` / `weft_markers`). A decorator whose resolved root is a
PROJECT module never enters the partition, and "anything else going silent is a
regression" does not reach it.

That is not hypothetical. MEASURED 2026-08-12, an ordinary cross-module
re-export of a builtin marker is silent on ALL FOUR channels:

    pkg/al.py  : from wardline.decorators import trusted as T
    pkg/svc.py : from pkg.al import T
                 @T(level='ASSURED')   -> no finding; NOT declared; UNKNOWN_RAW

Silent for a well-formed marker, a shape-malformed one, a readable-but-invalid
level and an unreadable level alike, where the same four spellings imported
DIRECTLY produce the seed / PY-WL-130 / PY-WL-114 / the FACT respectively. The
cause is the guard-answers-from-a-datum shape: `unknown_vocabulary_marker`
decides "is this ours?" from the resolved FQN's root, so `pkg.al.T` reads as NOT
APPLICABLE rather than UNKNOWN and no channel claims it. A GHOST export *under* a
builtin root does correctly take WLN-ENGINE-UNKNOWN-MARKER; this shape escapes
precisely because its root is a project module.

This is a live false green in the engine (the direct import declares the function
and subjects it to the tier-gated leak rules; the re-export leaves it in
RAW_ZONE where those rules go quiet). It is tracked as wardline-69a58cb05f and
is NOT this module's to fix. Deliberately NO TEST BELOW PINS IT: a test asserting that
silence would convert a defect into a shipped contract, and the next person to
fix it would have to argue with this file. It is recorded here as an uncovered
axis, in prose, on purpose.

ORDERING IS NORMATIVE AND THIS MATRIX PINS IT. Task 5 runs call_shape_offences
BEFORE the levels loop, so a marker whose call shape is malformed drops its seed
without any level being read. A marker that is BOTH shape-malformed and
value-unreadable therefore takes PY-WL-130 and NOT the FACT; the
`malformed_shape_and_unreadable_value` row is what pins that, and the
`fired == {channel}` exclusivity assertion below is what carries its negative
half. Do not weaken that assertion to a presence-only check. Note the honest
reading: PY-WL-130 is a Kind.DEFECT and therefore suppressible, while the FACT
is unsuppressible but never gates — neither channel dominates, so the ordering
rests on noise avoidance and on the shipped secure default (at
trust_suppressions=False the gate population is rebuilt with an empty baseline
and waiver set, so a waived PY-WL-130 still trips --fail-on), not on dominance.

Task 5 deliberately does NOT demote a malformed builtin's seed to UNKNOWN_RAW:
that would move the function into RAW_ZONE, where modulate() returns
Severity.NONE and PY-WL-101 skips the declared tier — silencing the tier-gated
rules that currently fire on it.

ASSERTIONS RUN OVER ALL KINDS. Filtering to Kind.DEFECT would make the
Severity.NONE FACT invisible before any assertion saw it — a false green inside
the guard whose entire purpose is proving there are none.

WHAT EVERY ROW OF `MATRIX` SHARES, and what is done about it. Every row places
ONE marker, spelled `from wardline.decorators import ...`, on a module-top-level
`def`, in a module that shadows nothing and star-imports nothing. Four of those
five constants are varied deliberately below rather than left as unexamined
assumptions:
  * marker ROOT and import SPELLING and decoration SITE — the cross-product in
    `test_channel_is_invariant_across_root_and_site`, which is the axis on which
    a builtin-channel regression scoped to one root or one site would leave every
    `MATRIX` row green (`weft_markers` is the second builtin root and NO `MATRIX`
    row touches it);
  * ONE marker per function — the compositions in
    `test_two_markers_take_two_channels_on_one_function` and its neighbours,
    which pin channel exclusivity as PER-MARKER, not per-function; a naive
    reading of `fired == {channel}` gets that exactly backwards.
The residue is recorded honestly and NOT closed: `fired` is a repo-wide SET, so
`MATRIX` pins channel IDENTITY and not finding CARDINALITY nor the anchored
qualname (every `MATRIX` fixture has exactly one decorated function, so no row
could tell the difference). The added rows below assert qualname, where a
fixture really does carry more than one function.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from wardline.core.run import run_scan

# `Kind` is deliberately NOT imported: the assertions below run over ALL kinds,
# because a Kind.DEFECT filter would hide the Severity.NONE residual FACT.
_MARKER_CHANNELS = frozenset({"PY-WL-130", "PY-WL-114", "WLN-ENGINE-UNREADABLE-MARKER-VALUE"})

_IMPORTS = "from wardline.decorators import external_boundary, trust_boundary, trusted\n"
# CFG now RESOLVES under P3 form 5: one unconditional direct-top-level `str`
# binding, no other module-scope occurrence, lexically preceding a `def` that is a
# direct element of the module body, in a BUILTIN LEVEL slot. DYN does NOT: a call
# right-hand side is an explicitly refused shape (spec §4.2.1), so DYN is the
# binding that exercises the residual FACT. Neither name is rebound anywhere, and
# the module carries no star import — both preconditions the census checks.
_RUNTIME_VALUES = (
    "KW = {'level': 'ASSURED'}\nCFG = 'ASSURED'\nARGS = ()\n"
    "def get_level():\n    return 'ASSURED'\n"
    "DYN = get_level()\n"
    "def audit_fn(x):\n    return x\n"
)

# (case id, decorator line, expected channel, seed must drop)
MATRIX = [
    ("positional", "@trusted('ASSURED')", "PY-WL-130", True),
    ("undeclared_kwarg", "@trusted(level='ASSURED', audit=True)", "PY-WL-130", True),
    ("legacy_to_level", "@trusted(level='ASSURED', to_level='ASSURED')", "PY-WL-130", True),
    ("external_called_empty", "@external_boundary()", "PY-WL-130", True),
    ("external_called_empty_splat", "@external_boundary(**{})", "PY-WL-130", True),
    ("external_boundary_kwarg", "@external_boundary(source='http')", "PY-WL-130", True),
    ("dynamic_splat", "@trusted(**KW)", "PY-WL-130", True),
    ("invalid_literal_splat_key", "@trusted(**{1: 'ASSURED'})", "PY-WL-130", True),
    # Runtime-INVALID, like its neighbour above — which is why it sits ABOVE the
    # comment that follows rather than inside it. Verified at the interpreter:
    # `trusted(level='ASSURED', **{'level': 'ASSURED'})` raises TypeError (got
    # multiple values for keyword argument 'level'), and Task 6's clause table
    # correctly requires the runtime-invalid clause for its `duplicate_kwarg`
    # row. This matrix asserts CHANNELS only, so no diagnostic was ever
    # mis-built; what was wrong was the comment shipped over the row.
    ("duplicate_via_splat", "@trusted(level='ASSURED', **{'level': 'ASSURED'})", "PY-WL-130", True),
    # These four are RUNTIME-VALID calls that Wardline nonetheless refuses to
    # honour as declarations: they fire PY-WL-130 WITHOUT the runtime-invalid
    # clause (Task 6's truthfulness split — the diagnostic says the shape is
    # outside the statically readable declaration grammar, never that Python
    # raises TypeError). They are exactly Task 6's four `claims_runtime_invalid=
    # False` cases; the count in this comment is load-bearing, so keep the two
    # lists in step.
    ("positional_callable", "@trusted(audit_fn)", "PY-WL-130", True),
    ("star_args", "@trusted(*ARGS)", "PY-WL-130", True),
    ("computed_splat_key", "@trusted(**{'lev' + 'el': 'ASSURED'})", "PY-WL-130", True),
    ("external_called_with_callable", "@external_boundary(audit_fn)", "PY-WL-130", True),
    ("literal_splat_level_typo", "@trusted(**{'level': 'ASURED'})", "PY-WL-114", True),
    ("bare_required", "@trust_boundary", "PY-WL-130", True),
    ("zero_arg_required", "@trust_boundary()", "PY-WL-130", True),
    ("typo_level", "@trusted(level='ASURED')", "PY-WL-114", True),
    ("out_of_range_level", "@trust_boundary(to_level='INTEGRAL')", "PY-WL-114", True),
    # INVERTED at spec rev 6: CFG satisfies P3 form 5 in full, so this resolves and
    # the seed STANDS. The pre-rev-6 row pinned the silence as a passing contract.
    ("form5_module_constant_resolves", "@trusted(level=CFG)", "none", False),
    # What stays unreadable is OBSERVABLE, never silent — one row per builtin LEVEL
    # keyword, so `to_level=` on @trust_boundary is not left behind.
    ("unreadable_value_call_rhs", "@trusted(level=DYN)", "WLN-ENGINE-UNREADABLE-MARKER-VALUE", True),
    ("unreadable_to_level_call_rhs", "@trust_boundary(to_level=DYN)", "WLN-ENGINE-UNREADABLE-MARKER-VALUE", True),
    # THE SHORT-CIRCUIT ROW. Shape-malformed AND value-unreadable on one marker:
    # call_shape_offences runs BEFORE the levels loop, so no level is read and the
    # FACT is never emitted. The exclusivity assertion below carries the negative
    # half — this is the one row in the matrix that pins a channel's ABSENCE.
    ("malformed_shape_and_unreadable_value", "@trusted(level=DYN, audit=True)", "PY-WL-130", True),
    # THE SHORT-CIRCUIT ROW THAT ACTUALLY DISCRIMINATES THE SHORT CIRCUIT, added after
    # measuring that the row above does not. Mutating the provider's shape-gate
    # `return None, None, ()` away leaves `malformed_shape_and_unreadable_value`
    # GREEN: its offence is `undeclared_kwarg`, and `read_level` has its OWN
    # undeclared-metadata guard (marker_reader.py:394-395) returning
    # `_unreadable(None)` — payload None, so no FACT could co-fire whether or not the
    # provider short-circuited. It passes for the right ANSWER by the wrong MECHANISM.
    # A `duplicate_kwarg` offence is the shape that reaches a payload-bearing
    # unreadable: `level` is declared and supplied twice, so `read_level` takes
    # `len(values) != 1 -> _unreadable(values[0])` WITH a payload. Delete the
    # short-circuit and this row fires PY-WL-130 *and* the FACT, and the exclusivity
    # assertion reds. Verified by mutation: see the task-14 report.
    ("duplicate_kwarg_and_unreadable_value", "@trusted(level=DYN, **{'level': DYN})", "PY-WL-130", True),
    ("well_formed", "@trusted(level='ASSURED')", "none", False),
    ("bare_defaulted", "@trusted", "none", False),
]

# The three `none` rows and the level each must resolve TO. Asserting only "no channel
# fired and the function is declared" leaves a false green wide open: `trusted`'s
# LevelArg carries `default=TaintState.INTEGRAL`, so a regression in which an UNREAD
# value silently takes the default still declares the function and still fires nothing.
# Measured: with form 5 disabled AND `read_level`'s `token is None` arm changed from
# `_unreadable(values[0])` to `_defaulted()`, `form5_module_constant_resolves` stays
# GREEN while the engine has seeded an unread name at INTEGRAL. These assertions are
# what kill that mutant.
_RESOLVED_LEVELS = [
    ("form5_module_constant_resolves", "@trusted(level=CFG)", "ASSURED"),
    ("well_formed", "@trusted(level='ASSURED')", "ASSURED"),
    ("bare_defaulted", "@trusted", "INTEGRAL"),
]


@pytest.mark.parametrize(("case", "deco", "channel", "drops"), MATRIX, ids=[m[0] for m in MATRIX])
def test_drop_coverage(tmp_path: Path, case: str, deco: str, channel: str, drops: bool) -> None:
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "svc.py").write_text(
        f"{_IMPORTS}{_RUNTIME_VALUES}{deco}\ndef f(p):\n    return p\n",
        encoding="utf-8",
    )
    result = run_scan(proj)
    assert result.context is not None
    assert ("svc.f" not in result.context.declared_qualnames) is drops, case
    # Over ALL kinds. The residual channel is a Severity.NONE FACT, so a
    # Kind.DEFECT filter here would make it invisible before any assertion saw it.
    fired = {f.rule_id for f in result.findings} & _MARKER_CHANNELS
    if channel == "none":
        # The pure-absence branch survives ONLY for rows whose channel is literally
        # "none", and only because those rows do not drop the seed.
        assert not drops, f"{case}: a dropped seed must always name a channel"
        assert not fired, f"{case}: expected no marker channel, fired {sorted(fired)}"
    else:
        # Presence AND exclusivity over the full marker channel set, in one
        # assertion. Do NOT weaken this to a presence-only check: exclusivity is the
        # never-two-channels property, and it is also the FACT-absent half of the
        # `malformed_shape_and_unreadable_value` row that pins the shape-gate
        # short-circuit.
        assert fired == {channel}, f"{case}: expected exactly {channel}, fired {sorted(fired)}"


@pytest.mark.parametrize(("case", "deco", "channel", "drops"), MATRIX, ids=[m[0] for m in MATRIX])
def test_each_row_fires_exactly_one_finding_on_exactly_one_function(
    tmp_path: Path, case: str, deco: str, channel: str, drops: bool
) -> None:
    # CARDINALITY, which `test_drop_coverage` structurally cannot pin: `fired` there is
    # a repo-wide SET of rule ids, so it collapses one finding and five, and it names no
    # qualname. PY-WL-130 is `multi_emit` and `call_shape_offences` returns a TUPLE, so
    # a regression that emitted one finding per offence phase — or that fingerprinted
    # two offences identically and emitted both — passes every row of that test.
    #
    # This is live rather than theoretical: decorator_coverage's `unknown_markers` /
    # `unreadable_marker_values` summary keys are counted PER VALUE (Task 9), so a
    # doubled emission here doubles a shipped consumer's numbers.
    #
    # Measured 2026-08-11: every row of MATRIX fires EXACTLY ONE marker-channel finding
    # (or zero, on the three `none` rows), each anchored on `svc.f`. The fixture also
    # carries `get_level` and `audit_fn`, so the qualname assertion is not free — a
    # channel firing on the wrong entity would red here and nowhere else.
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "svc.py").write_text(
        f"{_IMPORTS}{_RUNTIME_VALUES}{deco}\ndef f(p):\n    return p\n",
        encoding="utf-8",
    )
    result = run_scan(proj)
    hits = [f for f in result.findings if f.rule_id in _MARKER_CHANNELS]
    assert len(hits) == (0 if channel == "none" else 1), (
        f"{case}: expected exactly {0 if channel == 'none' else 1} finding, got "
        f"{[(f.rule_id, f.qualname) for f in hits]}"
    )
    assert all(f.qualname == "svc.f" for f in hits), case
    # Distinct fingerprints too: two findings that collide on a fingerprint deduplicate
    # downstream, which would restore the very under-count this test exists to catch.
    assert len({f.fingerprint for f in hits}) == len(hits), case


def test_the_partitions_allowed_level_sets_are_not_allowed_to_diverge() -> None:
    """The unenforced duplication the four-way partition's completeness rests on.

    The allowed-level sets exist TWICE: ``boundary_types.py`` (:31-32) drives the
    PROVIDER's seed decision, and ``invalid_decorator_level.py`` (:40-41) drives
    PY-WL-114's ``is_invalid`` decision. Nothing checks that they agree — the
    load-time tripwire in ``boundary_types`` covers group / kwargs / arg_kinds
    against REGISTRY, and not these.

    MEASURED, and this is why the assertion is here rather than in a note: narrowing
    only the ``boundary_types`` copy (dropping ASSURED from ``_TRUSTED_LEVELS``) makes
    ``@trusted(level='ASSURED')`` DROP ITS SEED WHILE FIRING NOTHING AT ALL. The
    provider rejects the level, so `read_level` returns REJECTED — which carries no
    residual payload, by design, because PY-WL-114 is supposed to own that case — and
    PY-WL-114 reads its own unnarrowed copy and stays silent. The result is a fifth
    outcome the partition says cannot exist: a silent builtin seed drop.

    That is NOT a shipped defect; the two copies agree today and `test_drop_coverage`
    is green. It is the precondition the partition quietly depends on, so it is pinned
    where the partition is claimed.
    """
    from wardline.scanner.boundary_types import _BOUNDARY_LEVELS, _TRUSTED_LEVELS
    from wardline.scanner.rules.invalid_decorator_level import (
        _BOUNDARY_LEVELS as _RULE_BOUNDARY_LEVELS,
    )
    from wardline.scanner.rules.invalid_decorator_level import (
        _TRUSTED_LEVELS as _RULE_TRUSTED_LEVELS,
    )

    assert _TRUSTED_LEVELS == _RULE_TRUSTED_LEVELS, (
        "the provider's and PY-WL-114's `trusted` level sets have diverged: a level "
        "in one but not the other drops the seed with NO channel firing"
    )
    assert _BOUNDARY_LEVELS == _RULE_BOUNDARY_LEVELS, (
        "the provider's and PY-WL-114's `trust_boundary` level sets have diverged: a "
        "level in one but not the other drops the seed with NO channel firing"
    )


@pytest.mark.parametrize(("case", "deco", "level"), _RESOLVED_LEVELS, ids=[r[0] for r in _RESOLVED_LEVELS])
def test_resolving_rows_pin_the_level_they_resolved_to(tmp_path: Path, case: str, deco: str, level: str) -> None:
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "svc.py").write_text(
        f"{_IMPORTS}{_RUNTIME_VALUES}{deco}\ndef f(p):\n    return p\n",
        encoding="utf-8",
    )
    result = run_scan(proj)
    assert result.context is not None
    assert result.context.project_taints["svc.f"].value == level, case


def test_shadowed_root_is_the_only_deliberate_silence(tmp_path: Path) -> None:
    # The shadow disables the marker candidate wholesale, so no builtin LEVEL slot
    # exists to be read — this is the one silence left after spec rev 6.
    #
    # (Assertions below are unchanged and remain sound.)
    proj = tmp_path / "proj"
    (proj / "wardline" / "decorators").mkdir(parents=True)
    (proj / "wardline" / "__init__.py").write_text("", encoding="utf-8")
    (proj / "wardline" / "decorators" / "__init__.py").write_text("", encoding="utf-8")
    (proj / "svc.py").write_text(
        f"{_IMPORTS}@trusted(level='ASSURED', audit=True)\ndef f(p):\n    return p\n", encoding="utf-8"
    )
    result = run_scan(proj)
    assert not [f for f in result.findings if f.rule_id in ("PY-WL-130", "PY-WL-114")]
    assert result.context is not None
    assert "svc.f" not in result.context.declared_qualnames


# Every channel the four-way partition names, plus the two neighbouring engine FACTs
# the partition claims never co-fire with it. The silence rows below assert over ALL
# of these: a "deliberate silence" that merely rerouted onto a neighbour channel is
# not a silence.
_ALL_CHANNELS = _MARKER_CHANNELS | {"WLN-ENGINE-UNKNOWN-MARKER", "WLN-ENGINE-UNPROVABLE-BOUNDARY"}

_SHADOW_TREE = {
    "wardline/__init__.py": "",
    "wardline/decorators/__init__.py": "",
}


@pytest.mark.parametrize(
    "deco",
    [
        "@trusted(level='ASSURED', audit=True)",
        "@trusted(level=DYN)",
        "@trusted(level='ASURED')",
        "@trusted(level='ASSURED')",
    ],
    ids=["shape_malformed", "unreadable_value", "readable_invalid", "well_formed"],
)
def test_shadowed_root_silence_is_the_shadow_and_not_another_gate(tmp_path: Path, deco: str) -> None:
    # WHY THIS EXISTS, and why the pinned test above does not replace it. That test
    # uses `@trusted(level='ASSURED', audit=True)` — a SHAPE-MALFORMED marker, which
    # `call_shape_offences` silences on the residual channel with or without any
    # shadow. Measured: deleting the provider's shadow rejection
    # (`if root in shadowed_roots or not _is_builtin_decorator_fqn(...)`) leaves it
    # GREEN, so as a canary for the shadow it cannot die.
    #
    # `unreadable_value` is the cell that makes the shadow load-bearing: unshadowed it
    # is the MATRIX's `unreadable_value_call_rhs` row and fires the FACT, so its
    # silence here is attributable to the shadow and to nothing else. `readable_invalid`
    # does the same job for PY-WL-114 and `well_formed` for the seed itself — under
    # shadow a well-formed marker must NOT declare the function, which is the whole
    # point of rejecting a shadowed vocabulary root (a project-local `wardline/`
    # package could otherwise spoof @trusted and suppress real taint->sink flows).
    #
    # ABSENCE IS ASSERTED OVER THE WHOLE FINDING SET, not over a hand-picked id list.
    # An earlier revision of this comment claimed "every channel" while intersecting
    # with `_ALL_CHANNELS` — five ids chosen by hand — so a reroute onto any OTHER
    # `WLN-ENGINE-*` id would have read as a pass. Measured 2026-08-12: these fixtures
    # emit `WLN-ENGINE-METRICS` and nothing else, on all four shapes, so subtracting
    # that one id is stable and strictly stronger than the intersection was.
    proj = tmp_path / "proj"
    proj.mkdir()
    for rel, text in _SHADOW_TREE.items():
        path = proj / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    (proj / "svc.py").write_text(f"{_IMPORTS}{_RUNTIME_VALUES}{deco}\ndef f(p):\n    return p\n", encoding="utf-8")
    result = run_scan(proj)
    fired = {f.rule_id for f in result.findings} - {"WLN-ENGINE-METRICS"}
    assert not fired, f"{deco}: shadowed root must be silent, fired {sorted(fired)}"
    assert result.context is not None
    # The seed is gone too — silence WITHOUT a dropped seed would be the false green.
    assert "svc.f" not in result.context.declared_qualnames


# --- The cross-product: marker ROOT x import SPELLING x decoration SITE -------------
#
# THE AXIS NO `MATRIX` ROW VARIES. Every `MATRIX` row spells its marker
# `from wardline.decorators import ...` and puts it on a module-top-level `def`. Two
# builtin ROOTS ship (`wardline.decorators` and `weft_markers`,
# boundary_types.py:94-129) and the accepted-export table is ROOT-SPECIFIC, so a
# channel regression scoped to one root or one decoration site would leave all of
# `MATRIX` green. This is the cross-product the vacuity catalogue asks for rather than
# a flat list: 6 spellings x 4 sites x 5 shapes.

# (id, import line, decorator prefix). `wardline.decorators.trust` is the real
# implementation module the package re-exports from, and is an accepted export;
# `weft_markers` has NO `.trust` submodule, so that spelling is deliberately absent
# (it is a ghost export the engine must not honour, pinned elsewhere).
_SPELLINGS = [
    ("wd_direct", "from wardline.decorators import trusted\n", "trusted"),
    ("wd_dotted", "import wardline.decorators\n", "wardline.decorators.trusted"),
    ("wd_aliased", "from wardline.decorators import trusted as t\n", "t"),
    ("wd_trust_submodule", "from wardline.decorators.trust import trusted\n", "trusted"),
    ("weft_dotted", "import weft_markers\n", "weft_markers.trusted"),
    ("weft_direct", "from weft_markers import trusted\n", "trusted"),
]

# (id, body template, qualname of the decorated function)
_SITES = [
    ("module_def", "{deco}\ndef f(p):\n    return p\n", "svc.f"),
    ("async_def", "{deco}\nasync def f(p):\n    return p\n", "svc.f"),
    ("method", "class C:\n    {deco}\n    def m(self, p):\n        return p\n", "svc.C.m"),
    (
        "nested_def",
        "def outer():\n    {deco}\n    def f(p):\n        return p\n    return f\n",
        "svc.outer.<locals>.f",
    ),
]

# (id, argument text, channel, seed drops). `form5_constant` is the one shape whose
# channel is SITE-DEPENDENT and it is handled in `_expected_channel` below.
_SHAPES = [
    ("shape_malformed", "(level='ASSURED', audit=True)", "PY-WL-130", True),
    ("readable_invalid", "(level='ASURED')", "PY-WL-114", True),
    ("unreadable_value", "(level=DYN)", "WLN-ENGINE-UNREADABLE-MARKER-VALUE", True),
    ("well_formed", "(level='ASSURED')", "none", False),
    ("form5_constant", "(level=CFG)", "none", False),
]


def _expected_channel(shape: str, site: str, channel: str, drops: bool) -> tuple[str, bool]:
    """Form 5's site clause, applied — NOT an expectation fitted to observed output.

    P3 form 5 resolves only when the reference site is a ``def``/``async def`` that is
    a DIRECT element of ``Module.body`` (conjunct 4, marker_reader.level_token). A
    method or a nested ``def`` is not, so ``level=CFG`` there is an ordinary unreadable
    value and takes the residual FACT. That is a change of WHICH channel owns the cell,
    never a second channel and never a silence — which is exactly the property the
    partition claims, so the cross-product still asserts EXACTLY ONE channel per cell.
    """
    if shape == "form5_constant" and site not in ("module_def", "async_def"):
        return "WLN-ENGINE-UNREADABLE-MARKER-VALUE", True
    return channel, drops


@pytest.mark.parametrize(("shape", "args", "channel", "drops"), _SHAPES, ids=[s[0] for s in _SHAPES])
@pytest.mark.parametrize(("site", "template", "qualname"), _SITES, ids=[s[0] for s in _SITES])
@pytest.mark.parametrize(("spelling", "imp", "prefix"), _SPELLINGS, ids=[s[0] for s in _SPELLINGS])
def test_channel_is_invariant_across_root_and_site(
    tmp_path: Path,
    spelling: str,
    imp: str,
    prefix: str,
    site: str,
    template: str,
    qualname: str,
    shape: str,
    args: str,
    channel: str,
    drops: bool,
) -> None:
    channel, drops = _expected_channel(shape, site, channel, drops)
    cell = f"{spelling}/{site}/{shape}"
    proj = tmp_path / "proj"
    proj.mkdir()
    body = template.format(deco=f"@{prefix}{args}")
    (proj / "svc.py").write_text(f"{imp}{_RUNTIME_VALUES}{body}", encoding="utf-8")
    result = run_scan(proj)
    assert result.context is not None
    assert (qualname not in result.context.declared_qualnames) is drops, cell
    # ANCHORED, unlike `MATRIX`: these fixtures carry `get_level`/`audit_fn` beside the
    # decorated function, so pinning the qualname is what stops a channel firing on the
    # wrong entity from reading as a pass.
    fired = {(f.rule_id, f.qualname) for f in result.findings if f.rule_id in _ALL_CHANNELS}
    expected = set() if channel == "none" else {(channel, qualname)}
    assert fired == expected, f"{cell}: expected {sorted(expected)}, fired {sorted(fired)}"


# --- Compositions: two markers on one function --------------------------------------


def test_two_markers_take_two_channels_on_one_function(tmp_path: Path) -> None:
    # EXCLUSIVITY IS PER-MARKER, NOT PER-FUNCTION — the thing a naive reading of
    # `fired == {channel}` gets exactly backwards, and the reason that assertion is
    # safe only because every `MATRIX` fixture carries exactly one marker.
    #
    # @trusted(level='ASSURED', audit=True) is shape-malformed and takes PY-WL-130;
    # @trust_boundary(to_level=DYN) is value-unreadable and takes the FACT. Both fire,
    # on the same function, and that is CORRECT: the short-circuit the matrix pins is a
    # property of one marker's own shape gate, not a per-function precedence rule. If
    # this ever collapsed to one finding, the second marker's seed would have dropped
    # with nothing recording it.
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "svc.py").write_text(
        f"{_IMPORTS}{_RUNTIME_VALUES}"
        "@trusted(level='ASSURED', audit=True)\n@trust_boundary(to_level=DYN)\n"
        "def f(p):\n    return p\n",
        encoding="utf-8",
    )
    result = run_scan(proj)
    fired = {(f.rule_id, f.qualname) for f in result.findings if f.rule_id in _ALL_CHANNELS}
    assert fired == {("PY-WL-130", "svc.f"), ("WLN-ENGINE-UNREADABLE-MARKER-VALUE", "svc.f")}
    assert result.context is not None
    assert "svc.f" not in result.context.declared_qualnames


def test_readable_invalid_and_unreadable_compose_without_merging(tmp_path: Path) -> None:
    # The other two-channel composition, and the one that proves PY-WL-114 and the FACT
    # are not merely ordered but independent: a READ-then-rejected value on one marker
    # and an unread value on another. One site, one function, two channels, neither
    # suppressing the other.
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "svc.py").write_text(
        f"{_IMPORTS}{_RUNTIME_VALUES}"
        "@trusted(level='ASURED')\n@trust_boundary(to_level=DYN)\ndef f(p):\n    return p\n",
        encoding="utf-8",
    )
    result = run_scan(proj)
    fired = {(f.rule_id, f.qualname) for f in result.findings if f.rule_id in _ALL_CHANNELS}
    assert fired == {("PY-WL-114", "svc.f"), ("WLN-ENGINE-UNREADABLE-MARKER-VALUE", "svc.f")}


def test_shape_malformed_marker_does_not_demote_a_resolving_sibling(tmp_path: Path) -> None:
    # The composition that pins the "deliberately NOT demoted to UNKNOWN_RAW" clause the
    # module docstring states — the exact stack the provider comment names
    # (@trusted(level='ASSURED') over @external_boundary(source=...)).
    #
    # The malformed marker's seed drops and PY-WL-130 fires, while the provable sibling
    # STANDS: the function is declared at ASSURED, which is what keeps it subject to the
    # tier-gated leak rules. Demoting to UNKNOWN_RAW would move it into RAW_ZONE, where
    # modulate() returns Severity.NONE and the tier-gated rules go silent — a "safer"
    # seed that buys silence. No `MATRIX` row can see this: every one of them carries a
    # single marker, so `drops` and "the malformed marker contributed nothing" are the
    # same observation there and different observations here.
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "svc.py").write_text(
        f"{_IMPORTS}{_RUNTIME_VALUES}"
        "@trusted(level='ASSURED')\n@external_boundary(source='http')\ndef f(p):\n    return p\n",
        encoding="utf-8",
    )
    result = run_scan(proj)
    fired = {(f.rule_id, f.qualname) for f in result.findings if f.rule_id in _ALL_CHANNELS}
    assert fired == {("PY-WL-130", "svc.f")}
    assert result.context is not None
    assert "svc.f" in result.context.declared_qualnames
    assert result.context.project_taints["svc.f"].value == "ASSURED"
