"""WLN-ENGINE-UNREADABLE-MARKER-VALUE — the residual channel for a builtin
marker's statically unreadable LEVEL value (spec §4.2.1).

P3 form 5 resolves a same-file, module-level, one-hop value reference in a
BUILTIN marker's LEVEL slot on a module-top-level ``def``/``async def``.
Everything form 5 refuses stays unreadable — and becomes OBSERVABLE rather than
silent. Both halves ship; neither substitutes for the other.

Channel discipline pinned here:
  * unreadable builtin LEVEL value   -> this FACT (Severity.NONE, never gates)
  * readable-but-invalid token       -> PY-WL-114 DEFECT, and NO fact
  * malformed CALL SHAPE             -> PY-WL-130, and NO fact (the shape gate
                                        short-circuits before any level is read)
  * unreadable CUSTOM level value    -> WLN-ENGINE-UNPROVABLE-BOUNDARY, unchanged
                                        by revision 6, and NEVER also this FACT
One unreadable value takes exactly one channel, which is what keeps the
decorator_coverage count (Task 9) from double-counting a site.
"""

from __future__ import annotations

import unicodedata
from pathlib import Path

import pytest

from wardline.core.finding import Kind, Severity
from wardline.core.resolution_posture import compute_resolution_posture
from wardline.core.run import run_scan
from wardline.scanner.pipeline import _fp

FACT_ID = "WLN-ENGINE-UNREADABLE-MARKER-VALUE"
_IMPORT = "from wardline.decorators import trusted\n"


def _scan(tmp_path: Path, src: str):
    proj = tmp_path / "proj"
    proj.mkdir(parents=True)
    (proj / "svc.py").write_text(src, encoding="utf-8")
    return run_scan(proj)


def _facts(result):
    return [f for f in result.findings if f.rule_id == FACT_ID]


# Every shape form 5 refuses, from the §4.2.1 case table. Each row must produce
# exactly ONE fact, and — audit gap, pinned deliberately — that fact must carry a
# SOURCE LINE. tests/grammar/test_output_determinism.py filters to Kind.DEFECT
# today, so a ``line_start is None`` here would be invisible; this is the pin that
# makes widening that filter safe rather than a surprise.
_UNREADABLE = [
    pytest.param(
        _IMPORT + "def get_level():\n    return 'ASSURED'\n@trusted(level=get_level())\ndef f(p):\n    return p\n",
        "svc.f",
        "level",
        "get_level()",
        id="call",
    ),
    pytest.param(
        _IMPORT + "X = 'ASS'\n@trusted(level=f'{X}URED')\ndef f(p):\n    return p\n",
        "svc.f",
        "level",
        "f'{X}URED'",
        id="fstring",
    ),
    pytest.param(
        _IMPORT + "import os\n@trusted(level=os.environ['LVL'])\ndef f(p):\n    return p\n",
        "svc.f",
        "level",
        "os.environ['LVL']",
        id="subscript",
    ),
    pytest.param(
        _IMPORT + "A = 'ASSURED'\nB = A\n@trusted(level=B)\ndef f(p):\n    return p\n",
        "svc.f",
        "level",
        "B",
        id="two_hop",
    ),
    pytest.param(
        _IMPORT + "N = 3\n@trusted(level=N)\ndef f(p):\n    return p\n",
        "svc.f",
        "level",
        "N",
        id="non_str_constant",
    ),
    pytest.param(
        _IMPORT + "@trusted(level=LATE)\ndef f(p):\n    return p\nLATE = 'ASSURED'\n",
        "svc.f",
        "level",
        "LATE",
        id="binding_after_the_def",
    ),
    pytest.param(
        _IMPORT + "import sys\nX = 'INTEGRAL'\nif sys.platform == 'win32':\n    X = 'ASSURED'\n"
        "@trusted(level=X)\ndef f(p):\n    return p\n",
        "svc.f",
        "level",
        "X",
        id="two_occurrences",
    ),
    pytest.param(
        _IMPORT + "X = 'ASSURED'\ndef g():\n    global X\n@trusted(level=X)\ndef f(p):\n    return p\n",
        "svc.f",
        "level",
        "X",
        id="global_poisons_the_name",
    ),
    pytest.param(
        _IMPORT + "X = 'ASSURED'\nclass C:\n    @trusted(level=X)\n    def m(self, p):\n        return p\n",
        "svc.C.m",
        "level",
        "X",
        id="method_reference_site",
    ),
    pytest.param(
        _IMPORT + "import sys\nX = 'ASSURED'\nif sys.version_info >= (3, 12):\n"
        "    @trusted(level=X)\n    def f(p):\n        return p\n",
        "svc.f",
        "level",
        "X",
        id="conditionally_defined_def",
    ),
    # Pins §4.2.1's `X: Final` (AnnAssign, no value) case-table row, and it is the one
    # row COUPLED to Task 3: it is UNREADABLE-and-FACT either way, but only if Task 3's
    # builder counts a valueless AnnAssign as a census OCCURRENCE is it unreadable for
    # the stated reason rather than merely unbound. If Task 3 skips such nodes, fix
    # Task 3 — do not delete this row.
    pytest.param(
        _IMPORT + "from typing import Final\nX: Final\n@trusted(level=X)\ndef f(p):\n    return p\n",
        "svc.f",
        "level",
        "X",
        id="annassign_without_a_value",
    ),
    pytest.param(
        _IMPORT + "from unknownpkg import *\nX = 'ASSURED'\n@trusted(level=X)\ndef f(p):\n    return p\n",
        "svc.f",
        "level",
        "X",
        id="star_import_poisons_the_module",
    ),
    pytest.param(
        "from wardline.decorators import trust_boundary\n@trust_boundary(to_level=CFG)\ndef f(p):\n    return p\n",
        "svc.f",
        "to_level",
        "CFG",
        id="unbound_name_on_to_level",
    ),
]


@pytest.mark.parametrize(("src", "qualname", "arg", "value"), _UNREADABLE)
def test_every_unreadable_shape_is_observable_and_carries_a_source_line(
    tmp_path: Path, src: str, qualname: str, arg: str, value: str
) -> None:
    result = _scan(tmp_path, src)
    (fact,) = _facts(result)
    assert fact.severity is Severity.NONE
    assert fact.kind is Kind.FACT
    assert fact.qualname == qualname
    assert fact.properties == {"argument": arg, "value": value, "reason": "unreadable_level_value"}
    assert fact.location.line_start is not None  # never a lineless FACT
    # The seed dropped, so the function is NOT in the declared set — the FACT is
    # the honest record of that, not a substitute for it.
    assert result.context is not None
    assert qualname not in result.context.declared_qualnames


def test_form_5_resolution_emits_no_fact_and_enters_the_declared_set(tmp_path: Path) -> None:
    result = _scan(
        tmp_path,
        _IMPORT + "_SVC_LEVEL = 'ASSURED'\n@trusted(level=_SVC_LEVEL)\ndef f(p):\n    return p\n",
    )
    assert not _facts(result)
    assert result.context is not None
    assert "svc.f" in result.context.declared_qualnames


def test_readable_but_invalid_token_is_py_wl_114_and_takes_no_fact(tmp_path: Path) -> None:
    # READS, then rejects: the name->token hop succeeded and the allow-check failed,
    # so the louder DEFECT is the channel. The residual FACT must NOT stack on it.
    result = _scan(
        tmp_path,
        _IMPORT + "_SVC_LEVEL = 'ASURED'\n@trusted(level=_SVC_LEVEL)\ndef f(p):\n    return p\n",
    )
    assert [f for f in result.findings if f.rule_id == "PY-WL-114"]
    assert not _facts(result)


def test_shape_offence_short_circuits_the_value_reader(tmp_path: Path) -> None:
    # THE ORDERING PIN. call_shape_offences runs before the levels loop (Task 5), so
    # a marker that is BOTH shape-malformed AND value-unreadable never reaches the
    # reader: PY-WL-130 fires and no FACT is emitted. This is the only assertion in
    # the area that is positive AND negative, and it is the one that pins the
    # short-circuit. Note honestly what the ordering costs: PY-WL-130 is a DEFECT and
    # is therefore suppressible, so a waived PY-WL-130 leaves this site with no signal
    # at all. Neither channel dominates the other.
    result = _scan(
        tmp_path,
        _IMPORT + "def get_level():\n    return 'ASSURED'\n"
        "@trusted(level=get_level(), audit=True)\ndef f(p):\n    return p\n",
    )
    assert [f for f in result.findings if f.rule_id == "PY-WL-130"]
    assert not _facts(result)


def test_custom_boundary_unreadable_level_never_takes_the_residual_fact(tmp_path: Path) -> None:
    # §4.2's compatibility boundary: revision 6 changes nothing on the custom side.
    # The released channel stands and the residual FACT is builtin-only, so no site
    # is reported twice or counted twice in decorator_coverage. Built through
    # build_analyzer/default_grammar().extend(...) — the idiom in
    # tests/grammar/test_unprovable_boundary.py:35 — because run_scan takes no
    # grammar, and a test is never a reason to widen run_scan's signature.
    from wardline.core.config import WardlineConfig
    from wardline.core.taints import TaintState as T
    from wardline.scanner.analyzer import build_analyzer
    from wardline.scanner.grammar import BoundaryType, LevelArg, default_grammar
    from wardline.scanner.taint.provider import FunctionTaint

    custom = BoundaryType(
        canonical_name="sanitized",
        module_prefix="myproj.trust",
        group=1,
        level_args=(LevelArg("to_level", frozenset({T.GUARDED, T.ASSURED}), None),),
        seed=lambda lv: FunctionTaint(T.EXTERNAL_RAW, lv["to_level"]),
        builtin=False,
    )
    f = tmp_path / "m.py"
    f.write_text(
        "import myproj.trust\n@myproj.trust.sanitized(to_level=get())\ndef g(p):\n    return p\n",
        encoding="utf-8",
    )
    analyzer = build_analyzer(grammar=default_grammar().extend(boundary_types=(custom,)))
    findings = analyzer.analyze([f], WardlineConfig(), root=tmp_path)
    assert [x for x in findings if x.rule_id == "WLN-ENGINE-UNPROVABLE-BOUNDARY"]
    assert not [x for x in findings if x.rule_id == FACT_ID]
    # Soundness condition 5's OTHER half, and the assertion that makes this test
    # discriminate rather than merely observe: the custom site keeps its released
    # UNKNOWN_RAW seed. Without it, a change that routed the custom value onto the
    # residual channel could still leave the two finding-set assertions above true
    # by accident of some other suppression.
    assert analyzer.last_context is not None
    assert analyzer.last_context.project_taints["m.g"] is T.UNKNOWN_RAW


def test_two_unreadable_arguments_on_one_function_are_distinct(tmp_path: Path) -> None:
    # §4.2.1 condition 4's distinctness claim, stated to match the preimage exactly:
    # the registry's two LEVEL keywords give the cross-marker case for free.
    #
    # It is ALSO the proof that the emission loop iterates the WHOLE residual tuple:
    # `taint_for` EXTENDS across decorators, so the field is UNBOUNDED even though
    # `_match`'s own return is capped at one pair. A `values[0]` consumer reds here.
    result = _scan(
        tmp_path,
        "from wardline.decorators import trusted, trust_boundary\n"
        "def a():\n    return 'ASSURED'\n"
        "@trusted(level=a())\n@trust_boundary(to_level=a())\ndef f(p):\n    return p\n",
    )
    facts = _facts(result)
    assert len(facts) == 2
    assert len({f.fingerprint for f in facts}) == 2
    assert {f.properties["argument"] for f in facts} == {"level", "to_level"}


def test_repeated_unreadable_markers_have_distinct_fingerprints(tmp_path: Path) -> None:
    result = _scan(
        tmp_path,
        _IMPORT + "@trusted(level=DYN)\n@trusted(level=DYN)\ndef f(p):\n    return p\n",
    )

    facts = _facts(result)
    assert len(facts) == 2
    assert len({fact.fingerprint for fact in facts}) == 2


def test_fingerprint_preimage_is_nfc_normalised_and_truncated(tmp_path: Path) -> None:
    # The preimage uses pipeline._fp over five ordered parts — rule id, qualname,
    # argument name, value key, and within-def decorator ordinal — with NO relpath.
    # NFC and the 200-character truncation apply to the VALUE part only, before it
    # becomes a part, never to the joined preimage.
    long_expr = "get('" + "z" * 400 + "')"
    result = _scan(
        tmp_path,
        _IMPORT + f"def get(k):\n    return k\n@trusted(level={long_expr})\ndef f(p):\n    return p\n",
    )
    (fact,) = _facts(result)
    key = unicodedata.normalize("NFC", long_expr)[:200]
    assert len(fact.properties["value"]) == 200
    assert fact.properties["value"] == key
    assert fact.fingerprint == _fp(FACT_ID, "svc.f", "level", key, "decorator#0")


def test_two_spellings_of_one_value_text_share_one_fingerprint(tmp_path: Path) -> None:
    # NFC, per §4.2.1 condition 4, following §11.1's declarations-digest encoding:
    # two spellings of one text must not mint two fingerprints. The variation has to
    # ride a STRING LITERAL inside the value expression, NOT an identifier — CPython
    # NFKC-normalises identifiers at parse time, so an identifier pair would pass
    # without our normalisation ever running, which is a test that proves nothing.
    composed = "\u00c5"  # LATIN CAPITAL LETTER A WITH RING ABOVE
    decomposed = "A\u030a"  # LATIN CAPITAL LETTER A + COMBINING RING ABOVE
    fps = set()
    for i, spelling in enumerate((composed, decomposed)):
        result = _scan(
            tmp_path / f"v{i}",
            _IMPORT + f"def get(k):\n    return k\n@trusted(level=get('{spelling}'))\ndef f(p):\n    return p\n",
        )
        (fact,) = _facts(result)
        fps.add(fact.fingerprint)
    assert len(fps) == 1


def test_residual_fact_does_not_de_inert_a_scan(tmp_path: Path) -> None:
    # §4.2.1 condition 2. A residual entity is not a provider-seeded row, does not
    # move the posture denominator, and must not arm an otherwise inert project —
    # mirroring §4.3's unknown-marker contract. Only successful resolution moves it.
    body = "".join(f"def q{i}(p):\n    return p\n" for i in range(5))
    result = _scan(
        tmp_path,
        _IMPORT + body + "def get_level():\n    return 'ASSURED'\n"
        "@trusted(level=get_level())\ndef f(p):\n    return p\n",
    )
    assert len(_facts(result)) == 1
    assert compute_resolution_posture(result.findings).inert is True
    assert result.context is not None
    assert "svc.f" not in result.context.declared_qualnames


def test_mixed_stack_fact_does_not_claim_the_function_is_undeclared(tmp_path: Path) -> None:
    # THE ONE SHAPE THE _UNREADABLE TABLE CANNOT COVER, and therefore the one where the
    # message went wrong. Every row above asserts `qualname not in declared_qualnames`,
    # so none of them is a MIXED stack — a marker whose value is unreadable sitting
    # beside a marker that resolves. Here @trusted(level='ASSURED') seeds, so the
    # function IS declared at ASSURED, while @trust_boundary(to_level=a()) still takes
    # the residual FACT. A FACT that asserted "NOT in the declared set" here would be
    # stating a false fact about the engine's own state — which is the failure this
    # whole plan exists to remove, appearing in the diagnostic meant to close it.
    #
    # The FACT's semantic fields are unchanged by the mixed stack; its fingerprint also
    # carries the marker's within-def ordinal so repeated occurrences stay distinct.
    result = _scan(
        tmp_path,
        "from wardline.decorators import trusted, trust_boundary\n"
        "def a():\n    return 'ASSURED'\n"
        "@trusted(level='ASSURED')\n@trust_boundary(to_level=a())\ndef f(p):\n    return p\n",
    )
    (fact,) = _facts(result)
    assert fact.properties == {"argument": "to_level", "value": "a()", "reason": "unreadable_level_value"}
    assert fact.fingerprint == _fp(FACT_ID, "svc.f", "to_level", "a()", "decorator#1")
    # The seed SURVIVED via the sibling marker — so the function IS declared...
    assert result.context is not None
    assert "svc.f" in result.context.declared_qualnames
    # ...and the message must not say otherwise.
    assert "NOT in the declared set" not in fact.message
    assert "stays in the declared set" in fact.message


def test_undeclared_fact_still_states_the_declared_set_consequence(tmp_path: Path) -> None:
    # The other side of the conditional, so the branch is pinned in BOTH directions and
    # the fix cannot be "delete the clause". On a single unreadable marker the seed really
    # is dropped, and that consequence — every tier-modulated rule going quiet on this
    # function — is the most actionable thing the diagnostic carries. It must still be said.
    result = _scan(
        tmp_path,
        _IMPORT + "def a():\n    return 'ASSURED'\n@trusted(level=a())\ndef f(p):\n    return p\n",
    )
    (fact,) = _facts(result)
    assert result.context is not None
    assert "svc.f" not in result.context.declared_qualnames
    assert "NOT in the declared set" in fact.message


def test_unreadable_module_constant_fires_the_fact_that_form_5_suppresses(tmp_path: Path) -> None:
    # THE POSITIVE ANCHOR for the negative assertion at
    # tests/unit/scanner/taint/test_decorator_provider.py:279, which asserts NO
    # WLN-ENGINE-UNREADABLE-MARKER-VALUE fires over a RESOLVING `_SVC_LEVEL`. Until
    # this commit nothing emitted that id, so that assertion was green by absence and
    # could not fail. Here is the minimal mutation of its exact source and harness —
    # same run_scan/tmp_path driver, same module-level `_SVC_LEVEL` shape, same
    # `@trusted(level=_SVC_LEVEL)` on a module-body `def` — with the ONE conjunct of
    # form 5 that the sibling satisfies removed: the binding is no longer a readable
    # single occurrence. The FACT fires, so the sibling's silence is now a measured
    # property of form-5 RESOLUTION rather than of an unimplemented channel.
    result = _scan(
        tmp_path,
        _IMPORT + "def _compute():\n    return 'ASSURED'\n"
        "_SVC_LEVEL = _compute()\n@trusted(level=_SVC_LEVEL)\ndef f(p):\n    return p\n",
    )
    (fact,) = _facts(result)
    assert fact.properties == {
        "argument": "level",
        "value": "_SVC_LEVEL",
        "reason": "unreadable_level_value",
    }
    assert result.context is not None
    assert "svc.f" not in result.context.declared_qualnames
