"""PY-WL-130 — a malformed builtin-marker call must be a loud ERROR DEFECT.

The engine drops the seed for these shapes (wardline-4928b75782): the function
falls out of declared_qualnames and every tier-modulated rule goes quiet — the
scan gets GREENER on a typo. This suite pins the rule that makes the shape red,
its agreement with seeding (fires exactly where call_shape_offences drops the
seed), and where it stays silent (well-formed calls, unreadable VALUES,
foreign/custom/shadowed markers)."""

from __future__ import annotations

from pathlib import Path

import pytest

from wardline.core.finding import Kind, Severity
from wardline.core.run import run_scan
from wardline.core.taints import TaintState


def _scan(tmp_path: Path, src: str):
    # Accepts a directory that may not exist yet, so a parametrized case can pass
    # `tmp_path / case` and keep each case's project tree distinct.
    proj = tmp_path / "proj"
    proj.mkdir(parents=True, exist_ok=True)
    (proj / "svc.py").write_text(src, encoding="utf-8")
    return run_scan(proj)


def _hits(result, rule_id: str = "PY-WL-130"):
    return [f for f in result.findings if f.rule_id == rule_id]


def test_undeclared_kwarg_on_trusted_fires_error(tmp_path: Path) -> None:
    result = _scan(
        tmp_path,
        "from wardline.decorators import trusted\n@trusted(level='INTEGRAL', audit=True)\ndef f(p):\n    return p\n",
    )
    (hit,) = _hits(result)
    assert hit.severity is Severity.ERROR
    assert hit.kind is Kind.DEFECT
    assert hit.properties == {"decorator": "trusted", "offender": "audit", "reason": "undeclared_kwarg"}
    # Agreement: the seed dropped (rule observes, never repairs).
    assert result.context is not None
    assert "svc.f" not in result.context.declared_qualnames


def test_shape_offence_with_invalid_token_is_pywl130_only(tmp_path: Path) -> None:
    # THE DISCRIMINATING HAND-OFF, and the only shape in which the gate's ordering is
    # observable: this marker is BOTH shape-malformed AND carries a readable-but-INVALID
    # token. Shipped PY-WL-114 fires on `level='ASURED'` whatever its siblings are, so
    # without Task 2 Step 3's shape gate this one site would take BOTH channels. The
    # sibling above uses a VALID token, where PY-WL-114 is silent gate or no gate.
    # The residual-FACT assertion is a FORWARD pin, trivially true until Task 8 and
    # required to stay true after it — a READS-then-rejects token never takes the FACT.
    result = _scan(
        tmp_path,
        "from wardline.decorators import trusted\n@trusted(level='ASURED', audit=True)\ndef f(p):\n    return p\n",
    )
    (hit,) = _hits(result)
    assert hit.properties == {"decorator": "trusted", "offender": "audit", "reason": "undeclared_kwarg"}
    assert not _hits(result, "PY-WL-114")
    assert not _hits(result, "WLN-ENGINE-UNREADABLE-MARKER-VALUE")
    assert result.context is not None
    assert "svc.f" not in result.context.declared_qualnames


def test_legacy_to_level_on_trusted_fires(tmp_path: Path) -> None:
    # The runtime rejects this call; the tolerance is gone (Task 5) — loud DEFECT.
    result = _scan(
        tmp_path,
        "from wardline.decorators import trusted\n"
        "@trusted(level='ASSURED', to_level='ASSURED')\n"
        "def f(p):\n"
        "    return p\n",
    )
    (hit,) = _hits(result)
    assert hit.properties == {"decorator": "trusted", "offender": "to_level", "reason": "undeclared_kwarg"}
    assert result.context is not None
    assert "svc.f" not in result.context.declared_qualnames


def test_positional_arg_fires(tmp_path: Path) -> None:
    result = _scan(
        tmp_path,
        "from wardline.decorators import trusted\n@trusted('INTEGRAL')\ndef f(p):\n    return p\n",
    )
    (hit,) = _hits(result)
    assert hit.properties["reason"] == "positional_args"


def test_called_external_boundary_fires(tmp_path: Path) -> None:
    result = _scan(
        tmp_path,
        "from wardline.decorators import external_boundary\n@external_boundary()\ndef f(p):\n    return p\n",
    )
    (hit,) = _hits(result)
    assert hit.properties == {"decorator": "external_boundary", "offender": "<call>", "reason": "call_not_allowed"}
    assert result.context is not None
    assert "svc.f" not in result.context.declared_qualnames  # Task 5: no more seeding through it


def test_called_external_boundary_with_kwarg_drops_the_seed(tmp_path: Path) -> None:
    # THE GATE PIN. ``external_boundary`` has ``level_args=()``, so ``read_level`` is
    # NEVER called for it — its seed depends on the provider's shape gate ALONE. Every
    # other builtin marker is level-bearing, and ``read_level``'s own ``deco.args`` /
    # ``extract_keywords`` / ``declared`` / duplicate checks INDEPENDENTLY drop those
    # seeds, so a refactor that deleted ``_match``'s ``call_shape_offences`` short
    # circuit would keep them all green. This row (and the zero-arg sibling above) are
    # what red under that mutation: the rule still fires — it calls the validator
    # itself — but the marker would seed EXTERNAL_RAW and ``svc.f`` would re-enter
    # ``declared_qualnames``. Keep BOTH called forms: the bare-call form and the
    # kwarg-bearing form are the motivating stack of wardline-4928b75782.
    result = _scan(
        tmp_path,
        "from wardline.decorators import external_boundary\n"
        "@external_boundary(source='http')\n"
        "def f(p):\n"
        "    return p\n",
    )
    (hit,) = _hits(result)
    assert hit.properties == {"decorator": "external_boundary", "offender": "<call>", "reason": "call_not_allowed"}
    assert result.context is not None
    assert "svc.f" not in result.context.declared_qualnames
    # The seed itself, not just the declared set: gate removal would make this
    # EXTERNAL_RAW (the marker's own seed) instead of the L1 undeclared default.
    assert result.context.project_taints["svc.f"] is TaintState.UNKNOWN_RAW


def test_bare_trust_boundary_fires_call_required(tmp_path: Path) -> None:
    result = _scan(
        tmp_path,
        "from wardline.decorators import trust_boundary\n@trust_boundary\ndef f(p):\n    return p\n",
    )
    (hit,) = _hits(result)
    assert hit.properties == {"decorator": "trust_boundary", "offender": "<bare>", "reason": "call_required"}


def test_zero_arg_trust_boundary_fires_missing_kwarg(tmp_path: Path) -> None:
    result = _scan(
        tmp_path,
        "from wardline.decorators import trust_boundary\n@trust_boundary()\ndef f(p):\n    return p\n",
    )
    (hit,) = _hits(result)
    assert hit.properties["reason"] == "missing_kwarg"


def test_duplicate_level_via_splat_fires(tmp_path: Path) -> None:
    result = _scan(
        tmp_path,
        "from wardline.decorators import trusted\n"
        "@trusted(level='ASSURED', **{'level': 'ASSURED'})\n"
        "def f(p):\n"
        "    return p\n",
    )
    (hit,) = _hits(result)
    assert hit.properties == {"decorator": "trusted", "offender": "level", "reason": "duplicate_kwarg"}


def test_duplicate_inside_one_literal_dict_uses_last_value(tmp_path: Path) -> None:
    result = _scan(
        tmp_path,
        "from wardline.decorators import trusted\n"
        "@trusted(**{'level': 'ASURED', 'level': 'ASSURED'})\n"
        "def f(p):\n    return p\n",
    )
    assert not _hits(result)
    assert not [f for f in result.findings if f.rule_id == "PY-WL-114"]
    assert result.context is not None
    assert "svc.f" in result.context.declared_qualnames


def test_duplicate_inside_one_literal_dict_last_typo_is_pywl114(tmp_path: Path) -> None:
    result = _scan(
        tmp_path,
        "from wardline.decorators import trusted\n"
        "@trusted(**{'level': 'ASSURED', 'level': 'ASURED'})\n"
        "def f(p):\n    return p\n",
    )
    assert not _hits(result)
    assert [f for f in result.findings if f.rule_id == "PY-WL-114"]
    assert result.context is not None
    assert "svc.f" not in result.context.declared_qualnames


def test_literal_non_string_splat_key_is_shape_defect_only(tmp_path: Path) -> None:
    result = _scan(
        tmp_path,
        "from wardline.decorators import trusted\n@trusted(**{1: 'ASSURED'})\ndef f(p):\n    return p\n",
    )
    assert [f for f in result.findings if f.rule_id == "PY-WL-130"]
    assert not [f for f in result.findings if f.rule_id == "PY-WL-114"]


def test_unreadable_value_is_not_a_shape_offence(tmp_path: Path) -> None:
    # The PROPERTY survives rev 6 unchanged — a value problem is never a SHAPE
    # offence. The FIXTURE does not: `CFG = 'ASSURED'` now satisfies P3 form 5 in
    # full and RESOLVES (see the companion below), which would leave this test
    # green while exercising nothing. Re-expressed over a binding form 5
    # explicitly REFUSES — a call right-hand side (spec §4.2.1). `level=DYN` is a
    # runtime-VALID call whose value stays statically unreadable, so PY-WL-130 is
    # silent AND the residual FACT fires: unreadable is never silent.
    result = _scan(
        tmp_path,
        "from wardline.decorators import trusted\n"
        "def get_level():\n    return 'ASSURED'\n"
        "DYN = get_level()\n"
        "@trusted(level=DYN)\n"
        "def f(p):\n"
        "    return p\n",
    )
    assert not _hits(result)
    assert [f for f in result.findings if f.rule_id == "WLN-ENGINE-UNREADABLE-MARKER-VALUE"]
    assert result.context is not None
    assert "svc.f" not in result.context.declared_qualnames


def test_form5_module_constant_resolves_and_is_not_a_shape_offence(
    tmp_path: Path,
) -> None:
    # The companion, and the inversion rev 6 introduces. `CFG` is a single,
    # unconditional, direct-top-level `str` binding lexically preceding a `def`
    # that is a direct element of Module.body, read in a BUILTIN marker's LEVEL
    # slot — P3 form 5 in full. It RESOLVES: no shape offence (this rule stays
    # silent for the same reason as ever), no residual FACT (nothing stayed
    # unreadable), and the qualname ENTERS declared_qualnames (spec §4.2.1).
    result = _scan(
        tmp_path,
        "from wardline.decorators import trusted\nCFG = 'ASSURED'\n@trusted(level=CFG)\ndef f(p):\n    return p\n",
    )
    assert not _hits(result)
    assert not [f for f in result.findings if f.rule_id == "WLN-ENGINE-UNREADABLE-MARKER-VALUE"]
    assert result.context is not None
    assert "svc.f" in result.context.declared_qualnames


def test_aliased_builtin_fires(tmp_path: Path) -> None:
    result = _scan(
        tmp_path,
        "from wardline.decorators import trusted as t\n@t(level='INTEGRAL', audit=True)\ndef f(p):\n    return p\n",
    )
    assert len(_hits(result)) == 1


def test_imported_marker_rebound_before_use_is_a_local_decorator(tmp_path: Path) -> None:
    result = _scan(
        tmp_path,
        "from wardline.decorators import trusted\n"
        "def trusted(*, level, audit):\n"
        "    def decorate(fn):\n"
        "        return fn\n"
        "    return decorate\n"
        "@trusted(level='ASSURED', audit=True)\n"
        "def f(p):\n"
        "    return p\n",
    )
    assert not _hits(result)
    assert result.context is not None
    assert "svc.f" not in result.context.declared_qualnames


def test_imported_marker_rebound_after_use_still_resolves_at_the_decorator(tmp_path: Path) -> None:
    # Source order is load-bearing: a later rebind cannot retroactively change the
    # callable evaluated when the decorator ran.
    result = _scan(
        tmp_path,
        "from wardline.decorators import trusted\n"
        "@trusted(level='ASSURED', audit=True)\n"
        "def f(p):\n"
        "    return p\n"
        "trusted = object()\n",
    )
    assert len(_hits(result)) == 1


def test_foreign_and_custom_markers_are_not_this_rules_concern(tmp_path: Path) -> None:
    result = _scan(
        tmp_path,
        "import other_pkg\n@other_pkg.trusted(level='X', extra=1)\ndef f(p):\n    return p\n",
    )
    assert not _hits(result)


def test_shadowed_root_stays_silent(tmp_path: Path) -> None:
    proj = tmp_path / "proj"
    (proj / "wardline" / "decorators").mkdir(parents=True)
    (proj / "wardline" / "__init__.py").write_text("", encoding="utf-8")
    (proj / "wardline" / "decorators" / "__init__.py").write_text("", encoding="utf-8")
    (proj / "svc.py").write_text(
        "from wardline.decorators import trusted\n@trusted(level='INTEGRAL', audit=True)\ndef f(p):\n    return p\n",
        encoding="utf-8",
    )
    result = run_scan(proj)
    assert not _hits(result)


def test_stacked_malformed_markers_get_distinct_fingerprints(tmp_path: Path) -> None:
    result = _scan(
        tmp_path,
        "from wardline.decorators import trusted, external_boundary\n"
        "@trusted(level='INTEGRAL', audit=True)\n"
        "@external_boundary(source='http')\n"
        "def f(p):\n"
        "    return p\n",
    )
    hits = _hits(result)
    assert len(hits) == 2
    assert len({h.fingerprint for h in hits}) == 2


def test_multi_offence_call_pins_the_canonical_phase_order(tmp_path: Path) -> None:
    # The FINGERPRINT half of the phase-order contract Task 2 Step 5 pins at reader
    # level. ``offence_ordinal`` is the ``.N`` component of ``taint_path``, so the
    # canonical order of ``call_shape_offences`` (call-form, positional, extraction
    # offences, keyword classification, missing names) is a compatibility contract:
    # reorder those phases and every multi-offence fingerprint silently reshuffles.
    # The sibling above discriminates ``deco_ordinal`` across STACKED decorators and
    # is blind to this — it is the ``.N`` on ONE call that is unpinned without this row.
    #
    # Note the order: ``audit=True`` is written BEFORE ``**KW`` in the source, but
    # extraction offences precede keyword classification, so the splat takes ordinal 1
    # and the undeclared keyword ordinal 2.
    result = _scan(
        tmp_path,
        "from wardline.decorators import trusted\n"
        "KW = {'level': 'ASSURED'}\n"
        "@trusted('ASSURED', audit=True, **KW)\n"
        "def f(p):\n"
        "    return p\n",
    )
    hits = _hits(result)
    assert len(hits) == 3
    assert {h.properties["reason"]: h.taint_path_v0 for h in hits} == {
        "positional_args": "trusted:<positional>#0.0",
        "unreadable_splat": "trusted:<**splat>#0.1",
        "undeclared_kwarg": "trusted:audit#0.2",
    }
    assert len({h.fingerprint for h in hits}) == 3


_RUNTIME_INVALID = "invalid for the shipped runtime signature"

# (case id, source, expected reason, must the runtime-invalid clause appear?)
CLAUSE_CASES = [
    ("call_required", "@trust_boundary\ndef f(p):\n    return p\n", "call_required", True),
    ("undeclared_kwarg", "@trusted(level='ASSURED', audit=True)\ndef f(p):\n    return p\n", "undeclared_kwarg", True),
    ("duplicate_kwarg", "@trusted(level='A', **{'level': 'B'})\ndef f(p):\n    return p\n", "duplicate_kwarg", True),
    ("missing_kwarg", "@trust_boundary()\ndef f(p):\n    return p\n", "missing_kwarg", True),
    ("invalid_splat_key", "@trusted(**{1: 'ASSURED'})\ndef f(p):\n    return p\n", "invalid_splat_key", True),
    # --- the four cases that must NOT carry the claim (all REPL-verified runtime-VALID) ---
    (
        "call_not_allowed_callable",
        "def audit(x):\n    return x\n@external_boundary(audit)\ndef f(p):\n    return p\n",
        "call_not_allowed",
        False,
    ),
    (
        "positional_callable",
        "def audit(x):\n    return x\n@trusted(audit)\ndef f(p):\n    return p\n",
        "positional_args",
        False,
    ),
    ("star_args", "ARGS = ()\n@trusted(*ARGS)\ndef f(p):\n    return p\n", "positional_args", False),
    (
        "computed_splat_key",
        "@trusted(**{'lev' + 'el': 'ASSURED'})\ndef f(p):\n    return p\n",
        "unreadable_splat",
        False,
    ),
]


@pytest.mark.parametrize(
    ("case", "body", "reason", "claims_runtime_invalid"),
    CLAUSE_CASES,
    ids=[c[0] for c in CLAUSE_CASES],
)
def test_message_claims_runtime_invalidity_only_when_proved(
    tmp_path: Path, case: str, body: str, reason: str, claims_runtime_invalid: bool
) -> None:
    # Plan Global Constraints / spec §4.2: PY-WL-130 may call a shape
    # runtime-invalid ONLY for a proved runtime-invalid reason. Each False row
    # below was executed against the real decorators and did NOT raise.
    result = _scan(
        tmp_path / case,
        "from wardline.decorators import external_boundary, trust_boundary, trusted\n" + body,
    )
    hits = [h for h in _hits(result) if h.properties["reason"] == reason]
    assert hits, f"{case}: expected reason {reason}, got {[h.properties for h in _hits(result)]}"
    assert all((_RUNTIME_INVALID in h.message) is claims_runtime_invalid for h in hits), case


def test_star_args_and_computed_key_keep_the_pinned_reason_vocabulary(tmp_path: Path) -> None:
    # No new reason strings: the eight of spec §4.2 are the whole vocabulary.
    for body, reason, offender in (
        ("ARGS = ()\n@trusted(*ARGS)\ndef f(p):\n    return p\n", "positional_args", "<*args>"),
        ("@trusted(**{'lev' + 'el': 'X'})\ndef f(p):\n    return p\n", "unreadable_splat", "<**splat>"),
    ):
        result = _scan(tmp_path / reason, "from wardline.decorators import trusted\n" + body)
        (hit,) = _hits(result)
        assert hit.properties["reason"] == reason
        assert hit.properties["offender"] == offender


def test_computed_splat_key_suppresses_missing_kwarg(tmp_path: Path) -> None:
    # A computed key MAY be the required name; Wardline must not claim it is missing.
    result = _scan(
        tmp_path,
        "from wardline.decorators import trust_boundary\n"
        "@trust_boundary(**{'to_' + 'level': 'ASSURED'})\ndef f(p):\n    return p\n",
    )
    reasons = {h.properties["reason"] for h in _hits(result)}
    assert reasons == {"unreadable_splat"}
