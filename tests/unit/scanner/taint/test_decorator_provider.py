# tests/unit/scanner/taint/test_decorator_provider.py
from __future__ import annotations

import ast
import types

from wardline.core.registry import REGISTRY_VERSION
from wardline.core.taints import TaintState as T
from wardline.scanner.ast_primitives import build_import_alias_map
from wardline.scanner.grammar import BoundaryType
from wardline.scanner.index import discover_file_entities
from wardline.scanner.taint.decorator_provider import DecoratorTaintSourceProvider
from wardline.scanner.taint.provider import FunctionTaint, SeedContext


def _seed(
    src: str,
    *,
    module: str = "m",
    project_modules: frozenset[str] = frozenset(),
) -> dict[str, FunctionTaint | None]:
    """Run the provider over every function entity in *src*; map qualname -> result."""
    tree = ast.parse(src)
    alias_map = build_import_alias_map(tree, module_path=module)
    entities = discover_file_entities(tree, module=module, path="m.py")
    ctx = SeedContext(module=module, alias_map=alias_map, project_modules=project_modules)
    provider = DecoratorTaintSourceProvider()
    # .taint: assertions here compare the declared FunctionTaint; the unprovable-
    # boundary signal (Track 2 T2.4) is exercised separately in tests/grammar/.
    return {e.qualname: provider.taint_for(e, ctx).taint for e in entities}


def _custom_provider_fingerprint(seed: object) -> str:
    boundary = BoundaryType("custom_boundary", "custom_pack", 1, (), seed)
    return DecoratorTaintSourceProvider(boundary_types=(boundary,)).fingerprint()


def test_hostile_instance_dict_snapshot_degrades_instead_of_raising() -> None:
    # A custom pack controls its seed completely: ``__getattribute__`` may expose a
    # dict SUBCLASS as ``__dict__`` whose ``items()`` runs pack code and raises. The
    # provider fingerprint is computed BEFORE the parse loop's per-file isolation
    # (pipeline.py), so an escape here aborts the whole scan with no degradation
    # marker and the trust-boundary gate never runs. Both snapshot sites —
    # ``_instance_identity`` and ``_subclass_state`` — must degrade, never raise.
    class EvilItems(dict):
        def items(self):  # noqa: D102 - hostile fixture
            raise RuntimeError("pack boom in items()")

    class HostileSeed:
        def __call__(self, levels):  # noqa: ANN001, ANN204 - never called
            return None

        def __getattribute__(self, name: str):  # noqa: ANN204
            if name == "__dict__":
                return EvilItems()
            return object.__getattribute__(self, name)

    fp_instance = _custom_provider_fingerprint(HostileSeed())
    assert isinstance(fp_instance, str) and fp_instance

    class HostileMapping(dict):
        # A transparent-builtin SUBCLASS routes through ``_subclass_state`` — the
        # second site with the same unguarded snapshot.
        def __getattribute__(self, name: str):  # noqa: ANN204
            if name == "__dict__":
                return EvilItems()
            return object.__getattribute__(self, name)

    def template(levels):  # noqa: ANN001, ANN202 - never called
        return HOSTILE  # noqa: F821 - resolved via injected globals

    seed_fn = types.FunctionType(template.__code__, {"HOSTILE": HostileMapping()}, name="seed")
    seed_fn.__module__ = "custom_pack"
    seed_fn.__qualname__ = "seed"
    fp_subclass = _custom_provider_fingerprint(seed_fn)
    assert isinstance(fp_subclass, str) and fp_subclass
    # Degradation, not blinding: the two hostile shapes still discriminate.
    assert fp_instance != fp_subclass


def test_custom_seed_fingerprint_includes_referenced_global_names() -> None:
    seed_a = eval("lambda levels: safe_seed")  # noqa: S307 - local test fixture, no user input
    seed_b = eval("lambda levels: raw_seed")  # noqa: S307 - local test fixture, no user input

    assert seed_a.__code__.co_code == seed_b.__code__.co_code
    assert seed_a.__code__.co_consts == seed_b.__code__.co_consts
    assert _custom_provider_fingerprint(seed_a) != _custom_provider_fingerprint(seed_b)


def test_custom_seed_fingerprint_includes_referenced_global_values() -> None:
    safe_seed = FunctionTaint(T.INTEGRAL, T.INTEGRAL)
    raw_seed = FunctionTaint(T.EXTERNAL_RAW, T.EXTERNAL_RAW)

    def template(levels):  # noqa: ANN001, ANN202
        return SEED  # noqa: F821

    seed_a = types.FunctionType(template.__code__, {"SEED": safe_seed}, name="seed")
    seed_b = types.FunctionType(template.__code__, {"SEED": raw_seed}, name="seed")
    seed_a.__module__ = seed_b.__module__ = "custom_pack"
    seed_a.__qualname__ = seed_b.__qualname__ = "seed"

    assert seed_a.__code__.co_code == seed_b.__code__.co_code
    assert seed_a.__code__.co_consts == seed_b.__code__.co_consts
    assert seed_a.__code__.co_names == seed_b.__code__.co_names
    assert _custom_provider_fingerprint(seed_a) != _custom_provider_fingerprint(seed_b)


def test_external_boundary_from_import() -> None:
    out = _seed("from wardline.decorators import external_boundary\n@external_boundary\ndef read(p):\n    return p\n")
    assert out["m.read"] == FunctionTaint(T.EXTERNAL_RAW, T.EXTERNAL_RAW)


def test_weft_markers_external_boundary_from_import() -> None:
    out = _seed("from weft_markers import external_boundary\n@external_boundary\ndef read(p):\n    return p\n")
    assert out["m.read"] == FunctionTaint(T.EXTERNAL_RAW, T.EXTERNAL_RAW)


def test_weft_markers_trust_boundary_from_import() -> None:
    out = _seed(
        "from weft_markers import trust_boundary\n@trust_boundary(to_level='ASSURED')\ndef v(x):\n    return x\n"
    )
    assert out["m.v"] == FunctionTaint(T.EXTERNAL_RAW, T.ASSURED)


def test_weft_markers_trusted_from_import() -> None:
    out = _seed("from weft_markers import trusted\n@trusted\ndef f():\n    return 1\n")
    assert out["m.f"] == FunctionTaint(T.INTEGRAL, T.INTEGRAL)


def test_weft_markers_fires_end_to_end(tmp_path) -> None:
    from wardline.core.run import run_scan

    (tmp_path / "m.py").write_text(
        "from weft_markers import external_boundary, trusted\n"
        "\n"
        "@external_boundary\n"
        "def read_raw(p):\n"
        "    return p\n"
        "\n"
        "@trusted(level='ASSURED')\n"
        "def build_record(p):\n"
        "    return read_raw(p)\n",
        encoding="utf-8",
    )

    result = run_scan(tmp_path)

    active = {f.rule_id for f in result.findings if f.suppressed.value == "active"}
    assert "PY-WL-101" in active


def test_marker_alias_resolves_at_decorator_before_later_import(tmp_path) -> None:
    from wardline.core.run import run_scan

    (tmp_path / "m.py").write_text(
        "from wardline.decorators import external_boundary, trusted as marker\n"
        "@external_boundary\n"
        "def read_raw(p):\n"
        "    return p\n"
        "@marker(level='ASSURED')\n"
        "def build_record(p):\n"
        "    return read_raw(p)\n"
        "from wardline.decorators import external_boundary as marker\n",
        encoding="utf-8",
    )

    result = run_scan(tmp_path)

    assert result.context is not None
    assert "m.build_record" in result.context.declared_qualnames
    assert any(f.rule_id == "PY-WL-101" and f.qualname == "m.build_record" for f in result.findings)


def test_comprehension_target_does_not_shadow_a_marker_alias(tmp_path) -> None:
    # A module-level comprehension target is LOCAL to the comprehension's implicit
    # scope: at runtime ``marker`` still binds the real decorator, so the marker is
    # live and must seed. Counting the target as a module rebind refused the alias
    # rewrite and dropped the seed with EVERY diagnostic channel empty — an inert
    # scan over a validly-marked module (the fail-open direction).
    from wardline.core.run import run_scan

    (tmp_path / "m.py").write_text(
        "from wardline.decorators import external_boundary, trusted as marker\n"
        "unused = [marker for marker in ()]\n"
        "@external_boundary\n"
        "def read_raw(p):\n"
        "    return p\n"
        "@marker(level='ASSURED')\n"
        "def build_record(p):\n"
        "    return read_raw(p)\n",
        encoding="utf-8",
    )

    result = run_scan(tmp_path)

    assert result.context is not None
    assert "m.build_record" in result.context.declared_qualnames
    assert any(f.rule_id == "PY-WL-101" and f.qualname == "m.build_record" for f in result.findings)


def test_external_boundary_aliased_from_import() -> None:
    out = _seed("from wardline.decorators import external_boundary as eb\n@eb\ndef read(p):\n    return p\n")
    assert out["m.read"] == FunctionTaint(T.EXTERNAL_RAW, T.EXTERNAL_RAW)


def test_external_boundary_module_alias_attribute() -> None:
    out = _seed("import wardline.decorators as wd\n@wd.external_boundary\ndef read(p):\n    return p\n")
    assert out["m.read"] == FunctionTaint(T.EXTERNAL_RAW, T.EXTERNAL_RAW)


def test_external_boundary_plain_import_dotted() -> None:
    out = _seed("import wardline.decorators\n@wardline.decorators.external_boundary\ndef read(p):\n    return p\n")
    assert out["m.read"] == FunctionTaint(T.EXTERNAL_RAW, T.EXTERNAL_RAW)


def test_trust_boundary_to_level_string() -> None:
    out = _seed(
        "from wardline.decorators import trust_boundary\n@trust_boundary(to_level='ASSURED')\ndef v(x):\n    return x\n"
    )
    assert out["m.v"] == FunctionTaint(T.EXTERNAL_RAW, T.ASSURED)


def test_trust_boundary_to_level_enum_attribute() -> None:
    out = _seed(
        "from wardline.decorators import trust_boundary\n"
        "from wardline.core.taints import TaintState\n"
        "@trust_boundary(to_level=TaintState.GUARDED)\ndef v(x):\n    return x\n"
    )
    assert out["m.v"] == FunctionTaint(T.EXTERNAL_RAW, T.GUARDED)


def test_trust_boundary_disallowed_level_is_no_opinion() -> None:
    # INTEGRAL is not a valid boundary target -> fail-closed (None).
    out = _seed(
        "from wardline.decorators import trust_boundary\n"
        "@trust_boundary(to_level='INTEGRAL')\ndef v(x):\n    return x\n"
    )
    assert out["m.v"] is None


def test_trust_boundary_bare_is_no_opinion() -> None:
    out = _seed("from wardline.decorators import trust_boundary\n@trust_boundary\ndef v(x):\n    return x\n")
    assert out["m.v"] is None


def test_trusted_bare_defaults_integral() -> None:
    out = _seed("from wardline.decorators import trusted\n@trusted\ndef f():\n    return 1\n")
    assert out["m.f"] == FunctionTaint(T.INTEGRAL, T.INTEGRAL)


def test_trusted_level_assured() -> None:
    out = _seed("from wardline.decorators import trusted\n@trusted(level='ASSURED')\ndef f():\n    return 1\n")
    assert out["m.f"] == FunctionTaint(T.ASSURED, T.ASSURED)


def test_legacy_to_level_on_trusted_now_drops_the_seed() -> None:
    # REVERSAL (S0, spec §4.2): the analyzer-only tolerance for the runtime-
    # invalid `@trusted(level=..., to_level=...)` shape is gone. The runtime
    # raises TypeError on this call; the analyzer now agrees — undeclared
    # keyword => shape offence => no seed (and PY-WL-130 fires, rule suite).
    out = _seed(
        "from wardline.decorators import trusted\n"
        "@trusted(level='ASSURED', to_level='ASSURED')\n"
        "def f():\n"
        "    return 1\n"
    )
    assert out["m.f"] is None


def test_called_external_boundary_drops_the_seed() -> None:
    # external_boundary's runtime signature takes NO call arguments; the provider
    # previously never inspected them (level_args=()) and seeded anyway. The
    # shape validator closes that: a runtime-TypeError declaration never seeds.
    for call in (
        "external_boundary()",
        "external_boundary(**{})",
        "external_boundary(source='http')",
        "external_boundary('http')",
        "external_boundary(**KW)",
    ):
        out = _seed(f"from wardline.decorators import external_boundary\nKW = {{}}\n@{call}\ndef f():\n    return 1\n")
        assert out["m.f"] is None, call


def test_bare_external_boundary_still_seeds() -> None:
    out = _seed("from wardline.decorators import external_boundary\n@external_boundary\ndef f():\n    return 1\n")
    assert out["m.f"] == FunctionTaint(T.EXTERNAL_RAW, T.EXTERNAL_RAW)


def test_malformed_sibling_never_reduces_the_error_population(tmp_path) -> None:
    # The property that matters, and the one a seed-value assertion cannot express:
    # dropping a malformed marker must never make a scan QUIETER than leaving it.
    # Measured at release/2.0.0: the pre-Task-5 engine seeds this stack EXTERNAL_RAW
    # and fires ZERO ERROR+ defects, because EXTERNAL_RAW is in RAW_ZONE and modulate()
    # returns Severity.NONE. After Task 5 the malformed marker drops, @trusted stands
    # alone, the tier is ASSURED, and PY-WL-101 + PY-WL-112 fire. Demoting the seed to
    # UNKNOWN_RAW "for safety" would return it to silence — declaring trust is what
    # SUBJECTS a function to the leak rules.
    from wardline.core.finding import Kind, Severity
    from wardline.core.run import run_scan

    src = (
        "import subprocess\n"
        "from wardline.decorators import trusted, external_boundary\n"
        "@external_boundary\n"
        "def raw(p):\n    return p\n"
        "@trusted(level='ASSURED')\n"
        "@external_boundary(source='http')\n"
        "def f(p):\n"
        "    cmd = raw(p)\n"
        "    subprocess.run(cmd, shell=True)\n"
        "    return cmd\n"
    )
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "svc.py").write_text(src, encoding="utf-8")
    result = run_scan(proj)
    assert result.context is not None
    assert result.context.project_taints["svc.f"] == T.ASSURED
    errors = {
        f.rule_id
        for f in result.findings
        if f.kind is Kind.DEFECT and f.severity in (Severity.ERROR, Severity.CRITICAL)
    }
    assert {"PY-WL-101", "PY-WL-112", "PY-WL-130"} <= errors


def test_malformed_marker_alone_still_takes_no_opinion() -> None:
    # The contribute-only-alongside-a-candidate rule, SPLIT by rev 6 (spec §4.2.1):
    # a lone marker with a malformed SHAPE must NOT enter declared_qualnames
    # (posture denominator stability) — a shape offence is not a value problem, so
    # this half is unchanged. A lone marker whose LEVEL RESOLVES — including via
    # P3 form 5 — DOES enter declared_qualnames and DOES count in the anchored
    # posture bucket (spec §4.2.1, §11.4). The sibling below pins that half.
    out = _seed(
        "from wardline.decorators import trusted\n@trusted(level='ASSURED', audit=True)\ndef f():\n    return 1\n"
    )
    assert out["m.f"] is None


def test_form5_module_constant_level_seeds_and_declares(tmp_path) -> None:
    # The other half of the split above, and the posture consequence spec §4.2.1
    # states rather than leaving to the implementer. `_SVC_LEVEL` is a single,
    # unconditional, direct-top-level `str` binding lexically preceding a `def`
    # that is a direct element of Module.body, read in a BUILTIN marker's LEVEL
    # slot — P3 form 5 in full. It RESOLVES, so this function IS a recognised
    # boundary: it seeds, it enters declared_qualnames, and it takes NO residual
    # FACT (the FACT is for what stays unreadable, never for what resolves).
    #
    # run_scan/tmp_path, NOT _seed: _seed builds its own SeedContext and supplies
    # no per-module census, and a bare Name in a LEVEL slot with no census present
    # is a PLUMBING DEFECT the shared reader RAISES on (spec §4.2.1). Only the
    # parse loop builds the census, so only an end-to-end scan can exercise form 5.
    from wardline.core.run import run_scan

    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "svc.py").write_text(
        "from wardline.decorators import trusted\n"
        "_SVC_LEVEL = 'ASSURED'\n"
        "@trusted(level=_SVC_LEVEL)\n"
        "def f(p):\n"
        "    return p\n",
        encoding="utf-8",
    )
    result = run_scan(proj)
    assert result.context is not None
    # Primary assertion: the posture denominator moves, correctly.
    assert "svc.f" in result.context.declared_qualnames
    assert result.context.project_taints["svc.f"] == T.ASSURED
    assert not [f for f in result.findings if f.rule_id == "WLN-ENGINE-UNREADABLE-MARKER-VALUE"]


def test_trusted_level_static_kwargs_assured() -> None:
    out = _seed("from wardline.decorators import trusted\n@trusted(**{'level': 'ASSURED'})\ndef f():\n    return 1\n")
    assert out["m.f"] == FunctionTaint(T.ASSURED, T.ASSURED)


def test_trusted_dynamic_kwargs_is_no_opinion() -> None:
    out = _seed(
        "from wardline.decorators import trusted\nKW = {'level': 'ASSURED'}\n@trusted(**KW)\ndef f():\n    return 1\n"
    )
    assert out["m.f"] is None


def test_trusted_positional_arg_is_no_opinion() -> None:
    out = _seed("from wardline.decorators import trusted\n@trusted('ASSURED')\ndef f():\n    return 1\n")
    assert out["m.f"] is None


def test_trusted_unexpected_keyword_is_no_opinion() -> None:
    out = _seed("from wardline.decorators import trusted\n@trusted(other=1)\ndef f():\n    return 1\n")
    assert out["m.f"] is None


def test_trusted_disallowed_level_is_no_opinion() -> None:
    out = _seed("from wardline.decorators import trusted\n@trusted(level='GUARDED')\ndef f():\n    return 1\n")
    assert out["m.f"] is None


def test_module_constant_level_now_resolves_under_form5(tmp_path) -> None:
    # REWRITE of `test_trusted_dynamic_level_is_no_opinion` (:201-204), whose
    # premise spec §4.2.1 retires. That test read `LV = 'ASSURED'` /
    # `@trusted(level=LV)` through `_seed` and asserted no-opinion — "a non-literal
    # level (a Name) cannot be read statically -> fail-closed". Under P3 form 5
    # that exact source RESOLVES (one unconditional direct-top-level `str`
    # binding, lexically preceding a `def` that is a direct element of
    # Module.body, in a BUILTIN LEVEL slot), so BOTH the name and the assertion
    # invert.
    #
    # It also cannot stay on `_seed`: `_seed` constructs its own SeedContext with
    # no census, and from this task's commit the shared reader RAISES on a bare
    # `Name` in a builtin LEVEL slot with `census=None`. Left alone it would ERROR
    # here, not merely fail. Kept as its own row rather than folded into the test
    # above, so the reversal stays visible where the old fail-closed pin stood.
    from wardline.core.run import run_scan

    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "svc.py").write_text(
        "from wardline.decorators import trusted\nLV = 'ASSURED'\n@trusted(level=LV)\ndef f():\n    return 1\n",
        encoding="utf-8",
    )
    result = run_scan(proj)
    assert result.context is not None
    assert result.context.project_taints["svc.f"] == T.ASSURED
    assert "svc.f" in result.context.declared_qualnames


def test_undecorated_is_no_opinion() -> None:
    out = _seed("def f(p):\n    return p\n")
    assert out["m.f"] is None


def test_non_vocabulary_decorator_is_no_opinion() -> None:
    out = _seed("import functools\n@functools.cache\ndef f():\n    return 1\n")
    assert out["m.f"] is None


def test_coincidental_local_name_not_from_wardline_is_no_opinion() -> None:
    # A user's own 'trusted' with no wardline import must NOT be seeded.
    out = _seed("def trusted(fn):\n    return fn\n@trusted\ndef f():\n    return 1\n")
    assert out["m.f"] is None


def test_conflicting_decorators_pick_least_trusted_return() -> None:
    # An authoring conflict: @trusted (INTEGRAL) + @external_boundary (EXTERNAL_RAW).
    # Fail-closed: the least-trusted return wins (never over-trust).
    out = _seed(
        "from wardline.decorators import external_boundary, trusted\n"
        "@trusted\n@external_boundary\ndef f(p):\n    return p\n"
    )
    assert out["m.f"] == FunctionTaint(T.EXTERNAL_RAW, T.EXTERNAL_RAW)


def test_conflicting_decorators_least_trusted_per_field_order_independent() -> None:
    # Return-rank TIE (both ASSURED) but differing bodies: @trusted(level=ASSURED)
    # has body ASSURED, @trust_boundary(to_level=ASSURED) has body EXTERNAL_RAW.
    # The body must resolve to the least-trusted (EXTERNAL_RAW) regardless of
    # decorator source order — never an order-dependent body under-taint.
    src_a = (
        "from wardline.decorators import trusted, trust_boundary\n"
        "@trusted(level='ASSURED')\n@trust_boundary(to_level='ASSURED')\n"
        "def f(x):\n    return x\n"
    )
    src_b = (
        "from wardline.decorators import trusted, trust_boundary\n"
        "@trust_boundary(to_level='ASSURED')\n@trusted(level='ASSURED')\n"
        "def f(x):\n    return x\n"
    )
    expected = FunctionTaint(T.EXTERNAL_RAW, T.ASSURED)
    assert _seed(src_a)["m.f"] == expected
    assert _seed(src_b)["m.f"] == expected


def test_non_taintstate_attribute_level_is_no_opinion() -> None:
    # A dynamic value via a non-TaintState attribute (cfg.GUARDED) must NOT be
    # read as a level — its runtime value is unknown -> fail-closed.
    out = _seed(
        "import cfg\nfrom wardline.decorators import trust_boundary\n"
        "@trust_boundary(to_level=cfg.GUARDED)\ndef v(x):\n    return x\n"
    )
    assert out["m.v"] is None


def test_from_wardline_import_decorators_attribute_form() -> None:
    out = _seed("from wardline import decorators\n@decorators.external_boundary\ndef read(p):\n    return p\n")
    assert out["m.read"] == FunctionTaint(T.EXTERNAL_RAW, T.EXTERNAL_RAW)


def test_positional_level_arg_is_no_opinion() -> None:
    # The real decorators are keyword-only; a positional form is malformed source
    # and must read as fail-closed (no opinion), never a silent under-read.
    out = _seed("from wardline.decorators import trust_boundary\n@trust_boundary('ASSURED')\ndef v(x):\n    return x\n")
    assert out["m.v"] is None


def test_fingerprint_is_version_derived_and_stable() -> None:
    p = DecoratorTaintSourceProvider()
    assert p.fingerprint() == f"decorator-vocab:{REGISTRY_VERSION}"
    assert p.fingerprint() == p.fingerprint()


def test_star_import_materialises_vocabulary_decorators() -> None:
    # `from wardline.decorators import *` brings the trust decorators in by name.
    # The provider resolves them only if build_import_alias_map materialised the
    # statically-known vocabulary exports (T1.2) — without executing the target.
    from wardline.scanner.taint.decorator_provider import vocabulary_star_exports

    tree = ast.parse(
        "from wardline.decorators import *\n@trust_boundary(to_level='ASSURED')\ndef v(p):\n    return p\n"
    )
    alias_map = build_import_alias_map(tree, module_path="m", star_exports=vocabulary_star_exports())
    entities = discover_file_entities(tree, module="m", path="m.py")
    ctx = SeedContext(module="m", alias_map=alias_map)
    provider = DecoratorTaintSourceProvider()
    out = {e.qualname: provider.taint_for(e, ctx).taint for e in entities}
    assert out["m.v"] == FunctionTaint(T.EXTERNAL_RAW, T.ASSURED)


def test_star_imported_trust_boundary_fires_end_to_end(tmp_path) -> None:
    # End-to-end: a no-rejection @trust_boundary reached via star-import must fire
    # PY-WL-102 (was a silent FN — the star import was dropped on the floor).
    from wardline.core.run import run_scan

    pkg = tmp_path / "proj"
    pkg.mkdir()
    (pkg / "m.py").write_text(
        "from wardline.decorators import *\n@trust_boundary(to_level='ASSURED')\ndef v(p):\n    return p\n"
    )
    result = run_scan(pkg)
    active = {f.rule_id for f in result.findings if f.suppressed.value == "active"}
    # The boundary-integrity family partitions (wardline-718048a518): the bare
    # ``return p`` shape is PY-WL-119's domain, every other no-rejection shape is
    # PY-WL-102's. Either member firing proves the star-imported decorator was
    # seeded — the FN this test guards is the EMPTY intersection.
    assert {"PY-WL-102", "PY-WL-119"} & active, "star-imported @trust_boundary was not seeded"


# ── Coverage: fail-closed arms reached only by unusual / malformed decorator
# shapes. Each asserts the no-opinion (None) outcome the engine relies on. ──


def test_subscript_decorator_is_no_opinion() -> None:
    # ``@registry['x']`` — the decorator node is a Subscript, not a Name/Attribute
    # chain, so _dotted_name returns None and the decorator resolves to no opinion.
    out = _seed("registry = {}\n@registry['x']\ndef f():\n    return 1\n")
    assert out["m.f"] is None


def test_unexpected_keyword_fails_closed_even_with_valid_level_arg() -> None:
    # Builtin level-bearing decorators are keyword-only with a fixed signature. A
    # malformed call must not be seeded from the valid-looking level beside it.
    out = _seed(
        "from wardline.decorators import trust_boundary\n"
        "@trust_boundary(other=1, to_level='ASSURED')\ndef v(x):\n    return x\n"
    )
    assert out["m.v"] is None


def test_invalid_taintstate_token_is_no_opinion() -> None:
    # A string token that is NOT a canonical TaintState (TaintState(token) raises) ->
    # fail-closed (None), never a silent mis-read.
    out = _seed("from wardline.decorators import trusted\n@trusted(level='NOPE')\ndef f():\n    return 1\n")
    assert out["m.f"] is None


def test_wardline_prefixed_but_unknown_decorator_is_no_opinion() -> None:
    # A name under the wardline.decorators prefix that is NOT a REGISTRY decorator
    # (``wardline.decorators.bogus``) — canonical not in REGISTRY -> no opinion.
    out = _seed("import wardline.decorators\n@wardline.decorators.bogus\ndef f():\n    return 1\n")
    assert out["m.f"] is None


# ── Security: builtin marker decorators must resolve to the REAL exports only.
# A scanned project shipping a no-op ``trusted``/``trust_boundary`` under a builtin
# marker root (``wardline``/``weft_markers``) must NOT anchor trust — that would
# suppress real taint→sink flows (false GREEN). ──


def test_builtin_decorator_requires_exact_known_export() -> None:
    # Nested-path spoof: prefix + final-segment matching would accept this. Builtins
    # must be EXACT public/implementation exports, so a wardline.decorators.evil.trusted
    # path is rejected → no opinion (the @trusted spoof does not anchor trust).
    out = _seed("from wardline.decorators import evil\n@evil.trusted\ndef f():\n    return 1\n")
    assert out["m.f"] is None


def test_weft_markers_nested_path_spoof_rejected() -> None:
    # Same nested-path spoof under the weft_markers root.
    out = _seed("from weft_markers import evil\n@evil.trusted\ndef f():\n    return 1\n")
    assert out["m.f"] is None


def test_builtin_decorator_fails_closed_when_project_shadows_wardline() -> None:
    # A scanned project that defines its own ``wardline.decorators`` controls what
    # this import means at runtime, so the default provider must NOT anchor it as the
    # real marker package — fail closed (no opinion) for the spoofed @trusted.
    out = _seed(
        "from wardline.decorators import trusted\n@trusted\ndef f():\n    return 1\n",
        project_modules=frozenset({"app", "wardline", "wardline.decorators"}),
    )
    assert out["m.f"] is None


def test_builtin_decorator_fails_closed_when_project_shadows_weft_markers() -> None:
    # GENERALIZATION (the gap the codex PR left open): a project shadowing
    # ``weft_markers`` must also fail closed for weft_markers builtin markers.
    out = _seed(
        "from weft_markers import trusted\n@trusted\ndef f():\n    return 1\n",
        project_modules=frozenset({"app", "weft_markers"}),
    )
    assert out["m.f"] is None


def test_shadowing_one_root_does_not_disable_the_other() -> None:
    # Per-root, not a global bool: shadowing ``wardline`` must NOT stop a legitimate
    # ``weft_markers`` builtin marker from anchoring (and vice versa).
    out = _seed(
        "from weft_markers import trusted\n@trusted\ndef f():\n    return 1\n",
        project_modules=frozenset({"app", "wardline"}),
    )
    assert out["m.f"] == FunctionTaint(T.INTEGRAL, T.INTEGRAL)


def test_builtin_decorator_accepts_implementation_module_export() -> None:
    # Legit impl-module form: ``from wardline.decorators.trust import trusted`` still
    # anchors (one of the two exact accepted exports).
    out = _seed("from wardline.decorators.trust import trusted\n@trusted\ndef f():\n    return 1\n")
    assert out["m.f"] == FunctionTaint(T.INTEGRAL, T.INTEGRAL)


def test_builtin_decorator_rejects_weft_markers_ghost_implementation_module_export() -> None:
    # REVERSED (declaration-surface-v2 P9): the accepted-export table is ROOT-SPECIFIC.
    # ``wardline.decorators`` genuinely re-exports from ``wardline/decorators/trust.py``,
    # so BOTH ``wardline.decorators.trusted`` and ``wardline.decorators.trust.trusted``
    # are real. ``weft_markers`` ships a single ``__init__.py`` and has NO
    # ``weft_markers.trust`` submodule — verified in packages/weft-markers/src — so
    # ``weft_markers.trust.trusted`` is a GHOST export that cannot resolve at runtime.
    # Seeding trust off a path that does not exist is a false green, so it must NOT
    # anchor. The PY-WL-110 / PY-WL-114 silence twins live in the two rule test modules.
    out = _seed("from weft_markers.trust import trusted\n@trusted\ndef f():\n    return 1\n")
    assert out["m.f"] is None


def test_unrelated_nested_module_does_not_trip_shadow() -> None:
    # Scoping: only TOP-LEVEL module names trigger a shadow. ``app.wardline_helper``
    # and ``myweft.wardline`` are NOT the builtin roots, so a legit @trusted anchors.
    out = _seed(
        "from wardline.decorators import trusted\n@trusted\ndef f():\n    return 1\n",
        project_modules=frozenset({"app.wardline_helper", "myweft.wardline"}),
    )
    assert out["m.f"] == FunctionTaint(T.INTEGRAL, T.INTEGRAL)


def test_fingerprint_for_project_differs_between_shadowed_and_unshadowed() -> None:
    # Cache-key hardening: the project-aware fingerprint must differ across shadow
    # states (so a TRUSTED summary is never reused across them), and per-root so the
    # two roots do not collide. Unshadowed returns the bare (stability-preserving) value.
    provider = DecoratorTaintSourceProvider()
    bare = provider.fingerprint()
    unshadowed = provider.fingerprint_for_project(frozenset({"app"}))
    shadow_wardline = provider.fingerprint_for_project(frozenset({"app", "wardline"}))
    shadow_weft = provider.fingerprint_for_project(frozenset({"app", "weft_markers"}))
    assert unshadowed == bare
    assert shadow_wardline != bare
    assert shadow_weft != bare
    assert shadow_wardline != shadow_weft  # per-root, not a single bool
