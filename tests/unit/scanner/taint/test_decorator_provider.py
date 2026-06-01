# tests/unit/scanner/taint/test_decorator_provider.py
from __future__ import annotations

import ast

from wardline.core.registry import REGISTRY_VERSION
from wardline.core.taints import TaintState as T
from wardline.scanner.ast_primitives import build_import_alias_map
from wardline.scanner.index import discover_file_entities
from wardline.scanner.taint.decorator_provider import DecoratorTaintSourceProvider
from wardline.scanner.taint.provider import FunctionTaint, SeedContext


def _seed(src: str, *, module: str = "m") -> dict[str, FunctionTaint | None]:
    """Run the provider over every function entity in *src*; map qualname -> result."""
    tree = ast.parse(src)
    alias_map = build_import_alias_map(tree, module_path=module)
    entities = discover_file_entities(tree, module=module, path="m.py")
    ctx = SeedContext(module=module, alias_map=alias_map)
    provider = DecoratorTaintSourceProvider()
    # .taint: assertions here compare the declared FunctionTaint; the unprovable-
    # boundary signal (Track 2 T2.4) is exercised separately in tests/grammar/.
    return {e.qualname: provider.taint_for(e, ctx).taint for e in entities}


def test_external_boundary_from_import() -> None:
    out = _seed("from wardline.decorators import external_boundary\n@external_boundary\ndef read(p):\n    return p\n")
    assert out["m.read"] == FunctionTaint(T.EXTERNAL_RAW, T.EXTERNAL_RAW)


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


def test_trusted_disallowed_level_is_no_opinion() -> None:
    out = _seed("from wardline.decorators import trusted\n@trusted(level='GUARDED')\ndef f():\n    return 1\n")
    assert out["m.f"] is None


def test_trusted_dynamic_level_is_no_opinion() -> None:
    # A non-literal level (a Name) cannot be read statically -> fail-closed.
    out = _seed("from wardline.decorators import trusted\nLV = 'ASSURED'\n@trusted(level=LV)\ndef f():\n    return 1\n")
    assert out["m.f"] is None


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
    assert "PY-WL-102" in active, "star-imported @trust_boundary was not seeded"


# ── Coverage: fail-closed arms reached only by unusual / malformed decorator
# shapes. Each asserts the no-opinion (None) outcome the engine relies on. ──


def test_subscript_decorator_is_no_opinion() -> None:
    # ``@registry['x']`` — the decorator node is a Subscript, not a Name/Attribute
    # chain, so _dotted_name returns None and the decorator resolves to no opinion.
    out = _seed("registry = {}\n@registry['x']\ndef f():\n    return 1\n")
    assert out["m.f"] is None


def test_non_matching_keyword_is_skipped_before_level_arg() -> None:
    # A decorator with an UNRELATED keyword before to_level: the kw loop must skip the
    # non-matching keyword (118->117) and still read to_level correctly.
    out = _seed(
        "from wardline.decorators import trust_boundary\n"
        "@trust_boundary(other=1, to_level='ASSURED')\ndef v(x):\n    return x\n"
    )
    assert out["m.v"] == FunctionTaint(T.EXTERNAL_RAW, T.ASSURED)


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
