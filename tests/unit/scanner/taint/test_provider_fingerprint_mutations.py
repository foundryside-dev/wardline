"""P8 — the provider fingerprint moves iff the declaration surface moves.

Mutation table: every component of a grammar's identity (name, prefix, group,
builtin flag, level-arg schema, seed body, order) must change the fingerprint.
Reformat stability: cosmetic re-authoring of an identical seed must NOT change
it. The builtin literal is pinned so a REGISTRY_VERSION drift in S0 is loud."""

from __future__ import annotations

import pathlib
import subprocess
import sys

import pytest

from wardline.core.taints import TaintState
from wardline.scanner.grammar import BoundaryType, LevelArg
from wardline.scanner.taint.decorator_provider import (
    DecoratorTaintSourceProvider,
    _canonical_json,
    _grammar_digest,
    _seed_identity,
)
from wardline.scanner.taint.provider import FunctionTaint

_ALLOWED = frozenset({TaintState.GUARDED, TaintState.ASSURED})


def _seed(levels):
    return FunctionTaint(TaintState.EXTERNAL_RAW, levels["to_level"])


def _bt(
    name="sanitized",
    prefix="myproj.trust",
    group=1,
    arg="to_level",
    allowed=_ALLOWED,
    default=None,
    seed=_seed,
    builtin=False,
    level_args=None,
):
    return BoundaryType(
        canonical_name=name,
        module_prefix=prefix,
        group=group,
        level_args=level_args if level_args is not None else (LevelArg(arg, allowed, default),),
        seed=seed,
        builtin=builtin,
    )


def _fp(*bts) -> str:
    return DecoratorTaintSourceProvider(boundary_types=tuple(bts)).fingerprint()


BASE = _bt()

MUTATIONS = {
    "canonical_name": _bt(name="cleansed"),
    "module_prefix": _bt(prefix="otherproj.trust"),
    "group": _bt(group=2),
    "builtin_flag": _bt(builtin=True),
    "arg_name": _bt(arg="level"),
    "allowed_set": _bt(allowed=frozenset({TaintState.ASSURED})),
    "default": _bt(default=TaintState.GUARDED),
}


@pytest.mark.parametrize("label", sorted(MUTATIONS))
def test_mutation_changes_fingerprint(label: str) -> None:
    assert _fp(BASE) != _fp(MUTATIONS[label]), f"mutating {label} did not move the fingerprint"


def test_seed_body_mutation_changes_fingerprint() -> None:
    def other_seed(levels):
        return FunctionTaint(TaintState.UNKNOWN_RAW, levels["to_level"])

    assert _fp(BASE) != _fp(_bt(seed=other_seed))


def test_boundary_order_changes_fingerprint() -> None:
    a, b = _bt(name="alpha"), _bt(name="beta")
    assert _fp(a, b) != _fp(b, a)


def test_level_arg_order_changes_fingerprint() -> None:
    # The level-arg schema is ORDERED (it is a tuple on BoundaryType), so a
    # re-ordering is a different declaration and must move the digest.
    first = LevelArg("from_level", _ALLOWED, None)
    second = LevelArg("to_level", _ALLOWED, None)
    assert _fp(_bt(level_args=(first, second))) != _fp(_bt(level_args=(second, first)))


def test_finite_mutation_table_has_distinct_fingerprints() -> None:
    fps = {_fp(BASE)} | {_fp(m) for m in MUTATIONS.values()} | {_fp(_bt(name="alpha"), _bt(name="beta"))}
    assert len(fps) == len(MUTATIONS) + 2


def test_adversarial_nul_delimiter_pairs_do_not_collide() -> None:
    # These would be ambiguous under delimiter-joined strings.
    left = _bt(name="a\0b", prefix="c")
    right = _bt(name="a", prefix="b\0c")
    assert _fp(left) != _fp(right)


# The pre-Task-13 preimage joined boundary-type parts with "\x00", terminated each
# record with "\x01", joined the seed identity with "|", and joined each level-arg
# triple with ":". EVERY one of those separators is a live ambiguity: for any
# separator D, ("a"+D+"b", "c") and ("a", "b"+D+"c") join to the same preimage. The
# sweep proves the JSON preimage separates the whole class, not just the one
# separator that happened to ship at this layer.
@pytest.mark.parametrize("delimiter", [":", "\0", "\x01", "|", ",", "="])
def test_delimiter_shift_between_adjacent_fields_does_not_collide(delimiter: str) -> None:
    left = _bt(name="a" + delimiter + "b", prefix="c")
    right = _bt(name="a", prefix="b" + delimiter + "c")
    assert _fp(left) != _fp(right)


def test_level_arg_arity_shift_does_not_collide() -> None:
    """One crafted ``arg_name`` reproducing a TWO-``LevelArg`` record byte for byte.

    Under the old ``f"{arg_name}:{allowed}:{default}"`` triple joined by ``"\\x00"``,
    a single arg named ``a:GUARDED:\\x00b`` renders exactly as the two args ``a`` and
    ``b``. This is the colon ambiguity of the level-arg layer, and it changes the
    ARITY of the schema — a strictly worse collision than a field shift.
    """
    one = _bt(level_args=(LevelArg("a:GUARDED:\x00b", frozenset({TaintState.GUARDED}), None),))
    two = _bt(
        level_args=(
            LevelArg("a", frozenset({TaintState.GUARDED}), None),
            LevelArg("b", frozenset({TaintState.GUARDED}), None),
        )
    )
    assert _fp(one) != _fp(two)


def test_seed_module_qualname_delimiter_shift_does_not_collide() -> None:
    a = _compile_seed('    return FunctionTaint(TaintState.EXTERNAL_RAW, levels["to_level"])\n')
    b = _compile_seed('    return FunctionTaint(TaintState.EXTERNAL_RAW, levels["to_level"])\n')
    a.__module__, a.__qualname__ = "x|y", "z"
    b.__module__, b.__qualname__ = "x", "y|z"
    assert _fp(_bt(seed=a)) != _fp(_bt(seed=b))


def _compile_seed(body: str, filename: str = "<generated>", lead: str = ""):
    ns = {"FunctionTaint": FunctionTaint, "TaintState": TaintState}
    exec(compile(lead + "def seed(levels):\n" + body, filename, "exec"), ns)
    return ns["seed"]


def test_reformat_stability_of_an_identical_seed() -> None:
    a = _compile_seed('    return FunctionTaint(TaintState.EXTERNAL_RAW, levels["to_level"])\n')
    b = _compile_seed(
        '    # layout-only change\n    return FunctionTaint( TaintState.EXTERNAL_RAW, levels["to_level"] )\n'
    )
    assert _fp(_bt(seed=a)) == _fp(_bt(seed=b))


def test_filename_does_not_move_the_fingerprint() -> None:
    # co_filename is not part of the declaration surface: the same grammar loaded
    # from a moved/renamed file must keep its cache.
    body = '    return FunctionTaint(TaintState.EXTERNAL_RAW, levels["to_level"])\n'
    a = _compile_seed(body, filename="/one/place/pack.py")
    b = _compile_seed(body, filename="/another/place/pack.py")
    assert _fp(_bt(seed=a)) == _fp(_bt(seed=b))


def test_first_line_number_does_not_move_the_fingerprint() -> None:
    body = '    return FunctionTaint(TaintState.EXTERNAL_RAW, levels["to_level"])\n'
    a = _compile_seed(body)
    b = _compile_seed(body, lead="\n\n\n")
    assert a.__code__.co_firstlineno != b.__code__.co_firstlineno
    assert _fp(_bt(seed=a)) == _fp(_bt(seed=b))


def test_same_module_qualname_body_mutation_changes_fingerprint() -> None:
    a = _compile_seed('    return FunctionTaint(TaintState.EXTERNAL_RAW, levels["to_level"])\n')
    b = _compile_seed('    return FunctionTaint(TaintState.UNKNOWN_RAW, levels["to_level"])\n')
    assert a.__module__ == b.__module__ and a.__qualname__ == b.__qualname__
    assert _fp(_bt(seed=a)) != _fp(_bt(seed=b))


def test_referenced_global_name_moves_the_fingerprint_with_identical_bytecode() -> None:
    # ``return SAFE`` vs ``return RAW``: identical co_code, identical co_consts —
    # only co_names (and the bound global) differ. This is the case the old
    # docstring named and the one a bytecode-only digest gets wrong.
    ns_a = {"SAFE": FunctionTaint(TaintState.ASSURED, TaintState.ASSURED)}
    ns_b = {"RAW": FunctionTaint(TaintState.UNKNOWN_RAW, TaintState.UNKNOWN_RAW)}
    exec(compile("def seed(levels):\n    return SAFE\n", "<generated>", "exec"), ns_a)
    exec(compile("def seed(levels):\n    return RAW\n", "<generated>", "exec"), ns_b)
    a, b = ns_a["seed"], ns_b["seed"]
    assert a.__code__.co_code == b.__code__.co_code
    assert a.__code__.co_consts == b.__code__.co_consts
    assert _fp(_bt(seed=a)) != _fp(_bt(seed=b))


def test_closure_cell_contents_move_the_fingerprint() -> None:
    # Two seeds off ONE factory: identical bytecode, identical co_freevars, identical
    # module/qualname. Only the CAPTURED value differs, and it decides the seeded
    # taint — so it must move the digest.
    def factory(level):
        def seed(levels):
            return FunctionTaint(level, levels["to_level"])

        return seed

    a, b = factory(TaintState.EXTERNAL_RAW), factory(TaintState.UNKNOWN_RAW)
    assert a.__code__.co_code == b.__code__.co_code
    assert a.__code__.co_freevars == b.__code__.co_freevars == ("level",)
    assert _fp(_bt(seed=a)) != _fp(_bt(seed=b))


_NESTED_BODY = (
    "    def _inner(state):\n"
    "        return state\n"
    '    return FunctionTaint(_inner(TaintState.EXTERNAL_RAW), levels["to_level"])\n'
)


def test_nested_code_reformat_stability() -> None:
    # The nested code object rides in co_consts. repr(co_consts) would embed its
    # memory address AND its source line, so a layout-only edit (or merely a second
    # process) used to move the digest. Structural recursion fixes both.
    a = _compile_seed(_NESTED_BODY)
    b = _compile_seed(
        "    # layout-only change\n"
        "    def _inner(state):\n"
        "\n"
        "        return  state\n"
        '    return FunctionTaint(_inner( TaintState.EXTERNAL_RAW ), levels["to_level"])\n'
    )
    inner_a = [c for c in a.__code__.co_consts if hasattr(c, "co_code")][0]
    inner_b = [c for c in b.__code__.co_consts if hasattr(c, "co_code")][0]
    assert inner_a.co_firstlineno != inner_b.co_firstlineno  # layout really did move
    # The old preimage keyed nested code by repr(co_consts), which carries both the
    # first line AND the object's memory address — unstable across layout AND runs.
    assert repr(a.__code__.co_consts) != repr(b.__code__.co_consts)
    assert _fp(_bt(seed=a)) == _fp(_bt(seed=b))


def test_nested_code_constant_mutation_changes_fingerprint() -> None:
    # Same outer bytecode, same outer names; only a CONSTANT inside the nested code
    # differs. A digest that stops at the top-level code object misses this.
    a = _compile_seed("    def _inner(state):\n        return 41\n    return _inner(levels)\n")
    b = _compile_seed("    def _inner(state):\n        return 42\n    return _inner(levels)\n")
    assert a.__code__.co_code == b.__code__.co_code
    assert _fp(_bt(seed=a)) != _fp(_bt(seed=b))


def test_digest_is_stable_within_the_process_for_an_identical_grammar() -> None:
    assert _fp(BASE) == _fp(_bt())


def test_preimage_carries_no_address_or_source_location() -> None:
    """The preimage must be structural, not ``repr``-of-object.

    A memory address makes the digest differ every PROCESS (so a custom grammar
    never warms its cache), and a filename/line makes it differ on pure layout. Both
    used to leak in through ``repr(co_consts)`` for any seed with nested code.
    """
    seed = _compile_seed(_NESTED_BODY, filename="/some/where/pack.py")
    blob = _canonical_json(_seed_identity(seed))
    assert "0x" not in blob
    assert "/some/where/pack.py" not in blob
    # module and qualname are DISTINCT slots, never one joined string.
    record = _seed_identity(seed)
    assert "module" in record and "qualname" in record


def test_digest_is_identical_in_a_fresh_process() -> None:
    """Cross-process determinism — the property a ``repr``-based preimage breaks."""
    here = str(pathlib.Path(__file__).parent)
    src = (
        "import sys;"
        f"sys.path.insert(0, {here!r});"
        "import test_provider_fingerprint_mutations as T;"
        "from wardline.scanner.taint.decorator_provider import _grammar_digest as D;"
        "print(D((T._bt(seed=T._compile_seed(T._NESTED_BODY)),)))"
    )
    out = subprocess.run(  # noqa: S603
        [sys.executable, "-c", src], capture_output=True, text=True, check=True
    ).stdout.strip()
    assert out == _grammar_digest((_bt(seed=_compile_seed(_NESTED_BODY)),))
    assert len(out) == 64


def test_custom_digest_is_full_sha256() -> None:
    prefix, sep, digest = _fp(BASE).partition("+grammar:")
    assert sep and prefix == "decorator-vocab:wardline-generic-2"
    assert len(digest) == 64
    assert set(digest) <= set("0123456789abcdef")


def test_builtin_fingerprint_literal_is_pinned_for_s0() -> None:
    # S0 must not move the vocabulary version; the S1 generic-3 bump updates this pin.
    assert DecoratorTaintSourceProvider().fingerprint() == "decorator-vocab:wardline-generic-2"
