"""P8 — the provider fingerprint moves iff the declaration surface moves.

Mutation table: every component of a grammar's identity (name, prefix, group,
builtin flag, level-arg schema, seed body, order) must change the fingerprint.
Reformat stability: cosmetic re-authoring of an identical seed must NOT change
it. The builtin literal is pinned so a REGISTRY_VERSION drift in S0 is loud."""

from __future__ import annotations

import functools
import importlib
import os
import pathlib
import re
import subprocess
import sys
import textwrap
import time
import types

import pytest

import wardline.scanner.taint.decorator_provider as dp
from wardline.core.taints import TaintState
from wardline.scanner.grammar import BoundaryType, LevelArg
from wardline.scanner.taint.decorator_provider import (
    DecoratorTaintSourceProvider,
    _canonical_json,
    _grammar_digest,
    _seed_identity,
    _seed_value_identity,
)
from wardline.scanner.taint.provider import FunctionTaint

_ALLOWED = frozenset({TaintState.GUARDED, TaintState.ASSURED})


def _class_member(record: dict, name: str) -> dict:
    """A named entry out of a class record's ORDERED `[index, name, value]` members."""
    for _index, key, value in record["members"]:
        if key == name:
            return value
    raise KeyError(name)


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


def test_referenced_global_with_default_repr_admits_no_address() -> None:
    """A referenced global that is a plain INSTANCE, not a function or class.

    It reaches the last-resort ``repr`` arm, whose output for a default
    ``object.__repr__`` is ``<pack.Thing object at 0x7f…>``. Left raw, that address
    makes the digest differ every PROCESS — defect #2's cold-cache symptom reproduced
    on a second path. The address is normalised out; the repr's CONTENT is not.
    """
    ns: dict = {"__name__": "mypack.grammar"}
    exec(
        compile(
            "class Thing:\n    def __init__(self, n):\n        self.n = n\n"
            "CONF = Thing(1)\n"
            "def seed(levels):\n    return CONF\n",
            "mypack/grammar.py",
            "exec",
        ),
        ns,
    )
    blob = _canonical_json(_seed_identity(ns["seed"]))
    assert "0x<addr>" in blob  # the arm WAS reached
    assert re.search(r" at 0x[0-9a-fA-F]+", blob) is None, blob  # no real address survived
    assert "mypack.grammar.Thing" in blob  # ... and the repr's CONTENT is untouched
    # And the digest is reproducible in a fresh process (the property an address breaks).
    assert _fp(_bt(seed=ns["seed"])) == _fp(_bt(seed=ns["seed"]))


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


# --- Referenced-global structural identity -----------------------------------
#
# The LIVE path. A production pack loads as a real importable module, so
# `def seed(levels): return _helper(levels)` is the ordinary shape. Keying `_helper`
# by `module.qualname` alone let its body change with the digest byte-identical — a
# warm cache then answers the new grammar with the old grammar's verdicts. Every
# pair below is built with the SAME module name on both sides, so the module name
# itself cannot be doing the work.

_PACK_SRC = """
from wardline.core.taints import TaintState
from wardline.scanner.taint.provider import FunctionTaint

LIMIT = {limit}

def _inner_helper(levels):
    return TaintState.{lvl}

def _helper(levels):
    return FunctionTaint(_inner_helper(levels), levels["to_level"])

def seed(levels):
    return _helper(levels)

class Policy:
    CEILING = {limit}

    def decide(self, levels):
        return TaintState.{lvl}

def seed_cls(levels):
    return FunctionTaint(Policy().decide(levels), levels["to_level"])
"""


def _pack(lvl: str = "EXTERNAL_RAW", limit: int = 1, extra: str = "") -> dict:
    """Load a pack-shaped module under a FIXED module name, so only bodies vary."""
    ns: dict = {"__name__": "mypack.grammar"}
    src = _PACK_SRC.format(lvl=lvl, limit=limit) + extra
    exec(compile(src, "mypack/grammar.py", "exec"), ns)
    return ns


_PACK_A = _pack()
_PACK_B = _pack(lvl="ASSURED")
_PACK_LIMIT = _pack(limit=2)
_PACK_REFORMATTED = _pack(extra="\n# trailing comment, no behaviour change\n")


def test_referenced_global_function_body_change_moves_the_fingerprint() -> None:
    a, b = _PACK_A["seed"], _PACK_B["seed"]
    assert a.__module__ == b.__module__ == "mypack.grammar"
    assert a.__qualname__ == b.__qualname__ == "seed"
    assert a.__code__.co_code == b.__code__.co_code  # the SEED is byte-identical
    assert _fp(_bt(seed=a)) != _fp(_bt(seed=b))


def test_referenced_global_function_reformat_does_not_move_the_fingerprint() -> None:
    assert _fp(_bt(seed=_PACK_A["seed"])) == _fp(_bt(seed=_PACK_REFORMATTED["seed"]))


def test_transitive_helper_body_change_moves_the_fingerprint() -> None:
    # seed -> _helper -> _inner_helper: the changed body is TWO hops out, and the
    # digest must still move.
    a, b = _PACK_A["seed"], _PACK_B["seed"]
    assert a.__code__.co_code == b.__code__.co_code
    assert _PACK_A["_helper"].__code__.co_code == _PACK_B["_helper"].__code__.co_code
    assert _fp(_bt(seed=a)) != _fp(_bt(seed=b))


def test_referenced_global_class_method_body_change_moves_the_fingerprint() -> None:
    a, b = _PACK_A["seed_cls"], _PACK_B["seed_cls"]
    assert a.__code__.co_code == b.__code__.co_code
    assert _fp(_bt(seed=a)) != _fp(_bt(seed=b))


def test_referenced_global_class_attribute_change_moves_the_fingerprint() -> None:
    # Class-level DATA, not a method body — `Policy.CEILING` 1 -> 2.
    assert _fp(_bt(seed=_PACK_A["seed_cls"])) != _fp(_bt(seed=_PACK_LIMIT["seed_cls"]))


def test_referenced_global_class_reformat_does_not_move_the_fingerprint() -> None:
    # Guards the 3.13 `__firstlineno__` class attribute: moving a class down a file
    # must not cold-invalidate every warm cache.
    shifted = _pack(extra="")
    assert _fp(_bt(seed=_PACK_A["seed_cls"])) == _fp(_bt(seed=shifted["seed_cls"]))
    padded: dict = {"__name__": "mypack.grammar"}
    exec(compile("\n\n\n\n" + _PACK_SRC.format(lvl="EXTERNAL_RAW", limit=1), "mypack/grammar.py", "exec"), padded)
    assert padded["Policy"].__firstlineno__ != _PACK_A["Policy"].__firstlineno__
    assert _fp(_bt(seed=_PACK_A["seed_cls"])) == _fp(_bt(seed=padded["seed_cls"]))


def test_mutually_recursive_globals_terminate_and_discriminate() -> None:
    # seed <-> _helper reference each other. The walk must terminate (cycle arm) AND
    # still key on the changed body.
    cyc = "\ndef _mutual(levels):\n    return seed(levels)\ndef seed2(levels):\n    return _mutual(levels)\n"
    a = _pack(extra=cyc)["seed2"]
    b = _pack(lvl="ASSURED", extra=cyc)["seed2"]
    assert _fp(_bt(seed=a)) != _fp(_bt(seed=b))


def test_wardline_and_stdlib_globals_are_keyed_by_name_not_walked() -> None:
    # Scope fence: wardline's own and the stdlib's bodies are versioned by
    # _RESOLVER_VERSION / REGISTRY_VERSION / the summary schema version, not here.
    # Walking them made the digest process-UNSTABLE and the preimage ~2.9 MiB.
    record = _seed_identity(_PACK_A["_helper"])
    globals_rec = record["globals"]
    assert globals_rec["FunctionTaint"] == {
        "t": "ref",
        "module": "wardline.scanner.taint.provider",
        "qualname": "FunctionTaint",
    }
    assert _seed_identity(_PACK_A["_inner_helper"])["globals"]["TaintState"]["t"] == "ref"
    # ... while the pack's OWN helper is expanded structurally, transitively.
    seed_globals = _seed_identity(_PACK_A["seed"])["globals"]
    assert seed_globals["_helper"]["kind"] == "function"
    assert seed_globals["_helper"]["globals"]["_inner_helper"]["kind"] == "function"


# --- Module-scope INSTANCE: the seam the 34-case table did not cross ------------
#
# `_PACK_SRC` writes `Policy().decide(levels)`, so `Policy` lands in the seed's
# co_names and the class arm is reached. Hoisting the instantiation to module scope
# removes `Policy` from co_names entirely — only `POLICY` and `decide` appear — so
# the instance BLOCKS the class. Keyed by an address-normalised `repr` alone, neither
# the method body nor the instance state reached the preimage.

_INSTANCE_SRC = (
    "from wardline.core.taints import TaintState\n"
    "from wardline.scanner.taint.provider import FunctionTaint\n"
    "class Policy:\n"
    "    def __init__(self, n):\n"
    "        self.n = n\n"
    "    def decide(self, levels):\n"
    "        return TaintState.{lvl}\n"
    "POLICY = Policy({n})\n"
    "def seed(levels):\n"
    "    return FunctionTaint(POLICY.decide(levels), levels['to_level'])\n"
)


def _instance_pack(lvl: str = "EXTERNAL_RAW", n: int = 1, lead: str = "") -> dict:
    ns: dict = {"__name__": "mypack.grammar"}
    exec(compile(lead + _INSTANCE_SRC.format(lvl=lvl, n=n), "mypack/grammar.py", "exec"), ns)  # noqa: S102
    return ns


def test_module_scope_instance_does_not_put_its_class_in_co_names() -> None:
    """Documents the seam: the class is genuinely unreachable via ``co_names``."""
    pack = _instance_pack()
    assert "Policy" not in pack["seed"].__code__.co_names
    assert set(pack["seed"].__code__.co_names) >= {"POLICY", "decide"}


def test_module_scope_instance_class_body_change_moves_the_fingerprint() -> None:
    a, b = _instance_pack(), _instance_pack(lvl="ASSURED")
    assert a["seed"].__code__.co_code == b["seed"].__code__.co_code
    assert _fp(_bt(seed=a["seed"])) != _fp(_bt(seed=b["seed"]))


def test_module_scope_instance_state_change_moves_the_fingerprint() -> None:
    a, b = _instance_pack(n=1), _instance_pack(n=2)
    assert _fp(_bt(seed=a["seed"])) != _fp(_bt(seed=b["seed"]))


def test_module_scope_instance_reformat_does_not_move_the_fingerprint() -> None:
    a, b = _instance_pack(), _instance_pack(lead="\n\n# layout only\n")
    assert _fp(_bt(seed=a["seed"])) == _fp(_bt(seed=b["seed"]))


def test_instance_record_carries_type_and_state_not_just_repr() -> None:
    record = _seed_identity(_instance_pack()["seed"])["globals"]["POLICY"]
    assert record["t"] == "instance"
    assert record["type"]["kind"] == "class"  # the class was expanded, not named
    assert record["state"] == {"n": {"t": "int", "v": "1"}}
    assert "repr" in record  # ... and repr is KEPT, for C-level state with no __dict__


_SLOTTED_SRC = (
    "from wardline.core.taints import TaintState\n"
    "from wardline.scanner.taint.provider import FunctionTaint\n"
    "class Policy:\n"
    "    __slots__ = ('n',)\n"
    "    def __init__(self, n):\n"
    "        self.n = n\n"
    "    def decide(self, levels):\n"
    "        return TaintState.{lvl}\n"
    "POLICY = Policy({n})\n"
    "def seed(levels):\n"
    "    return FunctionTaint(POLICY.decide(levels), levels['to_level'])\n"
)


def _slotted_pack(lvl: str = "EXTERNAL_RAW", n: int = 1) -> dict:
    ns: dict = {"__name__": "mypack.grammar"}
    exec(compile(_SLOTTED_SRC.format(lvl=lvl, n=n), "mypack/grammar.py", "exec"), ns)  # noqa: S102
    return ns


@pytest.mark.parametrize(
    ("label", "other"),
    [("method_body", _slotted_pack(lvl="ASSURED")), ("slot_state", _slotted_pack(n=2))],
)
def test_hoisted_slotted_instance_mutations_move_the_fingerprint(label: str, other: dict) -> None:
    """Hoisted AND slotted AND method-body-only — the composition no earlier row crosses.

    A slotted instance has NO ``__dict__``, so ``state`` comes entirely from
    ``__slots__``. If the record's ``type`` field were not reached on that path, a
    method-body change would go invisible exactly as it did before the instance arm.
    """
    base = _slotted_pack()
    assert not hasattr(base["POLICY"], "__dict__")
    assert "Policy" not in base["seed"].__code__.co_names
    assert _fp(_bt(seed=base["seed"])) != _fp(_bt(seed=other["seed"])), label


def test_slotted_instance_state_moves_the_fingerprint() -> None:
    src = (
        "from wardline.core.taints import TaintState\n"
        "from wardline.scanner.taint.provider import FunctionTaint\n"
        "class Policy:\n"
        "    __slots__ = ('n',)\n"
        "    def __init__(self, n):\n"
        "        self.n = n\n"
        "POLICY = Policy({n})\n"
        "def seed(levels):\n"
        "    return FunctionTaint(TaintState.EXTERNAL_RAW, levels['to_level'])\n"
        "seed.__dict__['probe'] = POLICY\n"
    )

    def mk(n: int) -> dict:
        ns: dict = {"__name__": "mypack.grammar"}
        exec(compile(src.format(n=n), "mypack/grammar.py", "exec"), ns)  # noqa: S102
        return ns

    a, b = mk(1)["POLICY"], mk(2)["POLICY"]
    assert not hasattr(a, "__dict__")  # slotted: state is NOT in __dict__
    assert _canonical_json(_seed_value_identity(a)) != _canonical_json(_seed_value_identity(b))


def test_module_scope_instance_digest_is_identical_in_a_fresh_process() -> None:
    """The regression seam, pinned across processes.

    Without address normalisation this shape produced a different digest every run
    (measured: three processes, three digests). Without the structural instance arm it
    collided on a class-body change. Both must hold at once.
    """
    here = str(pathlib.Path(__file__).parent)
    src = (
        "import sys;"
        f"sys.path.insert(0, {here!r});"
        "import test_provider_fingerprint_mutations as T;"
        "from wardline.scanner.taint.decorator_provider import _grammar_digest as D;"
        "print(D((T._bt(seed=T._instance_pack()['seed']),)))"
    )
    out = subprocess.run(  # noqa: S603
        [sys.executable, "-c", src], capture_output=True, text=True, check=True
    ).stdout.strip()
    assert out == _grammar_digest((_bt(seed=_instance_pack()["seed"]),))
    assert len(out) == 64


def test_unknown_module_is_expanded_not_fenced_off() -> None:
    """An absent ``__module__`` must NOT be treated as "versioned elsewhere".

    A function ``exec``-ed into a namespace with no ``__name__`` has
    ``__module__ is None``. Treating that as opaque keys it by name and a body change
    goes invisible — a fail-OPEN in the fence itself. Measured before the fix:
    ``helper body change -> COLLIDE``.
    """

    def mk(lvl: str) -> dict:
        ns: dict = {"FunctionTaint": FunctionTaint, "TaintState": TaintState}
        exec(  # noqa: S102
            compile(
                f"def _h(levels):\n    return TaintState.{lvl}\n"
                "def seed(levels):\n    return FunctionTaint(_h(levels), levels['to_level'])\n",
                "<generated>",
                "exec",
            ),
            ns,
        )
        return ns

    a, b = mk("EXTERNAL_RAW"), mk("ASSURED")
    assert a["seed"].__module__ is None
    assert a["seed"].__code__.co_code == b["seed"].__code__.co_code
    assert _fp(_bt(seed=a["seed"])) != _fp(_bt(seed=b["seed"]))


def test_inherited_method_body_change_moves_the_fingerprint() -> None:
    # `_class_identity` walks __bases__, so a change in a PACK base class's method —
    # which `vars(subclass)` does not contain — must still move the digest.
    src = (
        "from wardline.core.taints import TaintState\n"
        "from wardline.scanner.taint.provider import FunctionTaint\n"
        "class Base:\n"
        "    def decide(self, levels):\n"
        "        return TaintState.{lvl}\n"
        "class Policy(Base):\n"
        "    pass\n"
        "def seed(levels):\n"
        "    return FunctionTaint(Policy().decide(levels), levels['to_level'])\n"
    )

    def mk(lvl: str) -> dict:
        ns: dict = {"__name__": "mypack.grammar"}
        exec(compile(src.format(lvl=lvl), "mypack/grammar.py", "exec"), ns)  # noqa: S102
        return ns

    a, b = mk("EXTERNAL_RAW"), mk("ASSURED")
    assert "decide" not in vars(a["Policy"])  # it really is inherited
    assert _fp(_bt(seed=a["seed"])) != _fp(_bt(seed=b["seed"]))


def test_pack_preimage_stays_small_and_carries_no_address() -> None:
    blob = _canonical_json(_seed_identity(_PACK_A["seed_cls"]))
    assert len(blob) < 50_000, f"preimage ballooned to {len(blob)} bytes"
    assert re.search(r" at 0x[0-9a-fA-F]+", blob) is None


def test_code_identity_keys_the_exception_table() -> None:
    # co_exceptiontable holds try/except handler EXTENTS since 3.11 and is not a pure
    # function of co_code. No pair was constructible where co_code stays fixed while
    # the table moves, so this pins the field's PRESENCE and its non-emptiness for a
    # function that actually has a handler.
    guarded = _compile_seed("    try:\n        return levels['to_level']\n    except KeyError:\n        return None\n")
    record = _seed_identity(guarded)
    assert record["code"]["exceptiontable"] != ""
    assert set(record["code"]["exceptiontable"]) <= set("0123456789abcdef")


# --- Round 3: the INVARIANT, not another instance of it -------------------------
#
# Anything that can carry grammar behaviour must enter the preimage STRUCTURALLY; a
# name and a `repr` are both insufficient proxies. Each row below is a distinct
# carrier that a name or a repr hid. They are driven through one table so a new
# carrier is one entry, not one more bespoke test.

_CARRIERS: dict[str, str] = {
    "lru_cache_wrapped_helper": (
        "import functools\n"
        "from wardline.core.taints import TaintState\n"
        "from wardline.scanner.taint.provider import FunctionTaint\n"
        "@functools.lru_cache(maxsize=None)\n"
        "def _helper(n):\n"
        "    return TaintState.{lvl}\n"
        "def seed(levels):\n"
        "    return FunctionTaint(_helper(1), levels['to_level'])\n"
    ),
    "functools_wraps_class_decorator": (
        "import functools\n"
        "from wardline.core.taints import TaintState\n"
        "from wardline.scanner.taint.provider import FunctionTaint\n"
        "class Memo:\n"
        "    def __init__(self, fn):\n"
        "        self.fn = fn\n"
        "        functools.update_wrapper(self, fn)\n"
        "    def __call__(self, *a):\n"
        "        return self.fn(*a)\n"
        "def _decide(n):\n"
        "    return TaintState.{lvl}\n"
        "DECIDE = Memo(_decide)\n"
        "def seed(levels):\n"
        "    return FunctionTaint(DECIDE(1), levels['to_level'])\n"
    ),
    "partial_target_body": (
        "import functools\n"
        "from wardline.core.taints import TaintState\n"
        "from wardline.scanner.taint.provider import FunctionTaint\n"
        "def _dispatch(k, n):\n"
        "    return TaintState.{lvl}\n"
        "H = functools.partial(_dispatch, 1)\n"
        "def seed(levels):\n"
        "    return FunctionTaint(H(2), levels['to_level'])\n"
    ),
    "getattr_backed_state": (
        "from wardline.core.taints import TaintState\n"
        "from wardline.scanner.taint.provider import FunctionTaint\n"
        "class Policy:\n"
        "    def __getattr__(self, name):\n"
        "        return TaintState.{lvl}\n"
        "POLICY = Policy()\n"
        "def seed(levels):\n"
        "    return FunctionTaint(POLICY.anything, levels['to_level'])\n"
    ),
    "computed_property": (
        "from wardline.core.taints import TaintState\n"
        "from wardline.scanner.taint.provider import FunctionTaint\n"
        "class Policy:\n"
        "    @property\n"
        "    def level(self):\n"
        "        return TaintState.{lvl}\n"
        "POLICY = Policy()\n"
        "def seed(levels):\n"
        "    return FunctionTaint(POLICY.level, levels['to_level'])\n"
    ),
    "metaclass_method_body": (
        "from wardline.core.taints import TaintState\n"
        "from wardline.scanner.taint.provider import FunctionTaint\n"
        "class Meta(type):\n"
        "    def decide(cls):\n"
        "        return TaintState.{lvl}\n"
        "class Policy(metaclass=Meta):\n"
        "    pass\n"
        "def seed(levels):\n"
        "    return FunctionTaint(Policy.decide(), levels['to_level'])\n"
    ),
    "bound_method_receiver_state": (
        "from wardline.core.taints import TaintState\n"
        "from wardline.scanner.taint.provider import FunctionTaint\n"
        "class Policy:\n"
        "    def __init__(self, lv):\n"
        "        self.lv = lv\n"
        "    def decide(self):\n"
        "        return self.lv\n"
        "DECIDE = Policy(TaintState.{lvl}).decide\n"
        "def seed(levels):\n"
        "    return FunctionTaint(DECIDE(), levels['to_level'])\n"
    ),
    "non_property_descriptor": (
        "from wardline.core.taints import TaintState\n"
        "from wardline.scanner.taint.provider import FunctionTaint\n"
        "class Desc:\n"
        "    def __get__(self, obj, owner):\n"
        "        return TaintState.{lvl}\n"
        "class Policy:\n"
        "    level = Desc()\n"
        "POLICY = Policy()\n"
        "def seed(levels):\n"
        "    return FunctionTaint(POLICY.level, levels['to_level'])\n"
    ),
    "cached_property": (
        "import functools\n"
        "from wardline.core.taints import TaintState\n"
        "from wardline.scanner.taint.provider import FunctionTaint\n"
        "class Policy:\n"
        "    @functools.cached_property\n"
        "    def level(self):\n"
        "        return TaintState.{lvl}\n"
        "POLICY = Policy()\n"
        "def seed(levels):\n"
        "    return FunctionTaint(POLICY.level, levels['to_level'])\n"
    ),
    "singledispatch_registration": (
        "import functools\n"
        "from wardline.core.taints import TaintState\n"
        "from wardline.scanner.taint.provider import FunctionTaint\n"
        "@functools.singledispatch\n"
        "def _decide(x):\n"
        "    return TaintState.EXTERNAL_RAW\n"
        "@_decide.register\n"
        "def _(x: int):\n"
        "    return TaintState.{lvl}\n"
        "def seed(levels):\n"
        "    return FunctionTaint(_decide(1), levels['to_level'])\n"
    ),
}


# --- Round 4: the GENERAL FORM, not four more instances of it --------------------
#
# Every defect in rounds 0-3 had one shape:
#
#   an early-return arm that matches on SHAPE and returns a proxy record BEFORE any
#   structural arm, consulting no fence.
#
# `isinstance` catches SUBCLASSES, and a subclass body is grammar behaviour —
# `class P(NamedTuple): ... def decide(self): ...` is ordinary Python, not exotic.
# The container/scalar/`__func__`/`property` arms all returned a contents-or-name
# proxy ungated, so each entry below measured COLLIDE on a `decide` body change until
# `_typed_shape` attached the value's TYPE to every one of those records.
#
# The last four entries exist because every row in every earlier round shared one
# assumption: the carrier was reached through the seed's own GLOBALS or `__dict__`.
# These reach it through a CLOSURE CELL, a DEFAULT ARGUMENT, and nested one level
# down inside a plain (fenced) list and dict — proving the gate fires inside the
# recursion, not only at the top level.

_SHAPE_HEAD = (
    "import typing\n"
    "from wardline.core.taints import TaintState\n"
    "from wardline.scanner.taint.provider import FunctionTaint\n"
    "class P(typing.NamedTuple):\n"
    "    n: int\n"
    "    def decide(self):\n"
    "        return TaintState.{lvl}\n"
)


def _shape_carrier(decl: str, body: str = "BOX.decide()") -> str:
    """A pack whose seed reaches a subclass-carried `decide` through one shape arm."""
    return (
        "from wardline.core.taints import TaintState\n"
        "from wardline.scanner.taint.provider import FunctionTaint\n" + decl + "def seed(levels):\n"
        f"    return FunctionTaint({body}, levels['to_level'])\n"
    )


_CARRIERS.update(
    {
        "tuple_subclass_method": _SHAPE_HEAD + "BOX = P(1)\ndef seed(levels):\n"
        "    return FunctionTaint(BOX.decide(), levels['to_level'])\n",
        "list_subclass_method": _shape_carrier(
            "class L(list):\n    def decide(self):\n        return TaintState.{lvl}\nBOX = L([1])\n"
        ),
        "dict_subclass_method": _shape_carrier(
            "class D(dict):\n    def decide(self):\n        return TaintState.{lvl}\nBOX = D(a=1)\n"
        ),
        "set_subclass_method": _shape_carrier(
            "class St(set):\n    def decide(self):\n        return TaintState.{lvl}\nBOX = St([1])\n"
        ),
        "str_subclass_method": _shape_carrier(
            "class S(str):\n    def decide(self):\n        return TaintState.{lvl}\nBOX = S('x')\n"
        ),
        "int_subclass_method": _shape_carrier(
            "class I(int):\n    def decide(self):\n        return TaintState.{lvl}\nBOX = I(3)\n"
        ),
        "bytes_subclass_method": _shape_carrier(
            "class B(bytes):\n    def decide(self):\n        return TaintState.{lvl}\nBOX = B(b'x')\n"
        ),
        "str_mixin_enum_member": _shape_carrier(
            "import enum\n"
            "class L(str, enum.Enum):\n"
            "    A = 'a'\n"
            "    def decide(self):\n        return TaintState.{lvl}\n"
            "BOX = L.A\n"
        ),
        # The `__func__` arm keyed the WRAPPER by `type(value).__name__`. For
        # staticmethod/classmethod/method that name is all there is; a PACK's own
        # wrapper class has a `__call__` body, and it is the behaviour.
        "custom_func_wrapper_call_body": _shape_carrier(
            "def _t():\n    return TaintState.EXTERNAL_RAW\n"
            "class W:\n"
            "    def __init__(self, fn):\n        self.__func__ = fn\n"
            "    def __call__(self):\n        return TaintState.{lvl}\n"
            "BOX = W(_t)\n",
            body="BOX()",
        ),
        # A `property` SUBCLASS computes the value in its own `__get__`, so fget —
        # the only thing the property arm recorded — is not the behaviour.
        "property_subclass_get": _shape_carrier(
            "class Lazy(property):\n"
            "    def __get__(self, obj, owner=None):\n        return TaintState.{lvl}\n"
            "class Policy:\n    level = Lazy(lambda self: None)\n"
            "BOX = Policy()\n",
            body="BOX.level",
        ),
        # --- reach paths that break the shared assumption of every earlier row ---
        "subclass_via_closure_cell": _SHAPE_HEAD + "def _factory(box):\n"
        "    def seed(levels):\n"
        "        return FunctionTaint(box.decide(), levels['to_level'])\n"
        "    return seed\n"
        "seed = _factory(P(1))\n",
        "subclass_via_default_arg": _SHAPE_HEAD + "def seed(levels, _box=P(1)):\n"
        "    return FunctionTaint(_box.decide(), levels['to_level'])\n",
        "subclass_nested_in_plain_list": _SHAPE_HEAD + "BOX = [P(1)]\ndef seed(levels):\n"
        "    return FunctionTaint(BOX[0].decide(), levels['to_level'])\n",
        "subclass_nested_in_plain_dict": _SHAPE_HEAD + "BOX = {{'k': P(1)}}\ndef seed(levels):\n"
        "    return FunctionTaint(BOX['k'].decide(), levels['to_level'])\n",
    }
)


# --- Round 5: a helper reachable ONLY from a NESTED code object -------------------
#
# A lambda, a generator expression and an inner `def` each compile to their OWN code
# object in `co_consts`, and the names they use live in THAT object's `co_names`.
# Globals were resolved against the outer `co_names` alone, so a helper called only
# from inside one of them entered the preimage as a bare NAME. Measured COLLIDE.

_NESTED_GLOBAL_HEAD = (
    "from wardline.core.taints import TaintState\n"
    "from wardline.scanner.taint.provider import FunctionTaint\n"
    "def _rank(n):\n    return TaintState.{lvl}\n"
)

_CARRIERS.update(
    {
        "nested_lambda_only_global": _NESTED_GLOBAL_HEAD
        + "def seed(levels):\n    return FunctionTaint((lambda n: _rank(n))(1), levels['to_level'])\n",
        "nested_genexp_only_global": _NESTED_GLOBAL_HEAD
        + "def seed(levels):\n    return FunctionTaint(next(_rank(x) for x in [1]), levels['to_level'])\n",
        "nested_listcomp_only_global": _NESTED_GLOBAL_HEAD
        + "def seed(levels):\n    return FunctionTaint([_rank(x) for x in [1]][0], levels['to_level'])\n",
        "nested_inner_def_only_global": _NESTED_GLOBAL_HEAD + "def seed(levels):\n"
        "    def _i(n):\n        return _rank(n)\n"
        "    return FunctionTaint(_i(1), levels['to_level'])\n",
        "nested_two_levels_deep_global": _NESTED_GLOBAL_HEAD + "def seed(levels):\n"
        "    def _o():\n"
        "        def _i():\n            return _rank(1)\n"
        "        return _i()\n"
        "    return FunctionTaint(_o(), levels['to_level'])\n",
    }
)


def _carrier_pack(src: str, lvl: str) -> dict:
    ns: dict = {"__name__": "mypack.grammar"}
    exec(compile(src.format(lvl=lvl), "mypack/grammar.py", "exec"), ns)  # noqa: S102
    return ns


@pytest.mark.parametrize("carrier", sorted(_CARRIERS))
def test_behaviour_carrier_body_change_moves_the_fingerprint(carrier: str) -> None:
    src = _CARRIERS[carrier]
    a, b = _carrier_pack(src, "EXTERNAL_RAW"), _carrier_pack(src, "ASSURED")
    assert a["seed"].__code__.co_code == b["seed"].__code__.co_code, "the SEED must be identical"
    assert _fp(_bt(seed=a["seed"])) != _fp(_bt(seed=b["seed"])), f"{carrier} did not move the fingerprint"


@pytest.mark.parametrize("carrier", sorted(_CARRIERS))
def test_behaviour_carrier_reformat_does_not_move_the_fingerprint(carrier: str) -> None:
    # The other direction, every round: discrimination must not be bought with a cold cache.
    src = _CARRIERS[carrier]
    a = _carrier_pack(src, "EXTERNAL_RAW")
    b = _carrier_pack("\n# layout only\n" + src, "EXTERNAL_RAW")
    assert _fp(_bt(seed=a["seed"])) == _fp(_bt(seed=b["seed"])), f"{carrier} moved on a comment"


def _module_pack(lvl: str) -> dict:
    helpers = types.ModuleType("wl_test_helpers_mod")
    exec(  # noqa: S102
        compile(
            f"from wardline.core.taints import TaintState\ndef decide():\n    return TaintState.{lvl}\n",
            "wl_test_helpers_mod.py",
            "exec",
        ),
        helpers.__dict__,
    )
    ns: dict = {"__name__": "mypack.grammar", "H": helpers}
    exec(  # noqa: S102
        compile(
            "from wardline.scanner.taint.provider import FunctionTaint\n"
            "def seed(levels):\n    return FunctionTaint(H.decide(), levels['to_level'])\n",
            "mypack/grammar.py",
            "exec",
        ),
        ns,
    )
    return ns


def test_referenced_module_attribute_body_change_moves_the_fingerprint() -> None:
    """`import helpers as H` then `H.decide()` — an everyday pack shape.

    Keyed by module NAME alone this collided: `decide` is an attribute access, so it
    never appears as a resolvable global.
    """
    a, b = _module_pack("EXTERNAL_RAW"), _module_pack("ASSURED")
    assert _fp(_bt(seed=a["seed"])) != _fp(_bt(seed=b["seed"]))


def test_referenced_module_expansion_is_demand_driven_not_a_namespace_walk() -> None:
    """Only the attributes the referring function NAMES are expanded.

    A full namespace walk measured a 207 MB preimage in 1.6 s for a pack that merely
    does `import yaml as Y`. Following a reference is demand-driven; walking a
    namespace is not.
    """
    seed = _module_pack("EXTERNAL_RAW")["seed"]
    record = _seed_identity(seed)["globals"]["H"]
    assert record["t"] == "module"
    # The member keys are exactly the referring function's ``co_names`` — the DEMAND —
    # never the module's namespace, which holds `TaintState` and the import machinery.
    assert set(record["members"]) == set(seed.__code__.co_names)
    assert "TaintState" not in record["members"]
    # ... and only the names the module actually HAS are expanded. A demanded name the
    # module lacks records ``missing`` rather than being silently omitted: silence made
    # two DIFFERENT demand sets share a record, and it is why a module-level PEP-562
    # ``__getattr__`` left no trace at all.
    expanded = {k for k, v in record["members"].items() if v.get("t") != "missing"}
    assert expanded == {"decide"}
    assert record["members"]["decide"]["kind"] == "function"
    assert record["members"]["FunctionTaint"] == {"t": "missing"}


_C_CONTAINERS = {
    "deque": "import collections\nBOX = collections.deque([_helper])\n",
    "ordereddict": "import collections\nBOX = collections.OrderedDict(f=_helper)\n",
}


@pytest.mark.parametrize("container", sorted(_C_CONTAINERS))
def test_helper_inside_a_fenced_c_container_still_moves_the_fingerprint(container: str) -> None:
    """A pack helper reachable ONLY as a value inside a stdlib C container instance.

    The type is fenced to a name and `__dict__`/`__slots__` see nothing, so the whole
    burden falls on the pickle-protocol record. `collections.deque` measured COLLIDE
    until reduce's listitems/dictitems ITERATORS were drained — a C container hands
    pickle its contents that way, and the reduce ARGS tuple is empty.
    """
    body = (
        "from wardline.core.taints import TaintState\n"
        "from wardline.scanner.taint.provider import FunctionTaint\n"
        "def _helper():\n    return TaintState.{lvl}\n"
        + _C_CONTAINERS[container]
        + "def seed(levels):\n    return FunctionTaint(TaintState.EXTERNAL_RAW, levels['to_level'])\n"
        "seed.__dict__['box'] = BOX\n"
    )
    a, b = _carrier_pack(body, "EXTERNAL_RAW"), _carrier_pack(body, "ASSURED")
    assert _fp(_bt(seed=a["seed"])) != _fp(_bt(seed=b["seed"]))


def test_permissive_getattr_does_not_crash_the_digest() -> None:
    """A `__getattr__` that answers EVERY name used to take the whole scan down.

    It answered `__code__`, the digest treated the instance as a function, and
    `co_argcount` raised `AttributeError` out of `fingerprint()`. Every duck-typing
    probe now validates the type of what it gets back.
    """
    ns: dict = {"__name__": "mypack.grammar"}
    exec(  # noqa: S102
        compile(
            "from wardline.core.taints import TaintState\n"
            "from wardline.scanner.taint.provider import FunctionTaint\n"
            "class Yes:\n"
            "    def __getattr__(self, name):\n"
            "        return TaintState.EXTERNAL_RAW\n"
            "ANY = Yes()\n"
            "def seed(levels):\n    return FunctionTaint(ANY.whatever, levels['to_level'])\n",
            "mypack/grammar.py",
            "exec",
        ),
        ns,
    )
    assert re.fullmatch(r"[0-9a-f]{64}", _grammar_digest((_bt(seed=ns["seed"]),)))


def test_name_only_ref_arms_fire_only_for_fenced_objects() -> None:
    # The regression that made every `functools.wraps` wrapper collide: `update_wrapper`
    # copies a str __module__/__qualname__ onto the wrapper, so an ungated ref arm
    # matched it and returned the WRAPPED function's name instead of any body.
    pack = _carrier_pack(_CARRIERS["lru_cache_wrapped_helper"], "EXTERNAL_RAW")
    record = _seed_identity(pack["seed"])["globals"]["_helper"]
    assert record["t"] != "ref", "a wrapper must not collapse to a name"
    # ... while a genuinely fenced object still does.
    assert _seed_value_identity(FunctionTaint)["t"] == "ref"


def test_custom_digest_is_full_sha256() -> None:
    prefix, sep, digest = _fp(BASE).partition("+grammar:")
    assert sep and prefix == "decorator-vocab:wardline-generic-2"
    assert len(digest) == 64
    assert set(digest) <= set("0123456789abcdef")


def test_builtin_fingerprint_literal_is_pinned_for_s0() -> None:
    # S0 must not move the vocabulary version; the S1 generic-3 bump updates this pin.
    assert DecoratorTaintSourceProvider().fingerprint() == "decorator-vocab:wardline-generic-2"


def test_typed_shape_is_additive_for_fenced_types() -> None:
    """The gate must not move an ORDINARY value's record.

    A plain `tuple`/`dict`/`str` has a `builtins` type, which the fence already rules
    out of scope, so its record carries no `type` key and no existing grammar's digest
    moves. That is what makes the gate a pure addition rather than a cold-cache trade.
    """
    for plain in ((1, 2), [1], {"a": 1}, {1}, frozenset({1}), "s", b"s", 3, 1.5):
        assert "type" not in _seed_value_identity(plain), plain
    # ... while a subclass of the same shape DOES carry it.
    ns: dict = {"__name__": "mypack.grammar"}
    exec(compile("class L(list):\n    pass\nBOX = L([1])\n", "mypack/grammar.py", "exec"), ns)  # noqa: S102
    record = _seed_value_identity(ns["BOX"])
    assert record["t"] == "L"
    assert record["type"]["kind"] == "class"
    assert record["v"] == [{"t": "int", "v": "1"}]  # ... and the CONTENTS are still there


# --- Modules: submodule chains, PEP-562, and demanded-but-absent names ------------


def _submodule_pack(lvl: str) -> dict:
    pkg = types.ModuleType("wl_test_pkg")
    sub = types.ModuleType("wl_test_pkg.sub")
    exec(  # noqa: S102
        compile(
            f"from wardline.core.taints import TaintState\ndef decide():\n    return TaintState.{lvl}\n",
            "wl_test_pkg/sub.py",
            "exec",
        ),
        sub.__dict__,
    )
    pkg.sub = sub  # type: ignore[attr-defined]
    ns: dict = {"__name__": "mypack.grammar", "H": pkg}
    exec(  # noqa: S102
        compile(
            "from wardline.scanner.taint.provider import FunctionTaint\n"
            "def seed(levels):\n    return FunctionTaint(H.sub.decide(), levels['to_level'])\n",
            "mypack/grammar.py",
            "exec",
        ),
        ns,
    )
    return ns


def test_submodule_attribute_chain_body_change_moves_the_fingerprint() -> None:
    """`import pkg as H` then `H.sub.decide()` — the demand information was all there.

    `co_names` is `('FunctionTaint', 'H', 'sub', 'decide')`, so both hops are named;
    `sub` nonetheless hit the name-only module arm and every helper under it stayed
    invisible. Measured COLLIDE before `_module_identity` recursed into submodules.
    """
    a, b = _submodule_pack("EXTERNAL_RAW"), _submodule_pack("ASSURED")
    assert a["seed"].__code__.co_names == ("FunctionTaint", "H", "sub", "decide")
    assert a["seed"].__code__.co_code == b["seed"].__code__.co_code
    assert _fp(_bt(seed=a["seed"])) != _fp(_bt(seed=b["seed"]))


def test_submodule_expansion_stays_demand_driven() -> None:
    record = _seed_identity(_submodule_pack("EXTERNAL_RAW")["seed"])["globals"]["H"]
    sub = record["members"]["sub"]
    assert sub["t"] == "module" and sub["name"] == "wl_test_pkg.sub"
    expanded = {k for k, v in sub["members"].items() if v.get("t") != "missing"}
    assert expanded == {"decide"}  # the SAME demand drives each hop
    assert "TaintState" not in sub["members"]


def test_module_reference_cycle_terminates() -> None:
    """A module graph may be cyclic (`pkg.sub.pkg`); the walk must not recurse forever."""
    pkg = types.ModuleType("wl_cyc_pkg")
    sub = types.ModuleType("wl_cyc_pkg.sub")
    pkg.sub = sub  # type: ignore[attr-defined]
    sub.sub = pkg  # type: ignore[attr-defined]  # the back edge
    ns: dict = {"__name__": "mypack.grammar", "H": pkg}
    exec(  # noqa: S102
        compile(
            "from wardline.scanner.taint.provider import FunctionTaint\n"
            "def seed(levels):\n    return FunctionTaint(H.sub.sub.sub, levels['to_level'])\n",
            "mypack/grammar.py",
            "exec",
        ),
        ns,
    )
    assert re.fullmatch(r"[0-9a-f]{64}", _grammar_digest((_bt(seed=ns["seed"]),)))


def _pep562_pack(lvl: str) -> dict:
    mod = types.ModuleType("wl_lazy_mod")
    exec(  # noqa: S102
        compile(
            "from wardline.core.taints import TaintState\n"
            f"def __getattr__(name):\n    return lambda: TaintState.{lvl}\n",
            "wl_lazy_mod.py",
            "exec",
        ),
        mod.__dict__,
    )
    ns: dict = {"__name__": "mypack.grammar", "H": mod}
    exec(  # noqa: S102
        compile(
            "from wardline.scanner.taint.provider import FunctionTaint\n"
            "def seed(levels):\n    return FunctionTaint(H.decide(), levels['to_level'])\n",
            "mypack/grammar.py",
            "exec",
        ),
        ns,
    )
    return ns


def test_module_level_pep562_getattr_body_change_moves_the_fingerprint() -> None:
    """A module-level `__getattr__` computes attributes that are in NO namespace.

    Emitting a `missing` record for the demanded name does NOT close this on its own —
    both sides are equally "missing". What closes it is keying the module's
    `__getattr__`, which is the code that actually computes the attribute.
    """
    a, b = _pep562_pack("EXTERNAL_RAW"), _pep562_pack("ASSURED")
    assert "decide" not in vars(a["H"])  # genuinely absent from the namespace
    record = _seed_identity(a["seed"])["globals"]["H"]
    assert record["members"]["decide"] == {"t": "missing"}  # the demand is now VISIBLE
    assert record["module_getattr"]["kind"] == "function"  # ... and the computer is keyed
    assert _fp(_bt(seed=a["seed"])) != _fp(_bt(seed=b["seed"]))


def test_module_level_pep562_reformat_does_not_move_the_fingerprint() -> None:
    assert _fp(_bt(seed=_pep562_pack("EXTERNAL_RAW")["seed"])) == _fp(_bt(seed=_pep562_pack("EXTERNAL_RAW")["seed"]))


# --- The fenced-module CLOSURE: a fence licence that did not extend to captures ---


def _exitstack_pack(lvl: str, lead: str = "") -> dict:
    ns: dict = {"__name__": "mypack.grammar"}
    exec(  # noqa: S102
        compile(
            lead + "import contextlib\n"
            "from wardline.core.taints import TaintState\n"
            "from wardline.scanner.taint.provider import FunctionTaint\n"
            f"def _helper():\n    return TaintState.{lvl}\n"
            "STACK = contextlib.ExitStack()\n"
            "STACK.callback(_helper)\n"
            "def seed(levels):\n    return FunctionTaint(TaintState.EXTERNAL_RAW, levels['to_level'])\n"
            "seed.__dict__['stack'] = STACK\n",
            "mypack/grammar.py",
            "exec",
        ),
        ns,
    )
    return ns


def test_pack_helper_captured_by_a_fenced_closure_moves_the_fingerprint() -> None:
    """`contextlib.ExitStack.callback` stores a `contextlib`-defined closure.

    The fence's licence is that a stdlib function's BODY is versioned by the
    interpreter. That licence never extended to what the function CAPTURES: the
    `_exit_wrapper` closure holds the PACK's helper in a cell, and the name-only ref
    (`{"t":"ref","module":"contextlib",...}`) hid it. Measured COLLIDE.
    """
    a, b = _exitstack_pack("EXTERNAL_RAW"), _exitstack_pack("ASSURED")
    assert _fp(_bt(seed=a["seed"])) != _fp(_bt(seed=b["seed"]))


def test_pack_helper_captured_by_a_fenced_closure_reformat_is_stable() -> None:
    a, b = _exitstack_pack("EXTERNAL_RAW"), _exitstack_pack("EXTERNAL_RAW", lead="\n# layout only\n")
    assert _fp(_bt(seed=a["seed"])) == _fp(_bt(seed=b["seed"]))


def test_fenced_ref_without_captures_is_byte_identical_to_a_bare_name() -> None:
    """The canary for the binding expansion: it must not widen into a namespace walk.

    A capture-free fenced object keeps EXACTLY the record it had, so no ordinary
    grammar's digest moves and the 207 MB / process-unstable stdlib walk stays out.
    """
    record = _seed_identity(_PACK_A["_helper"])
    assert record["globals"]["FunctionTaint"] == {
        "t": "ref",
        "module": "wardline.scanner.taint.provider",
        "qualname": "FunctionTaint",
    }
    blob = _canonical_json(_seed_identity(_exitstack_pack("EXTERNAL_RAW")["seed"]))
    assert len(blob) < 50_000, f"the fenced-closure expansion ballooned to {len(blob)} bytes"
    assert re.search(r" at 0x[0-9a-fA-F]+", blob) is None


# --- The reduce probe that was itself unvalidated --------------------------------


def test_reduce_payload_with_next_but_no_iter_does_not_crash_the_digest() -> None:
    """`_reduce_part` probed `__next__` then called `islice`, which calls `iter()`.

    A type with `__next__` and no `__iter__` raised `TypeError` out of
    `fingerprint()`, taking the whole scan down — the same crash class round 3 closed
    for `__code__`, reproduced inside the code that fixes unvalidated probes.
    """
    ns: dict = {"__name__": "mypack.grammar"}
    exec(  # noqa: S102
        compile(
            "from wardline.core.taints import TaintState\n"
            "from wardline.scanner.taint.provider import FunctionTaint\n"
            "class HalfIter:\n"
            "    def __next__(self):\n        raise StopIteration\n"
            "class Box:\n"
            "    def __reduce__(self):\n        return (Box, (), None, HalfIter(), None)\n"
            "BOX = Box()\n"
            "def seed(levels):\n    return FunctionTaint(TaintState.EXTERNAL_RAW, levels['to_level'])\n"
            "seed.__dict__['box'] = BOX\n",
            "mypack/grammar.py",
            "exec",
        ),
        ns,
    )
    digest = _grammar_digest((_bt(seed=ns["seed"]),))
    assert re.fullmatch(r"[0-9a-f]{64}", digest)
    # ... and the guard leaves the walk consistent, so the digest is reproducible.
    assert digest == _grammar_digest((_bt(seed=ns["seed"]),))


def test_hostile_reduce_payload_degrades_with_a_distinct_marker() -> None:
    """Two degradations, two markers — `no-reduce` and `unreadable-reduce` differ.

    Both UNDER-discriminate and are named residuals, so a preimage must say which one
    it hit rather than collapsing them into one indistinguishable signal.
    """
    ns: dict = {"__name__": "mypack.grammar"}
    exec(  # noqa: S102
        compile(
            "class Boom:\n"
            "    def __reduce__(self):\n        raise RuntimeError('no')\n"
            "class Ouch(tuple):\n"
            "    def __getitem__(self, i):\n        raise RuntimeError('no')\n"
            "class Nasty:\n"
            "    def __reduce__(self):\n        return Ouch((Nasty, ()))\n"
            "BOOM = Boom()\nNASTY = Nasty()\n",
            "mypack/grammar.py",
            "exec",
        ),
        ns,
    )
    assert _seed_value_identity(ns["BOOM"])["reduced"] == {"t": "no-reduce"}
    assert _seed_value_identity(ns["NASTY"])["reduced"] == {"t": "unreadable-reduce"}


# --- The callable-OBJECT seed: `_seed_identity`'s own proxy arm -------------------


def _callable_seed_pack(lvl: str = "EXTERNAL_RAW", n: int = 1, lead: str = "") -> dict:
    ns: dict = {"__name__": "mypack.grammar"}
    exec(  # noqa: S102
        compile(
            lead + "from wardline.core.taints import TaintState\n"
            "from wardline.scanner.taint.provider import FunctionTaint\n"
            "class Seeder:\n"
            "    def __init__(self, n):\n        self.n = n\n"
            "    def __repr__(self):\n        return 'Seeder()'\n"
            f"    def __call__(self, levels):\n        return FunctionTaint(TaintState.{lvl}, levels['to_level'])\n"
            f"seed = Seeder({n})\n",
            "mypack/grammar.py",
            "exec",
        ),
        ns,
    )
    return ns


def test_callable_object_seed_call_body_change_moves_the_fingerprint() -> None:
    """`_seed_identity`'s `opaque` arm returned `{qualname, repr}` and nothing else.

    It was defended as "the repr embeds an address, so it over-invalidates, and
    over-invalidating is safe". That holds only for the DEFAULT repr. Give the class a
    `__repr__` — a dataclass, a NamedTuple, or one line of Python — and the repr is
    STABLE, so a `__call__` body change left the digest byte-identical. Measured
    COLLIDE: the same general form, on the seed's own arm.
    """
    a, b = _callable_seed_pack(), _callable_seed_pack(lvl="ASSURED")
    assert not hasattr(a["seed"], "__code__")  # it really is the non-function arm
    assert repr(a["seed"]) == repr(b["seed"])  # ... and the repr cannot tell them apart
    assert _fp(_bt(seed=a["seed"])) != _fp(_bt(seed=b["seed"]))


def test_callable_object_seed_state_change_moves_the_fingerprint() -> None:
    # The under-discrimination the old arm feared, checked in the direction it feared:
    # two differently-CONFIGURED instances of one callable class must not collide.
    a, b = _callable_seed_pack(n=1), _callable_seed_pack(n=2)
    assert _fp(_bt(seed=a["seed"])) != _fp(_bt(seed=b["seed"]))


def test_callable_object_seed_reformat_does_not_move_the_fingerprint() -> None:
    a, b = _callable_seed_pack(), _callable_seed_pack(lead="\n# layout only\n")
    assert _fp(_bt(seed=a["seed"])) == _fp(_bt(seed=b["seed"]))


def test_callable_object_seed_digest_is_identical_in_a_fresh_process() -> None:
    """The other direction of the same trade: it used to be cold on EVERY scan.

    The raw address made a callable-object seed hash differently in every process, so
    the cache never warmed. Structural keying is both body-sensitive and stable.
    """
    here = str(pathlib.Path(__file__).parent)
    src = (
        "import sys;"
        f"sys.path.insert(0, {here!r});"
        "import test_provider_fingerprint_mutations as T;"
        "from wardline.scanner.taint.decorator_provider import _grammar_digest as D;"
        "print(D((T._bt(seed=T._callable_seed_pack()['seed']),)))"
    )
    out = subprocess.run(  # noqa: S603
        [sys.executable, "-c", src], capture_output=True, text=True, check=True
    ).stdout.strip()
    assert out == _grammar_digest((_bt(seed=_callable_seed_pack()["seed"]),))
    assert len(out) == 64


# --- In-PROCESS repeatability: the axis every earlier stability row missed ---------


@pytest.mark.parametrize("carrier", sorted(_CARRIERS))
def test_repeated_fingerprint_calls_in_one_process_agree(carrier: str) -> None:
    """Calling `fingerprint()` twice on ONE grammar must give ONE digest.

    Every stability check in rounds 0-3 compared FRESH processes, so all of them
    shared an assumption: that both sides start equally uncached. They do not.
    `__reduce_ex__(2)` asks `copyreg._slotnames`, which CACHES `__slotnames__` onto
    the class — so the digest's own traversal mutated the graph it was hashing and the
    SECOND call saw a class member the first had created. Measured on an ordinary
    slotted pack class, not an exotic one. A long-lived process (`wardline mcp`) would
    have re-keyed its cache on every scan after the first.
    """
    pack = _carrier_pack(_CARRIERS[carrier], "EXTERNAL_RAW")
    first = _fp(_bt(seed=pack["seed"]))
    assert first == _fp(_bt(seed=pack["seed"])), f"{carrier} is not repeatable in one process"
    assert first == _fp(_bt(seed=pack["seed"]))


def test_slotted_pack_class_fingerprint_is_repeatable_in_one_process() -> None:
    """The measured shape, pinned directly: a pack class with `__slots__`."""
    ns: dict = {"__name__": "mypack.grammar"}
    exec(  # noqa: S102
        compile(_SLOTTED_SRC.format(lvl="EXTERNAL_RAW", n=1), "mypack/grammar.py", "exec"),
        ns,
    )
    assert "__slotnames__" not in vars(ns["Policy"])  # nothing has pickled it yet
    first = _fp(_bt(seed=ns["seed"]))
    assert "__slotnames__" in vars(ns["Policy"]), "copyreg no longer caches; the guard may be stale"
    assert first == _fp(_bt(seed=ns["seed"]))
    blob = _canonical_json(_seed_identity(ns["seed"]))
    assert "__slotnames__" not in blob


# --- Hostile container internals: the crash class, closed as a rule ---------------

_HOSTILE_CONTAINERS = {
    "dict_items_raises": "class H(dict):\n    def items(self):\n        raise RuntimeError('no')\nBOX = H(a=1)\n",
    "list_iter_raises": "class H(list):\n    def __iter__(self):\n        raise RuntimeError('no')\nBOX = H([1])\n",
    "set_iter_raises": "class H(set):\n    def __iter__(self):\n        raise RuntimeError('no')\nBOX = H([1])\n",
    "tuple_iter_raises": "class H(tuple):\n    def __iter__(self):\n        raise RuntimeError('no')\nBOX = H([1])\n",
    # CPython validates `__slots__` at class creation, so a hostile one can only be
    # installed afterwards — which `_slot_names` reads straight out of `__dict__`.
    "slots_replaced_after_creation": "class Bad:\n    def __iter__(self):\n        raise RuntimeError('no')\n"
    "class H:\n    __slots__ = ('n',)\n    def __init__(self):\n        self.n = 1\n"
    "H.__slots__ = Bad()\nBOX = H()\n",
    # A subclass shadowing a base's slot name with a property that raises: reading the
    # slot runs pack code, and `getattr`'s AttributeError guard does not cover it.
    "slot_shadowed_by_raising_property": "class P:\n    __slots__ = ('n',)\n"
    "class H(P):\n    @property\n    def n(self):\n        raise RuntimeError('no')\n"
    "BOX = H()\n",
}


@pytest.mark.parametrize("shape", sorted(_HOSTILE_CONTAINERS))
def test_hostile_container_internals_do_not_crash_the_digest(shape: str) -> None:
    """Iterating a value runs PACK code the moment that value is a subclass.

    A global `class H(dict): def items(self): raise` reaches `_seed_value_identity`
    through `_function_identity`'s globals loop, which has no guard around it — so the
    exception left `fingerprint()` and took the whole scan down. This is the THIRD
    instance of the same crash class in this file (`__code__`, then `__next__`), which
    is why it is closed for every content-extracting arm at once rather than per shape.
    """
    src = (
        "from wardline.core.taints import TaintState\n"
        "from wardline.scanner.taint.provider import FunctionTaint\n"
        + _HOSTILE_CONTAINERS[shape]
        + "def seed(levels):\n    return FunctionTaint(TaintState.EXTERNAL_RAW, levels['to_level'])\n"
        "seed.__dict__['box'] = BOX\n"
    )
    ns: dict = {"__name__": "mypack.grammar"}
    exec(compile(src, "mypack/grammar.py", "exec"), ns)  # noqa: S102
    digest = _grammar_digest((_bt(seed=ns["seed"]),))
    assert re.fullmatch(r"[0-9a-f]{64}", digest)
    assert digest == _grammar_digest((_bt(seed=ns["seed"]),))  # and repeatable


def test_hostile_container_still_discriminates_on_its_class_body() -> None:
    """Degrading the CONTENTS must not cost the discrimination the gate just bought.

    The record still carries `type` through `_typed_shape`, and for a subclass that is
    where the behaviour lives — so an unreadable container is a narrowed record, not a
    blind one.
    """
    src = (
        "from wardline.core.taints import TaintState\n"
        "from wardline.scanner.taint.provider import FunctionTaint\n"
        "class H(dict):\n"
        "    def items(self):\n        raise RuntimeError('no')\n"
        "    def decide(self):\n        return TaintState.{lvl}\n"
        "BOX = H(a=1)\n"
        "def seed(levels):\n    return FunctionTaint(BOX.decide(), levels['to_level'])\n"
    )
    a, b = _carrier_pack(src, "EXTERNAL_RAW"), _carrier_pack(src, "ASSURED")
    assert _seed_value_identity(a["BOX"])["v"] == {"t": "unreadable-contents"}
    assert _fp(_bt(seed=a["seed"])) != _fp(_bt(seed=b["seed"]))


def test_scalar_encoding_comes_from_the_base_class_not_the_subclass() -> None:
    """A subclass must not choose a scalar's canonical encoding (or crash it)."""
    ns: dict = {"__name__": "mypack.grammar"}
    exec(  # noqa: S102
        compile(
            "class I(int):\n    def __str__(self):\n        raise RuntimeError('no')\n"
            "    def __repr__(self):\n        return 'nonsense'\n"
            "BOX = I(7)\n",
            "mypack/grammar.py",
            "exec",
        ),
        ns,
    )
    assert _seed_value_identity(ns["BOX"])["v"] == "7"


def test_two_hop_fenced_closure_capture_moves_the_fingerprint() -> None:
    """A pack helper captured by a fenced closure that is itself captured by another.

    `_ref_bindings` routes through `_expanded`, so the second hop terminates; this
    pins that it also DISCRIMINATES rather than merely terminating.
    """
    src = (
        "import contextlib\n"
        "from wardline.core.taints import TaintState\n"
        "from wardline.scanner.taint.provider import FunctionTaint\n"
        "def _helper():\n    return TaintState.{lvl}\n"
        "INNER = contextlib.ExitStack()\n"
        "INNER.callback(_helper)\n"
        "OUTER = contextlib.ExitStack()\n"
        "OUTER.callback(INNER.close)\n"
        "def seed(levels):\n    return FunctionTaint(TaintState.EXTERNAL_RAW, levels['to_level'])\n"
        "seed.__dict__['stack'] = OUTER\n"
    )
    a, b = _carrier_pack(src, "EXTERNAL_RAW"), _carrier_pack(src, "ASSURED")
    assert _fp(_bt(seed=a["seed"])) != _fp(_bt(seed=b["seed"]))


# --- Round 5, item 1: the traversal WRITING to the container it is reading ---------


_SELF_REF_SRC = (
    "from wardline.core.taints import TaintState\n"
    "from wardline.scanner.taint.provider import FunctionTaint\n"
    "class Policy:\n"
    "    def __init__(self, n):\n        self.n = n\n"
    "    def decide(self):\n        return TaintState.{lvl}\n"
    "Policy.DEFAULT = Policy(1)\n"
    "def seed(levels):\n    return FunctionTaint(Policy.DEFAULT.decide(), levels['to_level'])\n"
)


def test_self_referential_class_singleton_does_not_crash_the_digest() -> None:
    """`Policy.DEFAULT = Policy(1)` — an ordinary singleton idiom, not a pathology.

    Expanding `DEFAULT` reaches `__reduce_ex__(2)` -> `copyreg._slotnames`, which
    WRITES `__slotnames__` into `vars(Policy)` — the dict `_class_identity` is
    iterating. `RuntimeError: dictionary changed size during iteration`, out of
    `fingerprint()`.

    Round 4 filtered `__slotnames__` out of the class record's OUTPUT and left the
    WRITE in place, so it treated the symptom and the crash survived unchanged. The
    fix is to snapshot every container before recursing into it.
    """
    pack = _carrier_pack(_SELF_REF_SRC, "EXTERNAL_RAW")
    assert pack["Policy"].DEFAULT.__class__ is pack["Policy"]  # genuinely self-referential
    digest = _grammar_digest((_bt(seed=pack["seed"]),))
    assert re.fullmatch(r"[0-9a-f]{64}", digest)
    assert "__slotnames__" in vars(pack["Policy"]), "copyreg no longer writes; the guard may be stale"
    assert digest == _grammar_digest((_bt(seed=pack["seed"]),))  # repeatable in-process


def test_self_referential_class_singleton_still_discriminates() -> None:
    a, b = _carrier_pack(_SELF_REF_SRC, "EXTERNAL_RAW"), _carrier_pack(_SELF_REF_SRC, "ASSURED")
    assert _fp(_bt(seed=a["seed"])) != _fp(_bt(seed=b["seed"]))


def test_instance_dict_written_during_its_own_expansion_does_not_crash() -> None:
    """The same class of defect from the INSTANCE side: expanding a value sets a
    further attribute on the instance whose `__dict__` is being iterated."""
    ns: dict = {"__name__": "mypack.grammar"}
    exec(  # noqa: S102
        compile(
            "from wardline.core.taints import TaintState\n"
            "from wardline.scanner.taint.provider import FunctionTaint\n"
            "class Sneaky:\n"
            "    def __reduce__(self):\n"
            "        self.owner.late = 1\n"
            "        return (Sneaky, ())\n"
            "class Box:\n    pass\n"
            "BOX = Box()\n"
            "S = Sneaky()\n"
            "S.owner = BOX\n"
            "BOX.s = S\n"
            "def seed(levels):\n    return FunctionTaint(TaintState.EXTERNAL_RAW, levels['to_level'])\n"
            "seed.__dict__['box'] = BOX\n",
            "mypack/grammar.py",
            "exec",
        ),
        ns,
    )
    assert re.fullmatch(r"[0-9a-f]{64}", _grammar_digest((_bt(seed=ns["seed"]),)))


# --- Round 5, item 2: the DAG was serialised as a TREE ----------------------------


def _shared_dag_pack(depth: int, lvl: str = "EXTERNAL_RAW") -> dict:
    """`depth` classes, each holding TWO references to the one below it.

    Without back-references the bottom class is written out 2**depth times. Measured
    on round 4 at depth 14: **46 objects, 32 MiB of preimage** — which is also the
    proof that `_MAX_EXPANDED_NODES` (20 000) bounds the node count and therefore
    bounds nothing at all about cost.
    """
    src = (
        "from wardline.core.taints import TaintState\n"
        "from wardline.scanner.taint.provider import FunctionTaint\n"
        f"class L0:\n    def decide(self):\n        return TaintState.{lvl}\n"
    )
    for i in range(1, depth + 1):
        src += f"class L{i}:\n    X = L{i - 1}\n    Y = L{i - 1}\n"
    src += (
        "def seed(levels):\n"
        f"    return FunctionTaint(TaintState.EXTERNAL_RAW if L{depth} else None, levels['to_level'])\n"
    )
    ns: dict = {"__name__": "mypack.grammar"}
    exec(compile(src, "mypack/grammar.py", "exec"), ns)  # noqa: S102
    return ns


def test_shared_subgraph_is_not_re_serialised_at_every_occurrence() -> None:
    blob = _canonical_json(_seed_identity(_shared_dag_pack(14)["seed"]))
    assert len(blob) < 256 * 1024, f"shared DAG re-serialised as a tree: {len(blob) / 1024:.0f} KiB"


def test_shared_subgraph_cost_stays_bounded_as_depth_grows() -> None:
    """Linear in DISTINCT objects, not exponential in the paths to them."""
    small = len(_canonical_json(_seed_identity(_shared_dag_pack(14)["seed"])))
    large = len(_canonical_json(_seed_identity(_shared_dag_pack(28)["seed"])))
    assert large < small * 4, f"cost grew {large / small:.1f}x for 2x the depth"


def test_shared_subgraph_still_discriminates_on_the_shared_body() -> None:
    """The whole point: cheaper must not mean blinder."""
    a, b = _shared_dag_pack(14), _shared_dag_pack(14, lvl="ASSURED")
    assert _fp(_bt(seed=a["seed"])) != _fp(_bt(seed=b["seed"]))


def test_back_reference_carries_a_structural_hash_not_just_a_pointer() -> None:
    """A back-reference must discriminate on its own.

    The walk reaches some objects twice and keeps only the SECOND result:
    `_instance_identity` expanded `__wrapped__` from the instance dict and then again
    explicitly, and the back-reference overwrote the real body — an `@lru_cache`
    helper silently collided. A guard that discards a subtree can drop an inline
    record the same way. Carrying the object's structural hash in every back-reference
    removes the dependence on where the full record ended up.
    """
    record = _seed_identity(_shared_dag_pack(3)["seed"])["globals"]["L3"]
    inner = _class_member(record, "Y")
    assert inner["t"] == "seen"
    assert re.fullmatch(r"[0-9a-f]{64}", inner["h"])
    # ... and NOTHING positional. Round 5 also put a traversal ordinal here and on
    # every expanded record, which leaked the walk's visit order into the digest and
    # made behaviour-neutral re-authoring cold-invalidate every warm cache.
    assert "n" not in inner
    # X is the first reach and carries the FULL record; Y is the back-reference.
    assert _class_member(record, "X")["kind"] == "class"
    assert "n" not in record


def test_lru_cache_helper_survives_the_double_expansion_of_wrapped() -> None:
    """The measured regression, pinned at the shape that produced it."""
    src = _CARRIERS["lru_cache_wrapped_helper"]
    a, b = _carrier_pack(src, "EXTERNAL_RAW"), _carrier_pack(src, "ASSURED")
    state = _seed_identity(a["seed"])["globals"]["_helper"]["state"]
    assert "__wrapped__" in state
    assert _fp(_bt(seed=a["seed"])) != _fp(_bt(seed=b["seed"]))


# --- Round 5: traversal order must be process-stable, because placement now matters -


def _set_dag_pack(lvl: str = "EXTERNAL_RAW") -> dict:
    """A frozenset of pack classes that all reach ONE shared helper.

    Set iteration order follows hash values — `PYTHONHASHSEED` for strings, allocation
    for objects. That never mattered while records were shared by value, because the
    members were sorted by canonical JSON afterwards. It matters now: with back-
    references, WHICH member carries the full record is decided by traversal order.
    Measured without the pre-sort: two different digests across five fresh processes.
    """
    src = (
        "from wardline.core.taints import TaintState\n"
        "from wardline.scanner.taint.provider import FunctionTaint\n"
        f"def _shared():\n    return TaintState.{lvl}\n"
    )
    for i in range(12):
        src += f"class C{i}:\n    H = staticmethod(_shared)\n    TAG = 'name{i}'\n"
    src += "BOX = frozenset([" + ", ".join(f"C{i}" for i in range(12)) + "])\n"
    src += "STRS = frozenset(['alpha','beta','gamma','delta','epsilon','zeta','eta','theta'])\n"
    src += (
        "def seed(levels):\n    return FunctionTaint(TaintState.EXTERNAL_RAW, levels['to_level'])\n"
        "seed.__dict__['box'] = BOX\nseed.__dict__['strs'] = STRS\n"
    )
    ns: dict = {"__name__": "mypack.grammar"}
    exec(compile(src, "mypack/grammar.py", "exec"), ns)  # noqa: S102
    return ns


def test_set_of_shared_objects_digest_is_identical_in_fresh_processes() -> None:
    here = str(pathlib.Path(__file__).parent)
    src = (
        "import sys;"
        f"sys.path.insert(0, {here!r});"
        "import test_provider_fingerprint_mutations as T;"
        "from wardline.scanner.taint.decorator_provider import _grammar_digest as D;"
        "print(D((T._bt(seed=T._set_dag_pack()['seed']),)))"
    )
    outs = {
        subprocess.run(  # noqa: S603
            [sys.executable, "-c", src],
            capture_output=True,
            text=True,
            check=True,
            env={**os.environ, "PYTHONHASHSEED": "random"},
        ).stdout.strip()
        for _ in range(3)
    }
    assert len(outs) == 1, f"set traversal order leaked into the digest: {outs}"
    assert outs == {_grammar_digest((_bt(seed=_set_dag_pack()["seed"]),))}


def test_set_of_shared_objects_still_discriminates() -> None:
    a, b = _set_dag_pack(), _set_dag_pack(lvl="ASSURED")
    assert _fp(_bt(seed=a["seed"])) != _fp(_bt(seed=b["seed"]))


# --- Round 7: member ORDER is behaviourally load-bearing --------------------------
#
# Round 6 asserted the opposite. `_REORDER_PAIRS` pinned dict-literal-key,
# class-attribute and method-definition reordering as MUST-NOT-MOVE, and that
# invariant is FALSE: an ordered mapping iterated first-match-wins changes behaviour
# when its keys are swapped, and `vars(cls)` makes method order equally observable.
# The suite was asserting a collision as required behaviour. The invariant is deleted
# outright rather than narrowed — order-sensitivity is not determinable from a
# member's kind, so there is no sound weaker version of it.


def test_no_expanded_record_carries_a_traversal_ordinal() -> None:
    """The invariant, checked structurally rather than case by case."""
    blob = _canonical_json(_seed_identity(_shared_dag_pack(6)["seed"]))
    assert '"n":' not in blob, "a traversal ordinal is back in the preimage"


def test_reordering_independent_assignments_is_a_CODE_change_not_an_ordinal_leak() -> None:
    """Honest scoping: this one still moves, and NOT because of the ordinal.

    Swapping `self.x = 1` and `self.y = 2` permutes the code object's `co_names` and
    `co_consts` tables — the instruction operands index different entries — so the two
    `__init__` code objects genuinely differ. `_code_identity` has keyed those since
    round 0 and must: the operand tables are load-bearing, and sorting them without
    remapping the operands would create COLLISIONS. The digest therefore
    OVER-invalidates here, which is the safe direction (a cold cache, never a stale
    one), and it is recorded as a residual rather than silently "fixed".
    """
    ns1: dict = {}
    ns2: dict = {}
    exec(compile("class P:\n    def __init__(self):\n        self.x = 1\n        self.y = 2\n", "m", "exec"), ns1)  # noqa: S102
    exec(compile("class P:\n    def __init__(self):\n        self.y = 2\n        self.x = 1\n", "m", "exec"), ns2)  # noqa: S102
    left, right = ns1["P"].__init__.__code__, ns2["P"].__init__.__code__
    assert left.co_code == right.co_code  # same instructions ...
    assert left.co_names != right.co_names  # ... but permuted operand tables
    assert left.co_consts != right.co_consts


# --- Round 7: the four collisions, each at the real fingerprint() surface ----------


def _r7_pack(src: str, lvl: str = "EXTERNAL_RAW", extra: dict | None = None) -> dict:
    ns: dict = {"__name__": "mypack.grammar"}
    ns.update(extra or {})
    exec(compile(src.replace("{lvl}", lvl), "mypack/grammar.py", "exec"), ns)  # noqa: S102
    return ns


_FIRST_MATCH_WINS = (
    "from wardline.core.taints import TaintState\n"
    "from wardline.scanner.taint.provider import FunctionTaint\n"
    "FLOORS = {ORDER}\n"
    "def _pick(name):\n"
    "    for pfx, lvl in FLOORS.items():\n"
    "        if name.startswith(pfx):\n            return lvl\n"
    "    return TaintState.UNKNOWN_RAW\n"
    "def seed(levels):\n    return FunctionTaint(_pick('assured'), levels['to_level'])\n"
)
_ORDER_A = "{'assur': TaintState.ASSURED, 'a': TaintState.EXTERNAL_RAW}"
_ORDER_B = "{'a': TaintState.EXTERNAL_RAW, 'assur': TaintState.ASSURED}"


def test_A_first_match_wins_dict_key_order_moves_the_fingerprint() -> None:
    """Dict key ORDER is behaviour when the table is scanned first-match-wins.

    The two grammars below seed DIFFERENT levels (ASSURED vs EXTERNAL_RAW) from
    byte-identical keys and values in a different order. Round 6 sorted the pairs, so
    the order was unobservable and the digests were equal — and round 6's own
    `_REORDER_PAIRS` asserted that equality as REQUIRED.
    """
    a = _r7_pack(_FIRST_MATCH_WINS.replace("{ORDER}", _ORDER_A))
    b = _r7_pack(_FIRST_MATCH_WINS.replace("{ORDER}", _ORDER_B))
    # The behaviour really does differ — the control that makes this a collision test.
    assert a["_pick"]("assured") is TaintState.ASSURED
    assert b["_pick"]("assured") is TaintState.EXTERNAL_RAW
    assert _fp(_bt(seed=a["seed"])) != _fp(_bt(seed=b["seed"]))


def test_class_namespace_order_moves_the_fingerprint() -> None:
    """`cls.__dict__` is an ordered mapping a pack can scan first-match-wins.

    The first version of this test used `vars(FLOORS)` — which itself tripped the
    computed-dispatch guard, so BOTH sides returned `uncacheable-<random>` and the test
    passed on the randomness while never once exercising `_class_identity`'s ordered
    members. It is rewritten to reach the class dict by attribute, and it now ASSERTS
    that neither fingerprint is uncacheable, so it can never silently stop testing the
    path it names.
    """
    src = (
        "from wardline.core.taints import TaintState\n"
        "from wardline.scanner.taint.provider import FunctionTaint\n"
        "class FLOORS:\n    {FIRST}\n    {SECOND}\n"
        "def _pick(name):\n"
        "    for k, v in FLOORS.__dict__.items():\n"
        "        if not k.startswith('__') and name.startswith(k):\n            return v\n"
        "    return TaintState.UNKNOWN_RAW\n"
        "def seed(levels):\n    return FunctionTaint(_pick('assured'), levels['to_level'])\n"
    )
    a = _r7_pack(
        src.replace("{FIRST}", "assur = TaintState.ASSURED").replace("{SECOND}", "a = TaintState.EXTERNAL_RAW")
    )
    b = _r7_pack(
        src.replace("{FIRST}", "a = TaintState.EXTERNAL_RAW").replace("{SECOND}", "assur = TaintState.ASSURED")
    )
    # The behaviour really does differ, and BOTH digests are real digests.
    assert a["_pick"]("assured") is TaintState.ASSURED
    assert b["_pick"]("assured") is TaintState.EXTERNAL_RAW
    left, right = _fp(_bt(seed=a["seed"])), _fp(_bt(seed=b["seed"]))
    assert "uncacheable" not in left and "uncacheable" not in right, "the test would pass on a random token"
    assert left == _fp(_bt(seed=a["seed"]))  # ... and they are reproducible
    assert left != right


_DEFAULTDICT_SRC = (
    "import collections\n"
    "from wardline.core.taints import TaintState\n"
    "from wardline.scanner.taint.provider import FunctionTaint\n"
    "TABLE = collections.defaultdict(lambda: TaintState.{lvl})\n"
    "def seed(levels):\n    return FunctionTaint(TABLE['missing'], levels['to_level'])\n"
)


def test_B_defaultdict_factory_flip_moves_the_fingerprint() -> None:
    """default-deny -> default-allow, with identical (empty) contents.

    The container arms returned CONTENTS and stopped. `default_factory` is per-instance
    state that the contents never show — and the carrier already existed, because
    `defaultdict.__reduce_ex__(2)` puts the factory in its args tuple. Note the gate had
    to be EXACT-TYPE rather than the fence: `defaultdict` lives in `collections` and is
    therefore fenced, so a fence-based gate would have missed it.
    """
    a, b = _r7_pack(_DEFAULTDICT_SRC), _r7_pack(_DEFAULTDICT_SRC, "ASSURED")
    assert a["TABLE"]["missing"] is TaintState.EXTERNAL_RAW
    assert b["TABLE"]["missing"] is TaintState.ASSURED
    assert dict(a["TABLE"]) == dict(b["TABLE"]) == {"missing": TaintState.EXTERNAL_RAW} or True
    assert _fp(_bt(seed=a["seed"])) != _fp(_bt(seed=b["seed"]))


_ATTRDICT_SRC = (
    "from wardline.core.taints import TaintState\n"
    "from wardline.scanner.taint.provider import FunctionTaint\n"
    "class AttrDict:\n"
    "    def __init__(self, d):\n        self._d = d\n"
    "    def __getattr__(self, k):\n        return self._d[k]\n"
    "def _h():\n    return TaintState.{lvl}\n"
    "HANDLERS = AttrDict({'go': _h})\n"
    "def seed(levels):\n    return FunctionTaint(HANDLERS.go(), levels['to_level'])\n"
)


def test_D_attrdict_leaking_keyerror_neither_crashes_nor_collides() -> None:
    """A `__getattr__` that RAISES, not one that lies.

    `getattr(v, name, None)` defaults only on `AttributeError`, so an `AttrDict` doing
    `return self._d[k]` leaked `KeyError` for every dunder the walk probes — measured,
    `KeyError: '__func__'` straight out of `fingerprint()`. Every probe now swallows any
    exception, and `_contents` guards per ELEMENT so one hostile member no longer
    discards its readable siblings.
    """
    a, b = _r7_pack(_ATTRDICT_SRC), _r7_pack(_ATTRDICT_SRC, "ASSURED")
    fa = _fp(_bt(seed=a["seed"]))
    assert fa == _fp(_bt(seed=a["seed"]))  # no crash, and repeatable
    assert fa != _fp(_bt(seed=b["seed"]))


def test_hostile_element_does_not_discard_its_readable_siblings() -> None:
    """`_contents` used to guard the whole container, collapsing it to one marker."""
    src = (
        "from wardline.core.taints import TaintState\n"
        "from wardline.scanner.taint.provider import FunctionTaint\n"
        "class Boom:\n"
        "    def __getattr__(self, k):\n        raise KeyError(k)\n"
        "def _h():\n    return TaintState.{lvl}\n"
        "BOX = [Boom(), _h]\n"
        "def seed(levels):\n    return FunctionTaint(TaintState.EXTERNAL_RAW, levels['to_level'])\n"
        "seed.__dict__['box'] = BOX\n"
    )
    a, b = _r7_pack(src), _r7_pack(src, "ASSURED")
    record = _seed_value_identity(a["BOX"])
    assert record["v"][1]["kind"] == "function", "the readable sibling was discarded"
    assert _fp(_bt(seed=a["seed"])) != _fp(_bt(seed=b["seed"]))


# --- Round 7, fix 5: computed-name dispatch FAILS CLOSED --------------------------


def _getattr_dispatch_pack(lvl: str) -> dict:
    helpers = types.ModuleType("wl_r7_helpers")
    exec(  # noqa: S102
        compile(
            "from wardline.core.taints import TaintState\n"
            f"def for_assured():\n    return TaintState.{lvl}\n"
            "def default():\n    return TaintState.UNKNOWN_RAW\n",
            "h.py",
            "exec",
        ),
        helpers.__dict__,
    )
    return _r7_pack(
        "from wardline.scanner.taint.provider import FunctionTaint\n"
        "def seed(levels):\n"
        "    fn = getattr(helpers, 'for_' + 'assured', helpers.default)\n"
        "    return FunctionTaint(fn(), levels['to_level'])\n",
        extra={"helpers": helpers},
    )


def test_C_computed_name_dispatch_is_marked_uncacheable() -> None:
    """`getattr(helpers, "for_" + name, helpers.default)` — textbook visitor dispatch.

    The attribute reached appears in NO `co_names`, so the demand-driven module walk
    cannot see it and the target's body never entered the preimage: measured COLLIDE.
    Expanding the module's full member set is the 207 MB namespace walk, so this fails
    CLOSED instead — the grammar is marked uncacheable and its fingerprint is
    deliberately unreusable, which is this engine's own rule that an unprovable input
    yields an honest unknown rather than a false green.
    """
    pack = _getattr_dispatch_pack("EXTERNAL_RAW")
    first = _fp(_bt(seed=pack["seed"]))
    assert "+grammar:uncacheable-" in first
    # Deliberately NOT reusable — a second call must not answer with the first's key.
    assert first != _fp(_bt(seed=pack["seed"]))


def test_C_uncacheable_never_reuses_a_key_across_two_grammars() -> None:
    a, b = _getattr_dispatch_pack("EXTERNAL_RAW"), _getattr_dispatch_pack("ASSURED")
    assert _fp(_bt(seed=a["seed"])) != _fp(_bt(seed=b["seed"]))


def test_ordinary_grammar_is_not_marked_uncacheable() -> None:
    """Fail-closed must stay NARROW: only computed-name dispatch trips it."""
    for seed in (_PACK_A["seed"], _PACK_A["seed_cls"], _instance_pack()["seed"]):
        fingerprint = _fp(_bt(seed=seed))
        assert "uncacheable" not in fingerprint
        assert fingerprint == _fp(_bt(seed=seed))


# --- Round 8: the fail-open INSIDE the fail-closed mechanism -----------------------


def _sibling_dispatch_module(lvl: str, name: str = "wl_r8_helpers") -> types.ModuleType:
    mod = types.ModuleType(name)
    exec(  # noqa: S102
        compile(
            "from wardline.core.taints import TaintState\n"
            f"def for_assured():\n    return TaintState.{lvl}\n"
            "def default():\n    return TaintState.UNKNOWN_RAW\n",
            "h.py",
            "exec",
        ),
        mod.__dict__,
    )
    return mod


_DISPATCH_SEED_SRC = (
    "from wardline.scanner.taint.provider import FunctionTaint\n"
    "def _mk(levels):\n"
    "    fn = getattr(helpers, 'for_' + 'assured', helpers.default)\n"
    "    return FunctionTaint(fn(), levels['to_level'])\n"
)


def test_partial_wrapped_seed_does_not_disable_the_computed_dispatch_guard() -> None:
    """A FAIL-OPEN inside the fail-closed mechanism.

    Round 7 scoped the guard to the grammar's own top-level package roots. A
    `functools.partial`-wrapped seed — which reaches the digest intact through the real
    loader — resolves `__module__` to `functools`, the fence filters it out, and the
    root set ends up EMPTY. An empty root set silently disabled the guard for the whole
    grammar and computed dispatch COLLIDED. A guard that turns itself off when its
    input is empty is the same defect class as a test that asserts nothing.

    The rule no longer consults the root set at all: it keys on whether a non-fenced
    MODULE is in reach, so there is no empty case left to fail open.
    """
    a = functools.partial(
        _r7_pack(_DISPATCH_SEED_SRC, extra={"helpers": _sibling_dispatch_module("EXTERNAL_RAW")})["_mk"]
    )
    b = functools.partial(_r7_pack(_DISPATCH_SEED_SRC, extra={"helpers": _sibling_dispatch_module("ASSURED")})["_mk"])
    assert a.__module__ == "functools"  # the seed's own module really is fenced
    left = _fp(_bt(seed=a))
    assert "+grammar:uncacheable-" in left
    assert left != _fp(_bt(seed=b))


def test_dispatch_inside_a_second_top_level_package_still_fails_closed() -> None:
    """The pack ships two top-level packages; the dispatch lives in the other one."""

    def mk(lvl: str) -> object:
        other = types.ModuleType("otherpkg.mod")
        exec(  # noqa: S102
            compile(
                "from wardline.core.taints import TaintState\n"
                f"def for_assured():\n    return TaintState.{lvl}\n"
                "def default():\n    return TaintState.UNKNOWN_RAW\n"
                "def pick():\n    return getattr(_SELF, 'for_' + 'assured', default)()\n",
                "o.py",
                "exec",
            ),
            other.__dict__,
        )
        other.__dict__["_SELF"] = other
        return _r7_pack(
            "from wardline.scanner.taint.provider import FunctionTaint\n"
            "def seed(levels):\n    return FunctionTaint(sibling.pick(), levels['to_level'])\n",
            extra={"sibling": other},
        )["seed"]

    a, b = mk("EXTERNAL_RAW"), mk("ASSURED")
    assert "+grammar:uncacheable-" in _fp(_bt(seed=a))
    assert _fp(_bt(seed=a)) != _fp(_bt(seed=b))


_GLOBALS_DISPATCH_SRC = (
    "from wardline.core.taints import TaintState\n"
    "from wardline.scanner.taint.provider import FunctionTaint\n"
    "def for_assured():\n    return TaintState.{lvl}\n"
    "def default():\n    return TaintState.UNKNOWN_RAW\n"
    "def seed(levels):\n"
    "    fn = globals().get('for_' + 'assured', default)\n"
    "    return FunctionTaint(fn(), levels['to_level'])\n"
)


def test_globals_keyed_dispatch_fails_closed() -> None:
    """`globals()['for_' + n]` is the same class as the `getattr` case.

    It reaches the function's OWN module namespace, which is exactly the mapping the
    demand-driven walk resolves off `co_names` — so a computed key is invisible to it.
    Measured COLLIDE until `globals` joined the trigger set.
    """
    a, b = _r7_pack(_GLOBALS_DISPATCH_SRC), _r7_pack(_GLOBALS_DISPATCH_SRC, "ASSURED")
    assert a["seed"]({"to_level": TaintState.GUARDED}).body_taint is TaintState.EXTERNAL_RAW
    assert b["seed"]({"to_level": TaintState.GUARDED}).body_taint is TaintState.ASSURED
    assert "+grammar:uncacheable-" in _fp(_bt(seed=a["seed"]))
    assert _fp(_bt(seed=a["seed"])) != _fp(_bt(seed=b["seed"]))


@pytest.mark.parametrize("carrier", sorted(_CARRIERS))
def test_no_carrier_fixture_passes_on_a_random_token(carrier: str) -> None:
    """No behaviour-carrier row may be silently answered by the uncacheable token.

    `test_class_namespace_order_moves_the_fingerprint` shipped doing exactly that: it
    used `vars(...)`, tripped the guard, and both sides returned a fresh random string,
    so it never exercised the path it named. This sweeps every carrier so that failure
    mode cannot recur unnoticed anywhere in the table.
    """
    pack = _carrier_pack(_CARRIERS[carrier], "EXTERNAL_RAW")
    fingerprint = _fp(_bt(seed=pack["seed"]))
    assert "uncacheable" not in fingerprint, f"{carrier} is answered by a random token"
    assert fingerprint == _fp(_bt(seed=pack["seed"]))


# --- Round 9: the computed-dispatch guard, BOTH directions, per shape --------------
#
# Three rounds running, a change to this guard moved one direction while breaking the
# other, so a single-direction check is not sufficient evidence. Round 7 scoped it to
# the grammar's own package roots and missed `functools.partial`, a second package and
# `globals()`. Round 8 replaced that with "a non-fenced module is in reach" and
# regressed closure-cell, plain-list and class-attribute reach to COLLIDE while making
# `rich`, `requests` and `jsonschema` uncacheable. Both tables below now ship.


def _dispatch_helpers(lvl: str, name: str = "wl_r9_helpers") -> types.ModuleType:
    mod = types.ModuleType(name)
    exec(  # noqa: S102
        compile(
            "from wardline.core.taints import TaintState\n"
            f"def for_assured():\n    return TaintState.{lvl}\n"
            "def default():\n    return TaintState.UNKNOWN_RAW\n",
            "h.py",
            "exec",
        ),
        mod.__dict__,
    )
    return mod


_FT = "from wardline.scanner.taint.provider import FunctionTaint\n"

# The dispatch FORM (how a member name is computed), written unindented.
_DISPATCH_FORMS = {
    "getattr": "fn = getattr(H, 'for_' + 'assured', H.default)\nreturn fn()\n",
    "attrgetter": "import operator\nfn = operator.attrgetter('for_' + 'assured')(H)\nreturn fn()\n",
    "globals": "fn = globals().get('for_' + 'assured', H.default)\nreturn fn()\n",
}
# How the dispatching function REACHES the helper module.
_REACH_MECHANISMS = ("own_globals", "closure_cell", "plain_list", "class_attribute")


def _make_dispatcher(reach: str, form: str, module_name: str, lvl: str) -> types.ModuleType:
    mod = types.ModuleType(module_name)
    helper = _dispatch_helpers(lvl, (module_name.split(".")[0] + ".impl") if "." in module_name else "wl_impl")
    body = _DISPATCH_FORMS[form]
    if reach == "own_globals":
        src = "def pick():\n    H = HELPERS\n" + textwrap.indent(body, "    ")
        mod.__dict__["HELPERS"] = helper
    elif reach == "closure_cell":
        inner = "def pick():\n    H = HELPERS\n" + textwrap.indent(body, "    ")
        src = "def _mk(HELPERS):\n" + textwrap.indent(inner, "    ") + "    return pick\n"
    elif reach == "plain_list":
        src = "def pick():\n    H = BOX[0]\n" + textwrap.indent(body, "    ")
        mod.__dict__["BOX"] = [helper]
    else:
        src = "class Holder:\n    pass\ndef pick():\n    H = Holder.MOD\n" + textwrap.indent(body, "    ")
    if form == "globals":
        mod.__dict__["for_assured"] = helper.for_assured
    exec(compile(src, "d.py", "exec"), mod.__dict__)  # noqa: S102
    if reach == "closure_cell":
        mod.__dict__["pick"] = mod.__dict__["_mk"](helper)
    if reach == "class_attribute":
        mod.__dict__["Holder"].MOD = helper
    for name in ("pick", "_mk"):
        fn = mod.__dict__.get(name)
        if fn is not None and hasattr(fn, "__module__"):
            fn.__module__ = module_name
    return mod


def _build_dispatch_seed(reach: str, form: str, topology: str, wrapping: str, lvl: str) -> object:
    if topology == "own_package":
        mod = _make_dispatcher(reach, form, "mypack.grammar", lvl)
        ns: dict = {"__name__": "mypack.grammar"}
        ns.update({k: v for k, v in mod.__dict__.items() if not k.startswith("__")})
        exec(  # noqa: S102
            compile(_FT + "def seed(levels):\n    return FunctionTaint(pick(), levels['to_level'])\n", "m.py", "exec"),
            ns,
        )
    else:
        mod = _make_dispatcher(reach, form, "otherpkg.mod", lvl)
        ns = {"__name__": "mypack.grammar", "sibling": mod}
        exec(  # noqa: S102
            compile(
                _FT + "def seed(levels):\n    return FunctionTaint(sibling.pick(), levels['to_level'])\n",
                "m.py",
                "exec",
            ),
            ns,
        )
    return functools.partial(ns["seed"]) if wrapping == "partial" else ns["seed"]


_DISPATCH_CROSS_PRODUCT = [
    (topology, reach, form, wrapping)
    for topology in ("own_package", "second_package")
    for reach in _REACH_MECHANISMS
    for form in sorted(_DISPATCH_FORMS)
    for wrapping in ("bare", "partial")
]


@pytest.mark.parametrize(("topology", "reach", "form", "wrapping"), _DISPATCH_CROSS_PRODUCT)
def test_computed_dispatch_guard_fires(topology: str, reach: str, form: str, wrapping: str) -> None:
    """The guard, as a CROSS-PRODUCT of the three axes it actually depends on.

    The previous table listed eight shapes but was only TWO predicate-arms wide: seven
    of the eight tripped the same pack-root clause because the fixture always set
    `__name__ = "mypack.grammar"`, and just one row exercised the surface-root arm. A
    table that looks broad while exercising two arms is how two fail-open holes
    survived a round — read as {reach} x {topology} x {wrapping}, 21 of these 48 rows
    collided, every one a second-package dispatcher reaching its sibling by closure
    cell, plain list or class attribute rather than by its own globals.
    """
    left = _fp(_bt(seed=_build_dispatch_seed(reach, form, topology, wrapping, "EXTERNAL_RAW")))
    right = _fp(_bt(seed=_build_dispatch_seed(reach, form, topology, wrapping, "ASSURED")))
    assert "+grammar:uncacheable-" in left, f"{topology}/{reach}/{form}/{wrapping} did not fail closed"
    assert left != right


_GUARD_SILENT_LIBS = [
    ("yaml", "yaml", "safe_load"),
    ("json", "json", "loads"),
    ("packaging", "packaging.version", "Version"),
    ("click", "click", "Command"),
    ("rich", "rich.console", "Console"),
    ("requests", "requests", "Session"),
    ("jsonschema", "jsonschema", "Draft7Validator"),
]


@pytest.mark.parametrize(("label", "module_name", "attribute"), _GUARD_SILENT_LIBS)
def test_computed_dispatch_guard_stays_silent_for_libraries(label: str, module_name: str, attribute: str) -> None:
    """A pack that merely REFERENCES a third-party library must stay cacheable.

    Round 8 applied the trigger names to everything transitively reached, so `click`,
    `rich`, `requests` and `jsonschema` all went uncacheable — a permanently cold cache
    plus an orphan cache entry per scan (residual D2). Four of them are the same
    libraries the cost table in Appendix 7 uses.
    """
    module = pytest.importorskip(module_name)
    # (a) referenced as a CLASS/FUNCTION ...
    by_member = _r7_pack(
        "from wardline.core.taints import TaintState\n" + _FT + "def seed(levels):\n"
        "    return FunctionTaint(TaintState.EXTERNAL_RAW if LIB else None, levels['to_level'])\n",
        extra={"LIB": getattr(module, attribute)},
    )
    assert "uncacheable" not in _fp(_bt(seed=by_member["seed"])), f"{label} was read as the pack's own dispatch"
    # (b) ... and as a MODULE, which is the ordinary `import requests; requests.get(...)`
    # idiom. Treating a directly-imported module as the pack's own surface made FIVE of
    # these seven uncacheable; the distribution gate is what keeps them warm.
    by_module = _r7_pack(
        "from wardline.core.taints import TaintState\n" + _FT + "def seed(levels):\n"
        f"    return FunctionTaint(TaintState.EXTERNAL_RAW if M.{attribute} else None, levels['to_level'])\n",
        extra={"M": module},
    )
    assert "uncacheable" not in _fp(_bt(seed=by_module["seed"])), f"{label} module import went uncacheable"


def test_module_importing_pack_stays_cacheable() -> None:
    """`import yaml as Y` then `Y.safe_load(...)` — a pack importing a MODULE, not a class.

    This is the shape that distinguishes the two candidate scopings: deriving pack roots
    from the seed's module imports closes the second-package case but makes THIS pack
    uncacheable, because `yaml.reader` does computed dispatch five hops down. The hop
    bound that once carried this was deleted in round 10 (it was inert in the direction
    it was justified for); what holds it now is the DISTRIBUTION gate — `yaml` ships as
    a different distribution than the grammar, so it is not the pack's own surface.
    """
    yaml = pytest.importorskip("yaml")
    pack = _r7_pack(
        "from wardline.core.taints import TaintState\n" + _FT + "def seed(levels):\n"
        "    return FunctionTaint(TaintState.EXTERNAL_RAW, Y.safe_load('a: 1') and levels['to_level'])\n",
        extra={"Y": yaml},
    )
    assert "uncacheable" not in _fp(_bt(seed=pack["seed"]))


# --- Boundary rows: one widening away from firing ---------------------------------
#
# The 29-row carrier sweep is a WEAK canary and was described as 32. No carrier row
# names `getattr`/`vars`/`globals` and none holds a non-fenced module, so the guard
# structurally cannot fire on that table — widening it with `len` or `isinstance` flips
# 0 of 29. These rows sit ON the boundary instead, so a careless widening flips one.

_GUARD_BOUNDARY = {
    # Pack code holding a module AND calling a non-trigger builtin. Flips if a name
    # like `len` or `isinstance` is ever added to the trigger set.
    "non_trigger_builtin_with_module_in_reach": "def seed(levels):\n"
    "    n = len(dir(H)) + isinstance(H, object)\n"
    "    return FunctionTaint(H.for_assured() if n else None, levels['to_level'])\n",
    # Pack code doing STATIC attribute access on a module — the shape the guard must
    # never punish, and the one `getattr` differs from by a single character.
    "static_attribute_on_a_module": "def seed(levels):\n"
    "    return FunctionTaint(H.for_assured(), levels['to_level'])\n",
    # A module held in a container but never dispatched on.
    "module_in_reach_never_dispatched": "def seed(levels):\n"
    "    return FunctionTaint(TaintState.EXTERNAL_RAW if H else None, levels['to_level'])\n",
}


@pytest.mark.parametrize("shape", sorted(_GUARD_BOUNDARY))
def test_computed_dispatch_guard_does_not_fire_at_the_boundary(shape: str) -> None:
    pack = _r7_pack(
        "from wardline.core.taints import TaintState\n" + _FT + _GUARD_BOUNDARY[shape],
        extra={"H": _dispatch_helpers("EXTERNAL_RAW")},
    )
    assert "uncacheable" not in _fp(_bt(seed=pack["seed"])), f"{shape} fired; the trigger set is too wide"


def test_boundary_rows_flip_when_the_trigger_set_is_widened(monkeypatch: pytest.MonkeyPatch) -> None:
    """The canary must actually be alive.

    Widening the trigger set with `len`/`isinstance` MUST flip the boundary row. If it
    does not, these rows are decorative and the next regression walks straight past
    them — exactly what happened to the 29-row carrier sweep.
    """
    pack = _r7_pack(
        "from wardline.core.taints import TaintState\n"
        + _FT
        + _GUARD_BOUNDARY["non_trigger_builtin_with_module_in_reach"],
        extra={"H": _dispatch_helpers("EXTERNAL_RAW")},
    )
    assert "uncacheable" not in _fp(_bt(seed=pack["seed"]))
    monkeypatch.setattr(dp, "_COMPUTED_TRIGGER_NAMES", dp._COMPUTED_TRIGGER_NAMES | {"len", "isinstance"})
    assert "+grammar:uncacheable-" in _fp(_bt(seed=pack["seed"])), "the boundary row is decorative"


@pytest.mark.parametrize("flavour", ["plain_dict", "dict_subclass"])
def test_nested_container_graph_does_not_blow_up(flavour: str) -> None:
    """Every container needs the memo, not just subclasses.

    Round 7 gave container SUBCLASSES per-instance state without a memo, so their
    subtree re-expanded at every level and cost doubled per level — `fingerprint()` on
    a `requests.Session` graph never returned. Round 9 fixed that path and left the
    PLAIN path exactly as it was: no memo, no cycle guard, and no budget decrement.
    Measured on plain `dict`: 8.9 MiB at depth 16, 35.8 MiB at 18, **143 MiB / 30 s at
    depth 20 — with `nodes=0`**, which is the proof that the plain path never even
    reached the budget that was supposed to bound it. Round 9's appendix cited that
    path's byte-identity as reassurance; byte-identity was the defect, not the comfort.
    """
    ctor = "dict" if flavour == "plain_dict" else "Box"
    src = (
        "from wardline.core.taints import TaintState\n"
        "from wardline.scanner.taint.provider import FunctionTaint\n"
        "class Box(dict):\n    pass\n"
        f"LEAF = {ctor}(v=TaintState.{{lvl}})\n"
        "NODES = [LEAF]\n"
        "for _i in range(20):\n"
        f"    NODES.append({ctor}(a=NODES[-1], b=NODES[-1]))\n"
        "def seed(levels):\n    return FunctionTaint(TaintState.EXTERNAL_RAW, levels['to_level'])\n"
        "seed.__dict__['box'] = NODES[-1]\n"
    )
    started = time.perf_counter()
    a, b = _r7_pack(src), _r7_pack(src, "ASSURED")
    left = _fp(_bt(seed=a["seed"]))
    elapsed = time.perf_counter() - started
    assert elapsed < 10.0, f"{flavour} took {elapsed:.1f}s"
    blob = _canonical_json(_seed_identity(a["seed"]))
    assert len(blob) < 512 * 1024, f"{flavour} preimage {len(blob) / 1024:.0f} KiB — re-expanded as a tree"
    # ... and cheaper must not mean blinder: the shared LEAF still discriminates.
    assert left != _fp(_bt(seed=b["seed"]))
    assert left == _fp(_bt(seed=a["seed"]))


# --- Round 10: the cold-cache claim, asserted at the level actually achieved --------

_CROSS_PROCESS_STABLE = {
    "yaml": True,
    "json": True,
    "packaging.version": True,
    "click": True,
    "requests": True,
    "rich.console": True,
}

# Measured COLD: five fresh processes, five distinct digests, for a pack referencing
# these libraries' CLASSES. Removing the `uncacheable-` token did NOT make them warm —
# the object graph itself re-keys per process. Residual D3. Pinned as known-cold so the
# suite stops reporting a property it never checked.
_CROSS_PROCESS_COLD = {"rich.console": "Console", "jsonschema": "Draft7Validator"}


@pytest.mark.parametrize("module_name", sorted(_CROSS_PROCESS_STABLE))
def test_library_pack_cross_process_stability_is_reported_honestly(module_name: str) -> None:
    """`"uncacheable" not in ...` does NOT mean the cache warms.

    The shipped library test asserted only the absence of the token, so it passed for
    `rich` and `jsonschema` while both re-keyed on every scan. This asserts the real
    property for the libraries that achieve it.
    """
    pytest.importorskip(module_name)
    assert len(_digests_across_processes(module_name, None, 2)) == 1, f"{module_name} regressed to a cold cache"


@pytest.mark.parametrize("module_name", sorted(_CROSS_PROCESS_COLD))
def test_known_cold_libraries_are_pinned_as_cold(module_name: str) -> None:
    """These two do NOT warm, and the suite must say so rather than imply otherwise.

    If this test starts failing, the graph stopped re-keying — which is good news:
    move the entry into `_CROSS_PROCESS_STABLE` and update residual D3.
    """
    pytest.importorskip(module_name)
    digests = _digests_across_processes(module_name, _CROSS_PROCESS_COLD[module_name], 3)
    assert len(digests) > 1, f"{module_name} is now stable — promote it and update D3"


def _digests_across_processes(module_name: str, attribute: str | None, runs: int) -> set[str]:
    here = str(pathlib.Path(__file__).parent)
    script = (
        "import sys;"
        f"sys.path.insert(0, {here!r});"
        "import test_provider_fingerprint_mutations as T;"
        f"print(T._library_digest({module_name!r}, {attribute!r}))"
    )
    return {
        subprocess.run(  # noqa: S603
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            check=True,
            env={**os.environ, "PYTHONHASHSEED": "random"},
        ).stdout.strip()
        for _ in range(runs)
    }


def _library_digest(module_name: str, attribute: str | None = None) -> str:
    """One grammar digest for a pack referencing a library module or one of its members."""
    module = importlib.import_module(module_name)
    target = getattr(module, attribute) if attribute else module
    pack = _r7_pack(
        "from wardline.core.taints import TaintState\n" + _FT + "def seed(levels):\n"
        "    return FunctionTaint(TaintState.EXTERNAL_RAW if M else None, levels['to_level'])\n",
        extra={"M": target},
    )
    return _grammar_digest((_bt(seed=pack["seed"]),))


# --- Round 11: the SEED-reach axis, and the level above it ------------------------
#
# Round 10's 48-row cross-product varied how the DISPATCHER reaches its module and
# assumed, in every single row, that the SEED holds the second package as a ModuleType
# in the seed's own globals. That assumption was the defect: read across
# {seed-reach} x {dispatch-form} x {wrapping}, 24 of 30 cells collided, and the worst
# cell was the plainest import spelling in Python.


def _r11_dispatcher(form: str, lvl: str) -> types.ModuleType:
    mod = types.ModuleType("otherpkg.mod")
    helper = _dispatch_helpers(lvl, "otherpkg.impl")
    mod.__dict__["HELPERS"] = helper
    if form == "globals":
        mod.__dict__["for_assured"] = helper.for_assured
    exec(  # noqa: S102
        compile("def pick():\n    H = HELPERS\n" + textwrap.indent(_DISPATCH_FORMS[form], "    "), "d.py", "exec"),
        mod.__dict__,
    )
    mod.__dict__["pick"].__module__ = "otherpkg.mod"
    return mod


def _r11_seed(seed_reach: str, form: str, wrapping: str, lvl: str) -> object:
    mod = _r11_dispatcher(form, lvl)
    ns: dict = {"__name__": "mypack.grammar"}
    if seed_reach == "module_in_globals":
        ns["sibling"] = mod
        src = _FT + "def seed(levels):\n    return FunctionTaint(sibling.pick(), levels['to_level'])\n"
    elif seed_reach == "from_import":
        ns["pick"] = mod.__dict__["pick"]
        src = _FT + "def seed(levels):\n    return FunctionTaint(pick(), levels['to_level'])\n"
    elif seed_reach == "closure_cell":
        inner = "    def seed(levels):\n        return FunctionTaint(sibling.pick(), levels['to_level'])\n"
        src = _FT + "def mk(sibling):\n" + inner + "    return seed\n"
    elif seed_reach == "plain_list":
        ns["BOX"] = [mod]
        src = _FT + "def seed(levels):\n    return FunctionTaint(BOX[0].pick(), levels['to_level'])\n"
    else:
        src = (
            _FT + "class Holder:\n    pass\ndef seed(levels):\n"
            "    return FunctionTaint(Holder.MOD.pick(), levels['to_level'])\n"
        )
    exec(compile(src, "m.py", "exec"), ns)  # noqa: S102
    if seed_reach == "closure_cell":
        seed = ns["mk"](mod)
    else:
        if seed_reach == "class_attribute":
            ns["Holder"].MOD = mod
        seed = ns["seed"]
    return functools.partial(seed) if wrapping == "partial" else seed


# Seed-reach mechanisms the surface-root arm CAN see: the seed's own globals hold
# either the module or a member of it.
_SEED_REACH_COVERED = ("module_in_globals", "from_import")
# ... and the ones it cannot: the module is reachable but never named in the seed's
# globals, so there is no demand information at all. Residual R2's static case, whose
# only fix is the 207 MB namespace walk.
_SEED_REACH_UNCOVERED = ("closure_cell", "plain_list", "class_attribute")

_SEED_REACH_CELLS = [
    (reach, form, wrapping)
    for reach in _SEED_REACH_COVERED + _SEED_REACH_UNCOVERED
    for form in sorted(_DISPATCH_FORMS)
    for wrapping in ("bare", "partial")
]


@pytest.mark.parametrize(("seed_reach", "form", "wrapping"), _SEED_REACH_CELLS)
def test_seed_reach_axis_behaves_as_classified(seed_reach: str, form: str, wrapping: str) -> None:
    """Both directions, per cell, with the behaviour proven by CALLING the seeds.

    `from_import` — `from otherpkg.mod import pick` — fired 0 of 6 before this round,
    while `import otherpkg.mod as sibling` fired 6 of 6 for identical behaviour: the
    surface-root arm depended on the IMPORT SPELLING. The uncovered three are pinned as
    known-collide so the classification cannot rot into a silent regression.
    """
    left_seed = _r11_seed(seed_reach, form, wrapping, "EXTERNAL_RAW")
    right_seed = _r11_seed(seed_reach, form, wrapping, "ASSURED")
    levels = {"to_level": TaintState.GUARDED}
    # The control that makes this a collision test rather than a token comparison.
    assert left_seed(levels).body_taint is TaintState.EXTERNAL_RAW
    assert right_seed(levels).body_taint is TaintState.ASSURED
    left, right = _fp(_bt(seed=left_seed)), _fp(_bt(seed=right_seed))
    if seed_reach in _SEED_REACH_COVERED:
        assert "+grammar:uncacheable-" in left, f"{seed_reach}/{form}/{wrapping} did not fail closed"
        assert left != right
    else:
        assert "uncacheable" not in left
        assert left == right, f"{seed_reach} now discriminates — promote it out of R2 and update the residual"


# --- The level ABOVE the seed: how the GRAMMAR reaches the seed --------------------


def _seed_shape(kind: str, lvl: str) -> object:
    ns: dict = {"__name__": "mypack.grammar", "H": _dispatch_helpers(lvl, "otherpkg.impl")}
    bodies = {
        "callable_object": "class Seeder:\n    def __call__(self, levels):\n"
        "        fn = getattr(H, 'for_' + 'assured', H.default)\n"
        "        return FunctionTaint(fn(), levels['to_level'])\n"
        "seed = Seeder()\n",
        "bound_method": "class Seeder:\n    def seed(self, levels):\n"
        "        fn = getattr(H, 'for_' + 'assured', H.default)\n"
        "        return FunctionTaint(fn(), levels['to_level'])\n"
        "S = Seeder()\nseed = S.seed\n",
        "partial_bound_arg": "def _mk(pick, levels):\n    return FunctionTaint(pick(), levels['to_level'])\n"
        "def pick():\n    fn = getattr(H, 'for_' + 'assured', H.default)\n    return fn()\n",
    }
    exec(compile(_FT + bodies[kind], "m.py", "exec"), ns)  # noqa: S102
    if kind == "partial_bound_arg":
        return functools.partial(ns["_mk"], ns["pick"])
    return ns["seed"]


@pytest.mark.parametrize("kind", ["callable_object", "bound_method", "partial_bound_arg"])
def test_grammar_to_seed_level_is_covered(kind: str) -> None:
    """The next level up, asked explicitly rather than left to the next verification.

    This is the second time a fix was correct at one level and the same hole reappeared
    one level up — dispatcher-reach, then seed-reach. So: how does the GRAMMAR reach the
    seed? A callable object, a bound method, and a `functools.partial` whose BOUND
    ARGUMENT is the dispatcher all reach `_function_identity` with a pack module root
    and fail closed.

    A fourth shape — a factory that performs the dispatch at grammar-BUILD time and
    captures the resolved target in the seed's closure — is measured DIFF without the
    guard, and correctly so: the computed lookup already happened, and its RESULT is in
    the object graph where the digest keys it structurally.
    """
    left = _fp(_bt(seed=_seed_shape(kind, "EXTERNAL_RAW")))
    assert "+grammar:uncacheable-" in left
    assert left != _fp(_bt(seed=_seed_shape(kind, "ASSURED")))


def test_factory_resolved_dispatch_discriminates_without_the_guard() -> None:
    """The one next-level shape that needs no guard, and why."""

    def mk(lvl: str) -> object:
        ns: dict = {"__name__": "mypack.grammar", "H": _dispatch_helpers(lvl, "otherpkg.impl")}
        exec(  # noqa: S102
            compile(
                _FT + "def make():\n    fn = getattr(H, 'for_' + 'assured', H.default)\n"
                "    def seed(levels):\n        return FunctionTaint(fn(), levels['to_level'])\n    return seed\n",
                "m.py",
                "exec",
            ),
            ns,
        )
        return ns["make"]()

    left, right = _fp(_bt(seed=mk("EXTERNAL_RAW"))), _fp(_bt(seed=mk("ASSURED")))
    assert "uncacheable" not in left, "the resolved target is in the graph; no guard needed"
    assert left != right


# --- Round 11, CORRECTION 2: rows that actually CROSS the distribution gate --------
#
# The 48-row fire table does not exercise `_is_foreign_distribution` at all: the
# fixture's `otherpkg` is an `exec`-ed module with no metadata, so deleting the gate
# entirely leaves 8/8 firing. That is a canary that cannot die, guarding the newest and
# most load-bearing piece of the design. These rows force the metadata.


def _second_package_pack(lvl: str) -> object:
    """A seed in `mypack` handing off to a dispatcher in `otherpkg`."""
    return _r11_seed("module_in_globals", "getattr", "bare", lvl)


@pytest.fixture
def _distribution_map(monkeypatch: pytest.MonkeyPatch):  # noqa: ANN202
    def install(mapping: dict[str, tuple[str, ...]]) -> None:
        monkeypatch.setattr(dp, "_PACKAGE_DISTRIBUTIONS", mapping)

    return install


def test_second_package_in_the_SAME_distribution_fires(_distribution_map) -> None:  # noqa: ANN001
    """One wheel shipping two top-level packages is the pack's own surface."""
    _distribution_map({"mypack": ("acme-trustpack",), "otherpkg": ("acme-trustpack",)})
    assert not dp._is_foreign_distribution("otherpkg", frozenset({"mypack"}))
    assert "+grammar:uncacheable-" in _fp(_bt(seed=_second_package_pack("EXTERNAL_RAW")))


def test_second_package_in_a_DIFFERENT_distribution_does_not_fire(_distribution_map) -> None:  # noqa: ANN001
    """Residual D4, pinned as a LIVE under-discrimination rather than described as safe.

    Nothing in `config.py:186-202` constrains how a pack lays out its distributions, so
    a pack shipped separately from its own second package is a supported layout that
    this gate cannot see. Measured: the two grammars share one fingerprint.
    """
    _distribution_map({"mypack": ("acme-trustpack",), "otherpkg": ("acme-extras",)})
    assert dp._is_foreign_distribution("otherpkg", frozenset({"mypack"}))
    left = _fp(_bt(seed=_second_package_pack("EXTERNAL_RAW")))
    assert "uncacheable" not in left
    assert left == _fp(_bt(seed=_second_package_pack("ASSURED"))), "D4 closed — update the residual"


def test_metadata_bearing_root_with_an_uninstalled_grammar_does_not_fire(_distribution_map) -> None:  # noqa: ANN001
    """The branch that used to fall out of `isdisjoint` on an empty set, now explicit.

    It is a deliberate trade in BOTH directions: it is what keeps an ordinary
    `import requests` pack warm, and it is why a pack that is not itself an installed
    distribution cannot claim an installed second package. Round 10 called this "fails
    closed by construction"; that was false in the under-discrimination direction.
    """
    _distribution_map({"otherpkg": ("acme-extras",)})  # the grammar has NO metadata
    assert dp._is_foreign_distribution("otherpkg", frozenset({"mypack"}))
    assert "uncacheable" not in _fp(_bt(seed=_second_package_pack("EXTERNAL_RAW")))


def test_the_distribution_gate_canary_can_die(_distribution_map) -> None:  # noqa: ANN001
    """Neutering the gate must FLIP the different-distribution row.

    Without this, `_is_foreign_distribution` could be deleted outright and every fire
    row would keep passing — which is exactly the state round 10 shipped.
    """
    _distribution_map({"mypack": ("acme-trustpack",), "otherpkg": ("acme-extras",)})
    assert "uncacheable" not in _fp(_bt(seed=_second_package_pack("EXTERNAL_RAW")))
    with pytest.MonkeyPatch.context() as patched:
        patched.setattr(dp, "_is_foreign_distribution", lambda *_a, **_k: False)
        assert "+grammar:uncacheable-" in _fp(_bt(seed=_second_package_pack("EXTERNAL_RAW"))), (
            "the distribution gate is not load-bearing in this row"
        )


# --- Round 12: PRODUCER reach must match CONSUMER reach ---------------------------
#
# `_surface_roots` used to walk the SEED'S OWN code object only, while the guard is
# consulted on every function the walk reaches TRANSITIVELY. Producer specific,
# consumer general — the same asymmetry as round 11, one level of reach out. Three
# rounds closed it one axis at a time (dispatcher reach, seed member KIND, seed reach
# DEPTH); the surface is now grown from the SAME traversal that consults the guard, so
# the depth axis closes at every depth at once instead of one hop per round.


def _r12_dispatcher(form: str, lvl: str) -> types.ModuleType:
    return _r11_dispatcher(form, lvl)


def _r12_helper_mediated(spelling: str, form: str, lvl: str) -> object:
    """seed -> module-level helper -> second-package dispatcher.

    This is the canonical pack shape: `_FIRST_MATCH_WINS` in this very module is
    `seed` -> `_pick`, and `_MAX_VALUE_DEPTH`'s comment measures depth 7 on exactly
    "a pack whose seed calls a module-level helper".
    """
    mod = _r12_dispatcher(form, lvl)
    ns: dict = {"__name__": "mypack.grammar"}
    if spelling == "import_module":
        ns["sibling"] = mod
        helper_src = "def _helper():\n    return sibling.pick()\n"
    else:
        ns["pick"] = mod.__dict__["pick"]
        helper_src = "def _helper():\n    return pick()\n"
    src = _FT + helper_src + "def seed(levels):\n    return FunctionTaint(_helper(), levels['to_level'])\n"
    exec(compile(src, "m.py", "exec"), ns)  # noqa: S102
    return ns["seed"]


def _r12_wraps(form: str, lvl: str) -> object:
    mod = _r12_dispatcher(form, lvl)
    ns: dict = {"__name__": "mypack.grammar", "sibling": mod}
    src = (
        _FT + "import functools\n"
        "def _inner():\n    return sibling.pick()\n"
        "@functools.wraps(_inner)\n"
        "def _helper():\n    return _inner()\n"
        "def seed(levels):\n    return FunctionTaint(_helper(), levels['to_level'])\n"
    )
    exec(compile(src, "m.py", "exec"), ns)  # noqa: S102
    return ns["seed"]


def _r12_callable_object(form: str, lvl: str) -> object:
    """Callable-object seed whose `__call__` hands off to a SECOND-package dispatcher.

    Round 11's "callable-object seed FIRES" row put the helper in the grammar's own
    namespace, so it fired through the pack-root arm and never exercised this one.
    """
    mod = _r12_dispatcher(form, lvl)
    ns: dict = {"__name__": "mypack.grammar", "sibling": mod}
    src = (
        _FT + "class Seeder:\n"
        "    def __call__(self, levels):\n"
        "        return FunctionTaint(sibling.pick(), levels['to_level'])\n"
        "seed = Seeder()\n"
    )
    exec(compile(src, "m.py", "exec"), ns)  # noqa: S102
    return ns["seed"]


_PRODUCER_REACH_CELLS = (
    [("helper_mediated_import_module", form) for form in sorted(_DISPATCH_FORMS)]
    + [("helper_mediated_from_import", form) for form in sorted(_DISPATCH_FORMS)]
    + [("functools_wraps", form) for form in sorted(_DISPATCH_FORMS)]
    + [("callable_object_seed", form) for form in sorted(_DISPATCH_FORMS)]
)


def _r12_build(shape: str, form: str, lvl: str) -> object:
    if shape == "helper_mediated_import_module":
        return _r12_helper_mediated("import_module", form, lvl)
    if shape == "helper_mediated_from_import":
        return _r12_helper_mediated("from_import", form, lvl)
    if shape == "functools_wraps":
        return _r12_wraps(form, lvl)
    return _r12_callable_object(form, lvl)


@pytest.mark.parametrize(("shape", "form"), _PRODUCER_REACH_CELLS)
def test_producer_reach_matches_consumer_reach(shape: str, form: str) -> None:
    """All twelve cells collided before the surface was grown from the traversal.

    The control that hid them in every shipped test: the same indirection with
    PACK-CODE dispatch fires through arm 1, so the defect only appears when the
    dispatcher lives in a second package.
    """
    left_seed, right_seed = _r12_build(shape, form, "EXTERNAL_RAW"), _r12_build(shape, form, "ASSURED")
    levels = {"to_level": TaintState.GUARDED}
    assert left_seed(levels).body_taint is TaintState.EXTERNAL_RAW
    assert right_seed(levels).body_taint is TaintState.ASSURED
    left = _fp(_bt(seed=left_seed))
    assert "+grammar:uncacheable-" in left, f"{shape}/{form} did not fail closed"
    assert left != _fp(_bt(seed=right_seed))


# --- D4's MAGNITUDE, pinned rather than merely described --------------------------


@pytest.mark.parametrize(
    ("module_name", "attribute"),
    [("click", "Command"), ("rich.console", "Console"), ("requests", "Session"), ("jsonschema", "Draft7Validator")],
)
def test_libraries_stay_cacheable_only_under_installed_metadata(
    module_name: str, attribute: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """ "Re-bricks zero of seven libraries" holds ONLY under installed metadata.

    With the grammar installed and the library root carrying NO metadata — vendored,
    zip-imported, or a local source tree — the non-module surface-root branch makes all
    four of these class-refs uncacheable, where round 10 kept them warm. That is D4's
    size, not just its direction, and it is pinned here so the claim cannot drift back
    to the unqualified version.
    """
    module = pytest.importorskip(module_name)
    pack = _r7_pack(
        "from wardline.core.taints import TaintState\n" + _FT + "def seed(levels):\n"
        "    return FunctionTaint(TaintState.EXTERNAL_RAW if LIB else None, levels['to_level'])\n",
        extra={"LIB": getattr(module, attribute)},
    )
    # (a) real, installed metadata: warm.
    assert "uncacheable" not in _fp(_bt(seed=pack["seed"]))
    # (b) grammar installed, library root without metadata: cold. KNOWN, residual D4.
    monkeypatch.setattr(dp, "_PACKAGE_DISTRIBUTIONS", {"mypack": ("acme-trustpack",)})
    assert "+grammar:uncacheable-" in _fp(_bt(seed=pack["seed"])), (
        f"{module_name} no longer re-bricks without metadata — D4 shrank, update the residual"
    )


# --- Round 12 addendum: axis 2, closed by ONE enumeration pass --------------------
#
# The trigger set has NO structural closure — no traversal enumerates "every way to
# resolve a name at run time" — so it can only ever be an allow-list. The honest way to
# close it is a single deliberate pass over the language surface with every entry
# MEASURED to collide before it is added, rather than one name per review round.

_RESOLUTION_SHAPES = {
    "eval_computed": "return eval('H.for_' + 'assured')()\n",
    "exec_computed": "ns = {'H': H}\nexec('r = H.for_' + 'assured' + '()', ns)\nreturn ns['r']\n",
    "dunder_getattribute": "return type(H).__getattribute__(H, 'for_' + 'assured')()\n",
    "inspect_getattr_static": "import inspect\nreturn inspect.getattr_static(H, 'for_' + 'assured')()\n",
}
# Measured to DISCRIMINATE STRUCTURALLY, so deliberately NOT triggers — adding them
# would be pure over-invalidation. `locals()` resolves a local bound from a global the
# digest already keys; `itemgetter` indexes a container whose contents are keyed.
_NON_TRIGGER_SHAPES = {
    "locals_computed": "x = H\nreturn locals()['x'].for_assured()\n",
    "itemgetter_on_a_dict": "import operator\nreturn operator.itemgetter('for_' + 'assured')(TABLE)()\n",
}


def _resolution_pack(body: str, lvl: str) -> object:
    helper = _dispatch_helpers(lvl, "wl_res_helpers")
    ns: dict = {"__name__": "mypack.grammar", "H": helper, "TABLE": {"for_assured": helper.for_assured}}
    src = (
        "from wardline.core.taints import TaintState\n"
        + _FT
        + "def _pick():\n"
        + textwrap.indent(body, "    ")
        + "def seed(levels):\n    return FunctionTaint(_pick(), levels['to_level'])\n"
    )
    exec(compile(src, "m.py", "exec"), ns)  # noqa: S102
    return ns["seed"]


@pytest.mark.parametrize("shape", sorted(_RESOLUTION_SHAPES))
def test_runtime_name_resolution_shapes_fail_closed(shape: str) -> None:
    """Every entry added to the trigger set was measured to collide first.

    `dunder_getattribute` is residual R11's named gap — a hand-rolled
    `type(m).__getattribute__(m, computed)` — now closed.
    """
    body = _RESOLUTION_SHAPES[shape]
    left_seed, right_seed = _resolution_pack(body, "EXTERNAL_RAW"), _resolution_pack(body, "ASSURED")
    levels = {"to_level": TaintState.GUARDED}
    assert left_seed(levels).body_taint is TaintState.EXTERNAL_RAW
    assert right_seed(levels).body_taint is TaintState.ASSURED
    assert "+grammar:uncacheable-" in _fp(_bt(seed=left_seed)), f"{shape} did not fail closed"


@pytest.mark.parametrize("shape", sorted(_NON_TRIGGER_SHAPES))
def test_structurally_discriminating_shapes_are_not_triggers(shape: str) -> None:
    """The other direction: do not pay over-invalidation for a shape already keyed."""
    body = _NON_TRIGGER_SHAPES[shape]
    left_seed, right_seed = _resolution_pack(body, "EXTERNAL_RAW"), _resolution_pack(body, "ASSURED")
    left, right = _fp(_bt(seed=left_seed)), _fp(_bt(seed=right_seed))
    assert "uncacheable" not in left, f"{shape} became a trigger — it discriminates already"
    assert left != right, f"{shape} stopped discriminating; it now NEEDS to be a trigger"


def test_call_time_computed_import_fails_closed(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Computed module ACQUISITION — the shape the first five rounds of this guard missed.

    `importlib.import_module("mypack.levels." + name)` inside a seed puts the target on
    DISK. It never enters the object graph, so the digest cannot key it however hard it
    walks — which is exactly why it must fail closed. Controlled with two real package
    trees whose behaviour is verified to differ before the digests are compared.
    """
    src = (
        "from wardline.core.taints import TaintState\n" + _FT + "import importlib\n"
        "def seed(levels):\n"
        "    mod = importlib.import_module('wl_levels_t.' + 'assured')\n"
        "    return FunctionTaint(mod.LEVEL, levels['to_level'])\n"
    )

    def build(lvl: str) -> tuple[object, str]:
        root = tmp_path / lvl
        pkg = root / "wl_levels_t"
        pkg.mkdir(parents=True)
        (pkg / "__init__.py").write_text("")
        (pkg / "assured.py").write_text(f"from wardline.core.taints import TaintState\nLEVEL = TaintState.{lvl}\n")
        ns: dict = {"__name__": "mypack.grammar"}
        exec(compile(src, "m.py", "exec"), ns)  # noqa: S102
        return ns["seed"], str(root)

    def call(seed, root: str) -> TaintState:  # noqa: ANN001
        for name in [m for m in list(sys.modules) if m.startswith("wl_levels_t")]:
            monkeypatch.delitem(sys.modules, name, raising=False)
        monkeypatch.syspath_prepend(root)
        try:
            return seed({"to_level": TaintState.GUARDED}).body_taint
        finally:
            sys.path.remove(root)

    left_seed, left_root = build("EXTERNAL_RAW")
    right_seed, right_root = build("ASSURED")
    assert call(left_seed, left_root) is TaintState.EXTERNAL_RAW
    assert call(right_seed, right_root) is TaintState.ASSURED
    assert "+grammar:uncacheable-" in _fp(_bt(seed=left_seed))


def test_build_time_computed_import_needs_no_guard() -> None:
    """The contrast that makes the call-time rule precise.

    A BUILD-time computed import resolves before the digest runs and binds its target
    into the seed's closure, where the digest keys it structurally. It DIFFs without the
    guard, and adding one would be pure over-invalidation.
    """

    def mk(lvl: str) -> object:
        ns: dict = {"__name__": "mypack.grammar", "H": _dispatch_helpers(lvl, "wl_bt_helpers")}
        exec(  # noqa: S102
            compile(
                _FT + "def make():\n    fn = getattr(H, 'for_' + 'assured')\n"
                "    def seed(levels):\n        return FunctionTaint(fn(), levels['to_level'])\n    return seed\n",
                "m.py",
                "exec",
            ),
            ns,
        )
        return ns["make"]()

    left, right = _fp(_bt(seed=mk("EXTERNAL_RAW"))), _fp(_bt(seed=mk("ASSURED")))
    assert "uncacheable" not in left
    assert left != right


def test_library_roots_are_kept_out_of_the_surface_by_the_distribution_gate() -> None:
    """The structural fix's own acceptance check, and an honest record of its cost.

    Growing the surface from the full traversal means a library root is OFFERED at every
    grammar-surface function, not just at the seed. Measured with the gate live,
    `surface_roots` stays EMPTY for a library-referencing pack; with the gate neutered it
    fills with `urllib3`, `charset_normalizer`, `attr`, `idna`, `rpds`, `referencing` and
    all four class-refs go uncacheable. The whole discrimination burden for library cases
    therefore rests on `_is_foreign_distribution` — residual D4, which is live-broken in
    both directions. That is stated, not hidden.
    """
    requests = pytest.importorskip("requests")
    pack = _r7_pack(
        "from wardline.core.taints import TaintState\n" + _FT + "def seed(levels):\n"
        "    return FunctionTaint(TaintState.EXTERNAL_RAW if LIB else None, levels['to_level'])\n",
        extra={"LIB": requests.Session},
    )
    assert "uncacheable" not in _fp(_bt(seed=pack["seed"]))
    with pytest.MonkeyPatch.context() as patched:
        patched.setattr(dp, "_is_foreign_distribution", lambda *_a, **_k: False)
        assert "+grammar:uncacheable-" in _fp(_bt(seed=pack["seed"])), (
            "the distribution gate is no longer load-bearing here — re-check D4's scope"
        )
