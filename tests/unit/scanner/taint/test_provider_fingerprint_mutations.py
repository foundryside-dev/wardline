"""P8 — the provider fingerprint moves iff the declaration surface moves.

Mutation table: every component of a grammar's identity (name, prefix, group,
builtin flag, level-arg schema, seed body, order) must change the fingerprint.
Reformat stability: cosmetic re-authoring of an identical seed must NOT change
it. The builtin literal is pinned so a REGISTRY_VERSION drift in S0 is loud."""

from __future__ import annotations

import os
import pathlib
import re
import subprocess
import sys
import types

import pytest

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
    inner = record["members"]["Y"]
    assert inner["t"] == "seen"
    assert re.fullmatch(r"[0-9a-f]{64}", inner["h"])
    # ... and NOTHING positional. Round 5 also put a traversal ordinal here and on
    # every expanded record, which leaked the walk's visit order into the digest and
    # made behaviour-neutral re-authoring cold-invalidate every warm cache.
    assert "n" not in inner
    # X is the first reach and carries the FULL record; Y is the back-reference.
    assert record["members"]["X"]["kind"] == "class"
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


# --- Round 6, item 1: REORDERING — the axis all 11 reformat rows missed -----------
#
# Every existing reformat-stability test varies whitespace, line numbers or filename.
# NONE of them reorders anything, and that was the shared assumption that let a
# traversal ordinal ship in round 5: `_expanded` wrote `record["n"] = ordinal`, so the
# walk's visit order entered the digest and swapping two method definitions — or two
# keys in a dict literal — cold-invalidated every warm cache for no discrimination.

_REORDER_PAIRS: dict[str, tuple[str, str]] = {
    "method_definition_order": (
        "class P:\n    def a(self):\n        return 1\n    def b(self):\n        return 2\n"
        "def seed(levels):\n    return FunctionTaint(TaintState.EXTERNAL_RAW if P else None, levels['to_level'])\n",
        "class P:\n    def b(self):\n        return 2\n    def a(self):\n        return 1\n"
        "def seed(levels):\n    return FunctionTaint(TaintState.EXTERNAL_RAW if P else None, levels['to_level'])\n",
    ),
    "dict_literal_key_order": (
        "class A:\n    pass\nclass B:\n    pass\nREG = {{'a': A, 'b': B}}\n"
        "def seed(levels):\n    return FunctionTaint(TaintState.EXTERNAL_RAW, levels['to_level'])\n"
        "seed.__dict__['r'] = REG\n",
        "class A:\n    pass\nclass B:\n    pass\nREG = {{'b': B, 'a': A}}\n"
        "def seed(levels):\n    return FunctionTaint(TaintState.EXTERNAL_RAW, levels['to_level'])\n"
        "seed.__dict__['r'] = REG\n",
    ),
    "class_attribute_order": (
        "class A:\n    pass\nclass B:\n    pass\n"
        "class REG:\n    a = A\n    b = B\n"
        "def seed(levels):\n    return FunctionTaint(TaintState.EXTERNAL_RAW if REG else None, levels['to_level'])\n",
        "class A:\n    pass\nclass B:\n    pass\n"
        "class REG:\n    b = B\n    a = A\n"
        "def seed(levels):\n    return FunctionTaint(TaintState.EXTERNAL_RAW if REG else None, levels['to_level'])\n",
    ),
}


@pytest.mark.parametrize("shape", sorted(_REORDER_PAIRS))
def test_member_reordering_does_not_move_the_fingerprint(shape: str) -> None:
    head = "from wardline.core.taints import TaintState\nfrom wardline.scanner.taint.provider import FunctionTaint\n"
    left, right = _REORDER_PAIRS[shape]
    a, b = _carrier_pack(head + left, "EXTERNAL_RAW"), _carrier_pack(head + right, "EXTERNAL_RAW")
    assert _fp(_bt(seed=a["seed"])) == _fp(_bt(seed=b["seed"])), f"{shape} cold-invalidated the cache"


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
