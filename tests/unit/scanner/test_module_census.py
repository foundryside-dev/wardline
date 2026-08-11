# tests/unit/scanner/test_module_census.py
"""The per-module binding census — form 5's ONE evaluation point (spec §4.2.1).

Sibling of ``test_module_bindings.py``. Every case is built against a PARSED
module and run through :func:`build_module_census`, never a hand-written
``ModuleCensus``, so each test exercises the real predicates rather than a
restatement of them.
"""

from __future__ import annotations

import ast
import textwrap

import pytest

from wardline.scanner.ast_primitives import build_import_alias_map
from wardline.scanner.index import discover_file_entities
from wardline.scanner.module_census import build_module_census
from wardline.scanner.taint.decorator_provider import vocabulary_star_exports

_TAINTSTATE_ALIASES = {"TaintState": "wardline.core.taints.TaintState"}


def _census(src: str, *, alias_map=None, shadowed_roots=frozenset(), star_exports=None):  # noqa: ANN001, ANN202
    tree = ast.parse(textwrap.dedent(src))
    return build_module_census(
        tree,
        alias_map=_TAINTSTATE_ALIASES if alias_map is None else alias_map,
        shadowed_roots=shadowed_roots,
        star_exports=vocabulary_star_exports() if star_exports is None else star_exports,
    )


# ── Resolution and the right-hand-side allowlist ─────────────────────────────────


def test_string_constant_right_hand_side_resolves() -> None:
    census = _census('X = "ASSURED"\n')
    assert census.values["X"].token == "ASSURED"
    assert census.values["X"].unreadable_reason is None
    assert census.values["X"].line == 1


def test_annassign_with_value_resolves_and_the_annotation_is_not_read() -> None:
    # ``X: Final = TaintState.ASSURED`` is the idiomatic DRY spelling; the census
    # reads only the right-hand side, so the annotation never enters the verdict.
    census = _census("X: Final = TaintState.ASSURED\n")
    assert census.values["X"].token == "ASSURED"


def test_annassign_without_value_is_unreadable_but_still_an_occurrence() -> None:
    # A bare ``X: Final`` binds nothing, so it cannot resolve — but it IS a
    # module-scope occurrence, which is what stops a later assignment resolving.
    census = _census("X: Final\n")
    assert census.values["X"].token is None
    assert census.values["X"].unreadable_reason is not None


@pytest.mark.parametrize(
    "rhs",
    [
        "get_level()",  # a call
        "f'{x}'",  # an f-string
        "LEVELS['x']",  # a subscript
        "'A' if flag else 'B'",  # a conditional expression
        "('ASSURED',)",  # a tuple
        "os.environ['LEVEL']",  # an environment read
        "3",  # a non-str Constant
        "True",
        "None",
        # ANOTHER BARE NAME — the one-hop-only row. The census reads right-hand
        # sides through ``level_token`` with an INLINE EMPTY census, so a bare-name
        # right-hand side resolves nothing BY CONSTRUCTION and no second hop is
        # reachable. If this row ever resolves, the census has re-entered the
        # widened reader with its own real census and form 5 has become a walk.
        "OTHER",
    ],
)
def test_right_hand_side_outside_form_1_or_2_is_unreadable(rhs: str) -> None:
    census = _census(f"X = {rhs}\n")
    assert census.values["X"].token is None
    assert census.values["X"].unreadable_reason is not None


@pytest.mark.parametrize(
    "src",
    [
        'X, Y = "ASSURED", "INTEGRAL"\n',
        'X = Y = "ASSURED"\n',
        '(X,) = ("ASSURED",)\n',
    ],
)
def test_multi_target_assignment_is_not_a_qualifying_binding(src: str) -> None:
    # Spec §4.2.1's tuple/starred/multiple-target row — "form 4's single-``Name``
    # target, verbatim" — pinned by the TARGET conjunct alone. Each form records
    # exactly ONE occurrence of ``X``, so the two-occurrence rule is not what
    # refuses it: relaxing the builder's
    # ``len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name)`` conjunct
    # would RESOLVE a binding the spec requires to be UNREADABLE, which is the
    # seed-minting direction and the only direction that ships a false green.
    census = _census(src)
    assert census.values["X"].token is None
    assert census.values["X"].unreadable_reason is not None


# ── Second occurrence, anywhere, at any depth ────────────────────────────────────


@pytest.mark.parametrize(
    "second",
    [
        'if flag:\n    X = "ASSURED"\n',
        'try:\n    X = "ASSURED"\nexcept Exception:\n    pass\n',
        'with ctx():\n    X = "ASSURED"\n',
        'if TYPE_CHECKING:\n    X = "ASSURED"\n',
        "for X in items:\n    pass\n",
        "with ctx() as X:\n    pass\n",
        "try:\n    pass\nexcept Exception as X:\n    pass\n",
        "flag = (X := 1)\n",
        'X += "!"\n',
        "import X\n",
        "from pkg import X\n",
        "def X():\n    pass\n",
        "class X:\n    pass\n",
        "del X\n",
        "match m:\n    case {'k': 1, **X}:\n        pass\n",
        "match m:\n    case [*X]:\n        pass\n",
        "match m:\n    case X:\n        pass\n",
    ],
)
def test_second_occurrence_at_any_depth_makes_the_name_unreadable(second: str) -> None:
    census = _census('X = "INTEGRAL"\n' + second)
    assert census.values["X"].token is None


def test_conditional_platform_rebind_is_unreadable_not_the_top_level_one() -> None:
    # The realistic ESCALATION shape, named because it is the one a last-wins or a
    # first-wins reader gets wrong in the seed-minting direction.
    census = _census(
        """
        X = "INTEGRAL"
        if sys.platform == "win32":
            X = "ASSURED"
        """
    )
    assert census.values["X"].token is None


def test_global_anywhere_poisons_the_name() -> None:
    # The ``global`` is inside a FUNCTION BODY — a scope walk 1 never enters — so
    # this passes only if walk 2 descends where walk 1 deliberately does not.
    census = _census(
        """
        X = "ASSURED"

        def mutate():
            global X
            X = "INTEGRAL"
        """
    )
    assert census.values["X"].token is None
    assert census.values["X"].unreadable_reason == "declared `global` in this module"


def test_class_and_function_body_bindings_do_not_enter_the_census() -> None:
    # A qualifying module-scope binding still resolves when the SAME name is bound
    # inside a function or a class body, because those are separate scopes.
    #
    # SOUND ONLY IN COMBINATION with (i) the reference-site restriction — form 5
    # resolves only for a ``def`` that is a direct element of ``Module.body``, so a
    # nested reader never reaches this entry — and (ii) the ``global`` poison, which
    # is what stops a function body writing back into module scope unseen. Neither
    # may be relaxed without re-deriving this row from scratch.
    census = _census(
        """
        X = "ASSURED"

        def f():
            X = "INTEGRAL"
            return X

        class C:
            X = "INTEGRAL"
        """
    )
    assert census.values["X"].token == "ASSURED"


# ── Star-import poison, and its anti-drift pin ───────────────────────────────────


def test_unresolved_star_import_poisons_the_module() -> None:
    census = _census('from unknown_pkg import *\nX = "ASSURED"\n')
    assert census.poisoned is True
    # The entry itself still reads — poison is a MODULE-level refusal applied by
    # the reader, not an erasure of the binding table.
    assert census.values["X"].token == "ASSURED"


@pytest.mark.parametrize(
    "nested_star",
    [
        "if enabled:\n    from unknown_pkg import *\n",
        "try:\n    from unknown_pkg import *\nexcept ImportError:\n    pass\n",
        "if enabled:\n    from wardline.decorators import *\n",
    ],
)
def test_unresolved_star_import_at_nested_module_statement_depth_poisons_the_module(nested_star: str) -> None:
    # A nested module-scope star import can overwrite X at runtime just as a direct
    # Module.body import can. The poison walk must therefore share the binding
    # census's statement-depth semantics rather than inspecting tree.body alone.
    census = _census('X = "ASSURED"\n' + nested_star)
    assert census.poisoned is True


@pytest.mark.parametrize(
    ("star", "module_path"),
    [
        ("from . import *", "pkg.mod"),  # relative — never materialised
        ("from unknown_pkg import *", "m"),  # unknown module — never materialised
        ("from wardline.decorators import *", "m"),  # known — materialised
    ],
)
def test_census_poison_agrees_with_build_import_alias_map(star: str, module_path: str) -> None:
    # THE ANTI-DRIFT PIN. ``poisoned`` must be the exact complement of whether
    # ``build_import_alias_map`` materialised that import's names — the two
    # predicates are the same question asked twice and must never diverge.
    src = f"{star}\nX = 'ASSURED'\n"
    tree = ast.parse(src)
    star_exports = vocabulary_star_exports()
    alias_map = build_import_alias_map(tree, module_path, star_exports=star_exports)
    census = build_module_census(
        tree,
        alias_map=alias_map,
        shadowed_roots=frozenset(),
        star_exports=star_exports,
    )
    materialised = bool(alias_map)
    assert census.poisoned is not materialised


# ── Reference sites ──────────────────────────────────────────────────────────────


def test_reference_sites_hold_only_direct_module_body_defs() -> None:
    src = textwrap.dedent(
        """
        def top():
            def nested():
                pass
            return nested

        async def top_async():
            pass

        class C:
            def method(self):
                pass
        """
    )
    tree = ast.parse(src)
    census = build_module_census(tree, alias_map={}, shadowed_roots=frozenset(), star_exports=vocabulary_star_exports())
    names = {node.name for node in census.reference_sites if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)}
    assert names == {"top", "top_async"}
    # ...and each is the DIRECT Module.body element, not a copy.
    assert all(site in tree.body for site in census.reference_sites)


def test_conditionally_defined_module_level_def_is_not_a_reference_site() -> None:
    # The newest and least obvious reference-site rule (spec §4.2.1): a ``def``
    # nested inside a module-level ``if`` is NOT a direct element of ``Module.body``
    # and therefore is not an eligible reference site — even though it has exactly
    # the same qualname as an unconditional one would.
    src = textwrap.dedent(
        """
        if sys.version_info >= (3, 12):
            def forked():
                pass
        else:
            def forked():
                pass

        if TYPE_CHECKING:
            def type_only():
                pass

        def plain():
            pass
        """
    )
    tree = ast.parse(src)
    census = build_module_census(tree, alias_map={}, shadowed_roots=frozenset(), star_exports=vocabulary_star_exports())
    names = {node.name for node in census.reference_sites if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)}
    assert names == {"plain"}


def test_reference_site_membership_is_the_entity_node_object() -> None:
    # THE WHOLE SOUNDNESS ARGUMENT for holding reference sites by node identity:
    # the entity index and the census are built from ONE parse, so the objects are
    # identical, not merely equal. If ``discover_file_entities`` ever stops handing
    # back the same object, form 5 silently stops resolving EVERYWHERE — a total,
    # fail-closed feature outage with nothing red. Hence the ``is`` assertion.
    src = 'X = "ASSURED"\n\n\ndef f(p):\n    return p\n'
    tree = ast.parse(src)
    census = build_module_census(tree, alias_map={}, shadowed_roots=frozenset(), star_exports=vocabulary_star_exports())
    entity = next(e for e in discover_file_entities(tree, module="m", path="m.py") if e.qualname == "m.f")
    assert entity.node in census.reference_sites
    assert entity.node is tree.body[1]


# ── The two properties that keep the predicates in ONE place ─────────────────────


def test_shadowed_root_refusal_is_applied_at_the_census_build() -> None:
    # A form-2 right-hand side in a project that SHADOWS the vocabulary root
    # records an UNREADABLE entry.
    #
    # THE ALTERNATIVE THAT WAS REFUSED: applying the shadowed-root refusal at the
    # value's USE site instead. By then the reader sees a bare ``Name`` whose token
    # has already been resolved — the form-2 receiver is gone — and the same code
    # reads as ordinary and RESOLVES. The refusal must happen here, where the
    # receiver is still in view, and nowhere else.
    clean = _census("X = TaintState.ASSURED\n")
    assert clean.values["X"].token == "ASSURED"

    shadowed = _census("X = TaintState.ASSURED\n", shadowed_roots=frozenset({"wardline"}))
    assert shadowed.values["X"].token is None
    assert shadowed.values["X"].unreadable_reason is not None


def test_the_census_is_marker_agnostic() -> None:
    # The census holds NO builtin/custom discriminator at all, so the entry it
    # records cannot depend on which marker later reads the name. This pins that
    # the builtin-only gate lives in exactly ONE place (the reader and its caller)
    # — the builtin/custom half of spec §4.2.1's two silent
    # cross-reader-disagreement cases. The star-import half is covered by the
    # cross-reader poison assertion in the provider-seedcontext suite.
    src = 'X = "ASSURED"\n\n\ndef f(p):\n    return p\n'
    tree = ast.parse(src)
    census = build_module_census(tree, alias_map={}, shadowed_roots=frozenset(), star_exports=vocabulary_star_exports())
    assert census.values["X"].token == "ASSURED"
    assert not hasattr(census, "builtin")
    assert set(census.values) == {"X", "f"}


def test_census_values_is_a_read_only_view() -> None:
    # Proxied in the BUILDER, not in ``AnalysisContext.__post_init__``: the
    # context's ``_freeze_value`` returns a non-Mapping value unchanged, so a
    # ``ModuleCensus`` passes through it opaque. Wrapping here also covers the
    # ``SeedContext`` path, which ``__post_init__`` never touches.
    census = _census('X = "ASSURED"\n')
    with pytest.raises(TypeError):
        census.values["X"] = None  # type: ignore[index]
