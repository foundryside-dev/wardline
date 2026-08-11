# src/wardline/scanner/module_census.py
"""The per-module binding census — form 5's ONE evaluation point (spec §4.2.1).

Built exactly ONCE per module, in the parse loop, where the tree is already in
hand, and handed to both readers: the provider directly (``SeedContext``), the
rule side as the value under its module key (``AnalysisContext``). It is never
rebuilt, and no rule computes one — the rule side holds neither the module AST
nor the star-export map, and that inability is precisely the pressure that would
otherwise produce the defaulted-empty census the specification forbids.

Three components, and the census — not either reader — owns all three:

* ``values`` — every name bound at module scope, resolved to a level token ONLY
  when exactly one occurrence satisfies the direct-top-level, unconditional,
  single-``Name``-target discipline and no other module-scope occurrence of any
  kind exists anywhere in the module;
* ``poisoned`` — an unresolved top-level star import makes every name in the
  module unreadable, because ``build_import_alias_map`` skipped that import and
  the star may silently override the visible assignment;
* ``reference_sites`` — the ``def`` / ``async def`` statements that are DIRECT
  elements of ``Module.body``, held by node identity.

Last-binding-wins is refused outright. Decorator expressions are evaluated at
``def`` time, not in module source order, so picking the last binding in a VALUE
position is a trust escalation: any second occurrence — at any statement depth,
of any kind — makes the name unreadable rather than resolving to one of the pair.

OVER-APPROXIMATION IS DELIBERATE AND FAILS CLOSED. A comprehension is its own
scope, yet the binding walk counts a comprehension's iteration target — and a
walrus target written inside one — as a module-scope occurrence. Over-counting
can only make a name UNREADABLE; it can never resolve one. Do not "fix" either
into a fail-open by teaching the walk to skip comprehension scopes.
"""

from __future__ import annotations

import ast
from collections.abc import Mapping
from types import MappingProxyType

from wardline.scanner.marker_reader import CensusBinding, ModuleCensus, level_token

CensusEntry = CensusBinding
"""Task 2's ``CensusBinding``, re-exported under the builder's local name.

Exactly one of ``token`` / ``unreadable_reason`` is set. ``line`` is the
binding's line, which is what makes form 5's lexical-precedence clause
decidable. ``unreadable_reason`` is DIAGNOSTIC MESSAGE TEXT, not a pinned
vocabulary and not fingerprint input — the residual FACT keys on the unparsed
value node, which needs no census entry at all. No test asserts on these strings
and no fingerprint consumes them; do not mint a reason vocabulary here.
"""


def _enclosing_scope_exprs(
    node: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef,
) -> tuple[ast.expr, ...]:
    """Child expressions Python evaluates in the ENCLOSING scope, not the body.

    A ``def``'s decorators, argument defaults and annotations, and a ``class``'s
    bases and keywords, are evaluated where the statement appears — so a binding
    occurrence inside one of them IS a module-scope occurrence. The body is a
    separate scope and never enters the census. Descending into exactly these and
    stopping at the body is what keeps the walk fail-closed in both directions.
    """
    if isinstance(node, ast.ClassDef):
        return (*node.decorator_list, *node.bases, *(kw.value for kw in node.keywords))
    args = node.args
    annotations = tuple(
        a.annotation for a in (*args.posonlyargs, *args.args, *args.kwonlyargs) if a.annotation is not None
    )
    return (
        *node.decorator_list,
        *args.defaults,
        *(d for d in args.kw_defaults if d is not None),
        *annotations,
        *((node.returns,) if node.returns is not None else ()),
    )


def build_module_census(
    tree: ast.Module,
    *,
    alias_map: Mapping[str, str],
    shadowed_roots: frozenset[str],
    star_exports: Mapping[str, Mapping[str, str]],
) -> ModuleCensus:
    """Build one module's census. Called ONCE per module, from the parse loop."""
    # POISON. This is build_import_alias_map's OWN expansion test, inverted: it
    # materialises a star import only when the import is ABSOLUTE and the target
    # module is in star_exports. Everything else it silently skips, so the star
    # may supply a name the census cannot see. Pinned against the shipped
    # function by test_census_poison_agrees_with_build_import_alias_map.
    poisoned = any(
        isinstance(stmt, ast.ImportFrom)
        and any(alias.name == "*" for alias in stmt.names)
        and not ((stmt.level or 0) == 0 and stmt.module is not None and stmt.module in star_exports)
        for stmt in tree.body
    )

    occurrences: dict[str, list[int]] = {}
    declared_global: set[str] = set()

    def occurrence(name: str, line: int) -> None:
        occurrences.setdefault(name, []).append(line)

    def visit(child: ast.AST) -> None:
        line = getattr(child, "lineno", 0)
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            # The def/class statement BINDS its own name — omitting it runs
            # fail-open: form 5 would resolve a token the code has since replaced
            # with a function or a class.
            occurrence(child.name, line)
            for sub in _enclosing_scope_exprs(child):
                visit(sub)
            return  # separate scope — the body never enters the census
        if isinstance(child, (ast.Import, ast.ImportFrom)):
            # An import IS a binding occurrence; the value it binds lives in
            # another module, so the name is unreadable for form 5.
            for alias in child.names:
                if alias.name == "*":
                    continue
                occurrence(alias.asname or alias.name.split(".")[0], line)
            return
        if isinstance(child, ast.Name) and isinstance(child.ctx, (ast.Store, ast.Del)):
            # One test covers Assign, AnnAssign, AugAssign, walrus, for/with/
            # comprehension targets, tuple and starred unpacking, and `del`.
            occurrence(child.id, line)
        elif isinstance(child, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar)) and child.name is not None:
            # `except ... as e`, a `match` capture and a `match` star-capture all
            # carry their bound name on ``.name``; merged into ONE branch because
            # ruff's SIM114 refuses the three-way `elif` chain that states them
            # separately. Semantics are unchanged — same names, same lines.
            occurrence(child.name, line)
        elif isinstance(child, ast.MatchMapping) and child.rest is not None:
            occurrence(child.rest, line)
        for grandchild in ast.iter_child_nodes(child):
            visit(grandchild)

    for stmt in tree.body:
        visit(stmt)

    # WALK 2 — deliberately unlike walk 1: `global` counts ANYWHERE in the module,
    # nested scopes included. It is the fail-closed substitute for interprocedural
    # reasoning about writes back into module scope, and it is what makes walk 1's
    # refusal to descend into function bodies sound.
    for node in ast.walk(tree):
        if isinstance(node, ast.Global):
            declared_global.update(node.names)

    # The one shape that may resolve: a DIRECT element of Module.body, single
    # `Name` target, unconditional. An `AnnAssign` qualifies when it has a value —
    # the annotation is not read, only the right-hand side, because `X: Final = ...`
    # is the idiomatic DRY spelling and refusing it re-opens the ticket for the
    # most likely real form. A name with two qualifying statements also has two
    # occurrences and is rejected below, so the last-wins write here is unreachable.
    qualifying: dict[str, tuple[ast.expr, int]] = {}
    for stmt in tree.body:
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
            qualifying[stmt.targets[0].id] = (stmt.value, stmt.lineno)
        elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name) and stmt.value is not None:
            qualifying[stmt.target.id] = (stmt.value, stmt.lineno)

    values: dict[str, CensusEntry] = {}
    for name, lines in occurrences.items():
        if name in declared_global:
            values[name] = CensusEntry(None, "declared `global` in this module", lines[0])
            continue
        if len(lines) != 1 or name not in qualifying:
            values[name] = CensusEntry(
                None,
                "bound more than once in module scope, or not a direct top-level unconditional single-name assignment",
                lines[0],
            )
            continue
        value_node, line = qualifying[name]
        # The RIGHT-HAND-SIDE ALLOWLIST is Task 2's public `level_token`, called
        # with an inline EMPTY census — which is what makes form 5's one-hop rule
        # STRUCTURAL rather than a discipline: an empty census resolves no bare
        # `Name`, so a right-hand side that is itself a bare name is refused by
        # construction and the walk cannot take a second hop. What survives is
        # exactly P3 form 1 (a `str` constant) and P3 form 2. No second reader and
        # no new identifier: this is the same inline-census idiom as Task 2's two
        # call sites, for the same reason — the engine floor ships no inert census
        # constant, because a public one is the defaulted-empty affordance spec
        # rev 6 §4.2.1 forbids. `shadowed_roots` is threaded so the form-2
        # shadowed-root refusal is applied HERE, where the form-2 receiver is still
        # in view, and nowhere else (spec §4.2.1). `builtin=True` is inert on this
        # call — form 5 cannot fire against an empty census — so it does not give
        # the census a builtin/custom opinion; the census stays marker-agnostic.
        token = level_token(
            value_node,
            alias_map,
            census=ModuleCensus(values={}, poisoned=False, reference_sites=frozenset()),
            reference_site=None,
            shadowed_roots=shadowed_roots,
            builtin=True,
        )
        values[name] = (
            CensusEntry(token, None, line)
            if token is not None
            else CensusEntry(None, "right-hand side is outside form 1 / form 2", line)
        )

    return ModuleCensus(
        # Proxied HERE, not in AnalysisContext.__post_init__: `_freeze_value` returns a
        # non-Mapping/non-set value unchanged, so a ModuleCensus passes through the
        # context's freeze opaque and its inner dict would stay mutable — against that
        # class's "genuinely read-only view" guarantee. Wrapping in the builder also
        # covers the SeedContext path, which __post_init__ never touches.
        values=MappingProxyType(values),
        poisoned=poisoned,
        reference_sites=frozenset(
            stmt for stmt in tree.body if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef))
        ),
    )
