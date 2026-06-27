"""Fingerprint discriminators shared by rule implementations."""

from __future__ import annotations

import ast
import hashlib

# Sentinel for "this field has no class-level (None) default" in _canonical_ast_dump.
_NO_DEFAULT = object()


def _canonical_ast_dump(node: ast.AST) -> str:
    """``ast.dump(node, include_attributes=False)`` made byte-identical across CPython
    versions.

    Python 3.13 changed ``ast.dump``: with its new default ``show_empty=False`` it OMITS
    empty-list fields (``posonlyargs=[]``, ``decorator_list=[]``, ``type_params=[]`` ...)
    that 3.12 and earlier always emit. Both versions already omit ``None``-default
    optional fields (``returns``, ``annotation``, ...) and both keep real values such as
    ``Constant(value=None)``, so the ONLY cross-version divergence is empty-list fields.
    This reproduces the 3.13 ``show_empty=False`` canonical form on every interpreter
    (verified node-for-node equal to 3.13's ``ast.dump``), so the entity discriminator
    below — and the cross-tool fingerprint JOIN KEY it feeds — is interpreter-stable; a
    wardline running under 3.12 vs 3.13 mints the same fingerprint for the same source.

    Done structurally rather than by string-munging ``ast.dump`` output: a string literal
    such as ``"x=[]"`` renders as ``Constant(value='x=[]')``, so a regex that stripped
    ``=[]`` from the dumped text would corrupt the literal (and the join key).
    """
    if isinstance(node, ast.AST):
        cls = type(node)
        parts: list[str] = []
        for name in node._fields:
            try:
                value = getattr(node, name)
            except AttributeError:
                continue
            if isinstance(value, list) and not value:
                continue  # empty-list field: omitted by 3.13 ast.dump (show_empty=False)
            if value is None and getattr(cls, name, _NO_DEFAULT) is None:
                continue  # None-default optional field: omitted by ast.dump on both versions
            parts.append(f"{name}={_canonical_ast_dump(value)}")
        return f"{cls.__name__}({', '.join(parts)})"
    if isinstance(node, list):
        return "[" + ", ".join(_canonical_ast_dump(x) for x in node) + "]"
    return repr(node)


def entity_source_fingerprint(node: ast.AST) -> str:
    """Line-independent discriminator for singleton findings tied to an entity body.

    Hashes a position-free canonical AST dump (see :func:`_canonical_ast_dump`), which
    keeps source semantics that affect the entity while excluding absolute line/column
    positions, so a whole-entity move or comment-only edit is stable but a same-qualname
    body or signature change is not. The canonical dump is interpreter-stable, so the
    fingerprint is byte-identical across CPython 3.12 and 3.13+.
    """
    digest = hashlib.sha256()
    digest.update(_canonical_ast_dump(node).encode("utf-8"))
    return f"entity:{digest.hexdigest()}"
