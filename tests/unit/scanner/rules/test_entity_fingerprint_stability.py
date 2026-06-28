"""Cross-interpreter stability of the entity-body fingerprint discriminator.

``entity_source_fingerprint`` feeds the cross-tool fingerprint JOIN KEY, so it must be
byte-identical across CPython versions. Python 3.13's ``ast.dump(show_empty=False)`` omits
empty-list fields that 3.12 emits; hashing the raw dump minted a DIFFERENT fingerprint per
interpreter (the 2026-06-28 3.12 identity-corpus drift). ``_canonical_ast_dump`` reproduces
the 3.13 ``show_empty=False`` canonical form on every interpreter so the join key is stable.
"""

from __future__ import annotations

import ast

from wardline.scanner.rules._fingerprint import _canonical_ast_dump, entity_source_fingerprint


def _entity(src: str) -> ast.AST:
    return ast.parse(src).body[0]


def test_canonical_dump_omits_empty_list_fields_on_every_interpreter() -> None:
    # The 3.13 show_empty=False canonical form omits empty-list fields (posonlyargs,
    # decorator_list, type_params, args' kwonly/defaults, ...). This literal is identical
    # on 3.12 and 3.13; under the old raw ast.dump, 3.12 carried the empties and drifted.
    node = _entity("def f(): pass")
    assert _canonical_ast_dump(node) == "FunctionDef(name='f', args=arguments(), body=[Pass()])"


def test_canonical_dump_preserves_string_literal_containing_bracket_syntax() -> None:
    # Structural, not regex: a string literal that happens to contain ``x=[]`` must NOT be
    # corrupted. A naive ``=[]`` strip over the dumped text would mangle this join key.
    node = _entity('def f():\n    s = "x=[],y"\n    return s\n')
    assert "Constant(value='x=[],y')" in _canonical_ast_dump(node)


def test_entity_source_fingerprint_is_deterministic_and_body_sensitive() -> None:
    a = entity_source_fingerprint(_entity("def f():\n    return 1\n"))
    a_again = entity_source_fingerprint(_entity("def f():\n    return 1\n"))
    b = entity_source_fingerprint(_entity("def f():\n    return 2\n"))
    assert a == a_again  # identical source -> identical fingerprint
    assert a != b  # body change -> different fingerprint
    assert a.startswith("entity:")
