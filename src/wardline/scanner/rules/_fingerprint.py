"""Fingerprint discriminators shared by rule implementations."""

from __future__ import annotations

import ast
import hashlib


def entity_source_fingerprint(node: ast.AST) -> str:
    """Line-independent discriminator for singleton findings tied to an entity body.

    ``ast.dump(..., include_attributes=False)`` keeps source semantics that affect the
    entity while excluding absolute line/column positions, so a whole-entity move or
    comment-only edit is stable but a same-qualname body or signature change is not.
    """
    digest = hashlib.sha256()
    digest.update(ast.dump(node, include_attributes=False).encode("utf-8"))
    return f"entity:{digest.hexdigest()}"
