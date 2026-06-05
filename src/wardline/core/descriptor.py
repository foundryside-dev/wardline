# src/wardline/core/descriptor.py
"""NG-25 vocabulary descriptor — the federation-clean *read-instead-of-import*
export of the trust-decorator ``REGISTRY``.

``build_vocabulary_descriptor()`` returns a plain, JSON/YAML-serializable dict
``{"schema": DESCRIPTOR_SCHEMA, "version": REGISTRY_VERSION, "entries": [...]}``.
``schema`` is the descriptor's FORMAT version (the cross-product contract shape);
``version`` is the vocabulary CONTENT version (which decorators exist). Each entry mirrors REGISTRY's
three fields — ``canonical_name``, ``group``, and ``attrs`` (the attr-name →
taint-type mapping, serialized as ``{name: type.__name__}``). The §2 FunctionTaint
mapping is parametric and provider-owned (``DecoratorTaintSourceProvider`` reads
``to_level``/``level`` from each call site), so it is deliberately out of scope:
the descriptor round-trips REGISTRY, not the provider.

No HMAC / signing / governance — a plain versioned export. The committed
``vocabulary.yaml`` (shipped in the wheel) is a derived snapshot of this function;
a byte-identity drift test keeps it current.

``attrs`` types are serialized by ``__name__`` (shape, not type identity): today
every attr is ``TaintState``. If the vocabulary ever grows two attr types that
share a ``__name__`` from different modules they would be silently conflated —
revisit the serialization if that day comes.
"""

from __future__ import annotations

from typing import Any, cast

from wardline.core.optional_deps import require_yaml
from wardline.core.registry import REGISTRY, REGISTRY_VERSION

# Descriptor-FORMAT identity — the cross-product contract surface version. This
# is DISTINCT from REGISTRY_VERSION (the vocabulary CONTENT version): `schema`
# names the shape (envelope/entry fields + their semantics), `version` names the
# decorator set. A consumer (Loomweave) gates expectations on `schema` and may
# tolerate unknown future entry fields within the same schema. Bump `schema`
# only on a breaking shape change, with a coordinated consumer migration — one
# self-describing string, no version negotiation.
DESCRIPTOR_SCHEMA = "wardline.vocabulary/v1"


def build_vocabulary_descriptor() -> dict[str, Any]:
    """Export REGISTRY as the NG-25 descriptor dict (entries in REGISTRY order)."""
    return {
        "schema": DESCRIPTOR_SCHEMA,
        "version": REGISTRY_VERSION,
        "entries": [
            {
                "canonical_name": entry.canonical_name,
                "group": entry.group,
                "attrs": {name: typ.__name__ for name, typ in entry.attrs.items()},
            }
            for entry in REGISTRY.values()
        ],
    }


def descriptor_to_yaml() -> str:
    """Serialize the descriptor to deterministic YAML (key order preserved)."""
    yaml = require_yaml("emitting the vocabulary descriptor")
    return cast(
        str,
        yaml.safe_dump(
            build_vocabulary_descriptor(),
            sort_keys=False,
            default_flow_style=False,
        ),
    )
