"""P3 S3 — construction-shape lint: multi_emit <-> taint_path discriminator.

Source-AST guardrail (wardline-8654423823). Since wlfp2 dropped ``line_start`` from
the hash, a rule that can emit >1 finding per (rule_id, qualname) MUST carry a
source-derived entity-relative discriminator in ``taint_path`` (a col span or an
ordinal); a singleton may use ``entity_source_fingerprint(entity.node)`` to avoid
carrying stale suppressions across same-qualname body changes. ``RuleMetadata.multi_emit``
is the declared source of truth. This lint enforces the correspondence at AUTHORING
time — the gap the runtime collision guard (P2) and the frozen corpus only close once a
colliding pair is actually planted in a fixture. ``taint_path`` is a hash input that is
never persisted, so the check MUST be over source, not runtime.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

from wardline.scanner.rules import BUILTIN_RULE_CLASSES
from wardline.scanner.rules._sink_helpers import TaintedSinkRule

_FP_NAMES = {"_fp", "compute_finding_fingerprint"}
_SINGLETON_DISCRIMINATOR = "entity_source_fingerprint"


def _taint_path_shapes(source_file: str) -> list[str]:
    """For every ``_fp``/``compute_finding_fingerprint`` call in ``source_file``, whether
    its ``taint_path`` kwarg is absent, singleton-scoped, or multi-emit-scoped.
    Asserts the kwarg is present at all (a missing taint_path is itself a bug)."""
    tree = ast.parse(Path(source_file).read_text(encoding="utf-8"))
    shapes: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in _FP_NAMES:
            tp = next((kw for kw in node.keywords if kw.arg == "taint_path"), None)
            assert tp is not None, f"{source_file}: a fingerprint call omits the taint_path kwarg"
            if isinstance(tp.value, ast.Constant) and tp.value.value is None:
                shapes.append("none")
            elif isinstance(tp.value, ast.Call) and isinstance(tp.value.func, ast.Name):
                shapes.append("singleton" if tp.value.func.id == _SINGLETON_DISCRIMINATOR else "multi")
            else:
                shapes.append("multi")
    return shapes


def test_taintedsinkrule_base_carries_a_discriminator() -> None:
    # The attribute-only sink subclasses (106/107/108/112/115/117/121-126) have NO
    # per-module _fp call — the single call lives in the shared base's
    # build_sink_finding (the 2026-06-10 consolidation restored this single-call
    # property; the former mixins satisfied it only transitively). It must carry a
    # (non-None) span so every subclass is covered.
    shapes = _taint_path_shapes(inspect.getfile(TaintedSinkRule))
    assert shapes, "expected the TaintedSinkRule base to build a fingerprint"
    assert all(shape == "multi" for shape in shapes), (
        "the shared sink-rule fingerprint must carry a per-trigger discriminator"
    )


def test_every_rule_multi_emit_matches_its_taint_path_shape() -> None:
    seen_multi = seen_singleton = False
    for cls in BUILTIN_RULE_CLASSES:
        multi_emit = cls.metadata.multi_emit
        shapes = _taint_path_shapes(inspect.getfile(cls))
        if not shapes:
            # No local fingerprint call => a TaintedSinkRule subclass, covered by the base
            # (asserted above). Such a rule is inherently multi-emit; the flag must say so.
            assert issubclass(cls, TaintedSinkRule), f"{cls.__name__}: no local _fp call but not a sink subclass"
            assert multi_emit, f"{cls.__name__}: sink subclass must be flagged multi_emit"
            seen_multi = True
            continue
        if multi_emit:
            seen_multi = True
            assert all(shape == "multi" for shape in shapes), (
                f"{cls.__name__} is multi_emit but a fingerprint call uses a singleton discriminator — "
                f"co-located findings would COLLIDE now that line_start left the hash (wlfp2). Give it an "
                f"entity-relative span/ordinal discriminator, or set multi_emit=False if it truly emits <=1 "
                f"per qualname."
            )
        else:
            seen_singleton = True
            assert all(shape == "singleton" for shape in shapes), (
                f"{cls.__name__} is a singleton (multi_emit=False) but a fingerprint call does not use "
                f"{_SINGLETON_DISCRIMINATOR}(). Either use the singleton source-body discriminator or "
                f"set multi_emit=True."
            )
    # Non-vacuity: the corpus of rules actually exercises both arms.
    assert seen_multi and seen_singleton, "expected both multi_emit and singleton rules in the builtin set"
