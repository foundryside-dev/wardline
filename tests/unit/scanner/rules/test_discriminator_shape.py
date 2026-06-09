"""P3 S3 — construction-shape lint: multi_emit <-> taint_path discriminator.

Source-AST guardrail (wardline-8654423823). Since wlfp2 dropped ``line_start`` from
the hash, a rule that can emit >1 finding per (rule_id, qualname) MUST carry a
source-derived entity-relative discriminator in ``taint_path`` (a col span or an
ordinal); a singleton passes ``taint_path=None``. ``RuleMetadata.multi_emit`` is the
declared source of truth. This lint enforces the correspondence at AUTHORING time —
the gap the runtime collision guard (P2) and the frozen corpus only close once a
colliding pair is actually planted in a fixture. ``taint_path`` is a hash input that
is never persisted, so the check MUST be over source, not runtime.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

from wardline.scanner.rules import BUILTIN_RULE_CLASSES
from wardline.scanner.rules._sink_helpers import TaintedSinkRule

_FP_NAMES = {"_fp", "compute_finding_fingerprint"}


def _taint_path_none_flags(source_file: str) -> list[bool]:
    """For every ``_fp``/``compute_finding_fingerprint`` call in ``source_file``, whether
    its ``taint_path`` kwarg is the literal ``None`` (True) or a real discriminator
    (False). Asserts the kwarg is present at all (a missing taint_path is itself a bug)."""
    tree = ast.parse(Path(source_file).read_text(encoding="utf-8"))
    flags: list[bool] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in _FP_NAMES:
            tp = next((kw for kw in node.keywords if kw.arg == "taint_path"), None)
            assert tp is not None, f"{source_file}: a fingerprint call omits the taint_path kwarg"
            flags.append(isinstance(tp.value, ast.Constant) and tp.value.value is None)
    return flags


def test_taintedsinkrule_base_carries_a_discriminator() -> None:
    # The 7 sink subclasses (106/107/108/112/115/116/117) have NO per-module _fp call —
    # the single call lives in the shared base. It must carry a (non-None) span so every
    # subclass is covered.
    flags = _taint_path_none_flags(inspect.getfile(TaintedSinkRule))
    assert flags, "expected the TaintedSinkRule base to build a fingerprint"
    assert not any(flags), "the shared sink-rule fingerprint must carry a discriminator (never taint_path=None)"


def test_every_rule_multi_emit_matches_its_taint_path_shape() -> None:
    seen_multi = seen_singleton = False
    for cls in BUILTIN_RULE_CLASSES:
        multi_emit = cls.metadata.multi_emit
        flags = _taint_path_none_flags(inspect.getfile(cls))
        if not flags:
            # No local fingerprint call => a TaintedSinkRule subclass, covered by the base
            # (asserted above). Such a rule is inherently multi-emit; the flag must say so.
            assert issubclass(cls, TaintedSinkRule), f"{cls.__name__}: no local _fp call but not a sink subclass"
            assert multi_emit, f"{cls.__name__}: sink subclass must be flagged multi_emit"
            seen_multi = True
            continue
        if multi_emit:
            seen_multi = True
            assert not any(flags), (
                f"{cls.__name__} is multi_emit but a fingerprint call passes taint_path=None — co-located "
                f"findings would COLLIDE now that line_start left the hash (wlfp2). Give it an entity-relative "
                f"span/ordinal discriminator, or set multi_emit=False if it truly emits <=1 per qualname."
            )
        else:
            seen_singleton = True
            assert all(flags), (
                f"{cls.__name__} is a singleton (multi_emit=False) but a fingerprint call passes a non-None "
                f"taint_path. Either drop the discriminator (taint_path=None) or set multi_emit=True."
            )
    # Non-vacuity: the corpus of rules actually exercises both arms.
    assert seen_multi and seen_singleton, "expected both multi_emit and singleton rules in the builtin set"
