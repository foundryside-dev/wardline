# src/wardline/scanner/rules/untrusted_to_deserialization.py
"""PY-WL-106 — untrusted data reaches a deserialization sink in a trusted-tier function.

Deserializing untrusted bytes (``pickle.loads``, ``yaml.load``, ``marshal.loads``, …)
is a classic remote-code-execution vector (CWE-502). Tier-modulated: silent in the
developer-freedom zone, fires where trust is declared. The ``safe_*`` loaders and the
*dump* direction are intentionally NOT sinks here. ``json.loads`` is excluded (it does
not execute) to avoid noise.

Sink families (ticket wardline-4299f07bb4):

* **Stdlib direct loaders** — pickle/marshal/yaml ``load``/``loads`` spellings. These
  keep the historical worst-of-ALL-args taint test (no :class:`ArgSpec`).
* **OO streaming-unpickle API** — ``pickle.Unpickler(stream).load()``, chained or
  stored-instance (``u = pickle.Unpickler(stream); u.load()``), resolved through the
  shared sink-binding machinery. ``load()`` itself takes no arguments; the dangerous
  data is the stream handed to the CONSTRUCTOR, so the taint is read from the
  constructor call's first argument. An annotation-only binding (``u:
  pickle.Unpickler`` with no constructor in scope) has no stream argument to read —
  a documented bounded false negative. ``marshal`` has no reader-object API, so there
  is no marshal analogue.
* **``shelve.open``** — pickle-backed: opening a shelf at an attacker-controlled PATH
  then reading keys unpickles attacker bytes. The taint shape differs from the blob
  loaders — it is on the path argument only (``positions=(0,)`` /
  ``keywords=("filename",)``), so a tainted flag/protocol slot does not fire.
* **Curated third-party CWE-502 table** — ``dill.load``/``loads``,
  ``jsonpickle.decode``, ``joblib.load``, ``torch.load``, ``numpy.load``. Matching is
  by canonical dotted name at the AST level (through the module's import-alias map);
  the analyzer never imports these packages. Two literal-keyword gates, same
  statically-visible-literal discipline as PY-WL-112's ``shell=True``:
  ``numpy.load`` fires ONLY with a literal ``allow_pickle=True`` (the default is
  False — safe — since numpy 1.16.3, so absent/False/dynamic stays silent);
  ``torch.load`` is suppressed by a literal ``weights_only=True`` (the restricted
  unpickler — the modern safe spelling) and fires otherwise, because older torch
  defaults to the full unpickler.

**Severity decision:** every entry here is RCE-equivalent (arbitrary object-graph
execution), so all carry the rule family's base severity (WARN, tier-modulated) —
exactly the standing of ``pickle.loads``. No per-sink severity split.

**Why WARN and not the 118/108/112/124 ERROR class — a deliberate FP-economics
call (severity lattice review 2026-06-10).** The ERROR family members buy their
base with strong per-finding evidence (slot-precise ArgSpecs, literal-keyword
gates, an SQL-string position test); the classic blob loaders here keep the
worst-of-all-args test, and deserializing data from internal stores/caches the
engine cannot vouch for is a pervasive legitimate idiom — exploitability hinges
on the SOURCE being attacker-reachable, which a static worst-arg test cannot
establish. One class lower balances that weaker evidence. Promote via
``rules.severity`` per project, or revisit alongside the frozen identity corpus.
"""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING

from wardline.core.finding import Kind, Severity
from wardline.scanner.rules._sink_helpers import (
    ArgSpec,
    TaintedSinkRule,
    collect_ctor_call_nodes,
    receiver_ctor_call,
)
from wardline.scanner.rules.metadata import RuleMetadata

if TYPE_CHECKING:
    from collections.abc import Mapping

# Direct-call sinks: the taint test runs over the SINK CALL's own arguments.
# ``None`` keeps the historical worst-of-all-args behavior for the original stdlib
# loaders; an ArgSpec narrows the test to the dangerous slot(s) for sinks whose
# non-data slots (flags, mmap modes, map_location) are taint-irrelevant.
_SINK_SPECS: dict[str, ArgSpec | None] = {
    "pickle.loads": None,
    "pickle.load": None,
    "marshal.loads": None,
    "marshal.load": None,
    "yaml.load": None,
    "yaml.load_all": None,
    "yaml.unsafe_load": None,
    "yaml.full_load": None,
    "shelve.open": ArgSpec(positions=(0,), keywords=("filename",)),
    "dill.load": ArgSpec(positions=(0,), keywords=("file",)),
    "dill.loads": ArgSpec(positions=(0,), keywords=("str",)),
    "jsonpickle.decode": ArgSpec(positions=(0,), keywords=("string",)),
    "joblib.load": ArgSpec(positions=(0,), keywords=("filename",)),
    "torch.load": ArgSpec(positions=(0,), keywords=("f",)),
    "numpy.load": ArgSpec(positions=(0,), keywords=("file",)),
}

# Stream-reader sinks: the sink is a no-arg METHOD on a reader object; the taint test
# runs over the CONSTRUCTOR call's stream argument (the ArgSpec addresses the ctor).
_READER_CTORS = frozenset({"pickle.Unpickler"})
_READER_SINK_SPECS: dict[str, ArgSpec] = {
    "pickle.Unpickler.load": ArgSpec(positions=(0,), keywords=("file",)),
}

_SINKS = frozenset(_SINK_SPECS) | frozenset(_READER_SINK_SPECS)


def _has_literal_true_kw(call: ast.Call, name: str) -> bool:
    """True iff *call* passes ``<name>=True`` as a literal keyword. ``**kwargs``,
    a non-constant value, or any constant other than ``True`` is not matched —
    only the unambiguous, statically-visible case (the PY-WL-112 discipline)."""
    return any(kw.arg == name and isinstance(kw.value, ast.Constant) and kw.value.value is True for kw in call.keywords)


METADATA = RuleMetadata(
    rule_id="PY-WL-106",
    base_severity=Severity.WARN,
    kind=Kind.DEFECT,
    multi_emit=True,
    description=(
        "Untrusted data reaches a deserialization sink (pickle/Unpickler/marshal/yaml.load/shelve "
        "+ curated third-party: dill/jsonpickle/joblib/torch.load/numpy.load(allow_pickle=True)) "
        "in a trusted-tier function."
    ),
    examples_violation=(
        "@external_boundary\ndef read_raw(p):\n    return p\n"
        "@trusted(level='ASSURED')\ndef f(p):\n    pickle.loads(read_raw(p))",
        "@external_boundary\ndef read_raw(p):\n    return p\n"
        "@trusted(level='ASSURED')\ndef f(p):\n    return pickle.Unpickler(read_raw(p)).load()",
    ),
    examples_clean=(
        "@external_boundary\ndef read_raw(p):\n    return p\n"
        "@trust_boundary(to_level='ASSURED')\ndef validate(x):\n    if not x:\n        raise ValueError\n    return x\n"
        "@trusted(level='ASSURED')\ndef f(p):\n    blob = validate(read_raw(p))\n"
        "    obj = pickle.loads(blob)\n    return blob",
        # numpy.load without allow_pickle=True is safe by default (no object unpickling).
        "@external_boundary\ndef read_raw(p):\n    return p\n"
        "@trusted(level='ASSURED')\ndef f(p):\n    return numpy.load(read_raw(p))",
    ),
)


class UntrustedToDeserialization(TaintedSinkRule):
    """Attribute-only since the 2026-06-10 consolidation, plus two hooks:

    * :meth:`_accept_call` — the numpy/torch literal-keyword gates;
    * :meth:`_taint_anchor_call` — a reader-method sink (``Unpickler.load``,
      argument-less) reads its taint from the CONSTRUCTOR call's stream
      argument (the merged ``SINK_SPECS`` entry addresses the ctor's slots).
    """

    rule_id = METADATA.rule_id
    metadata = METADATA
    SINKS = _SINKS
    SINK_SPECS: Mapping[str, ArgSpec | None] = {**_SINK_SPECS, **_READER_SINK_SPECS}
    sink_label = "deserialization"

    def _accept_call(self, call: ast.Call, fqn: str) -> bool:  # noqa: PLR6301
        if fqn == "numpy.load" and not _has_literal_true_kw(call, "allow_pickle"):
            return False  # safe-by-default: only a literal allow_pickle=True unpickles
        return not (fqn == "torch.load" and _has_literal_true_kw(call, "weights_only"))
        # weights_only=True → restricted unpickler, the modern safe spelling

    def _taint_anchor_call(  # noqa: PLR6301
        self,
        call: ast.Call,
        fqn: str,
        entity_node: ast.AST,
        alias_map: Mapping[str, str],
    ) -> ast.Call | None:
        if fqn not in _READER_SINK_SPECS:
            return call
        # Reader-method sink: the dangerous data is the stream handed to the
        # CONSTRUCTOR. Resolve the chained ``pickle.Unpickler(s).load()`` receiver
        # or the bound var's recorded constructor; ``None`` (an annotation-only
        # binding with no constructor in scope) is a documented bounded FN.
        ctors = collect_ctor_call_nodes(entity_node, alias_map, ctor_fqns=_READER_CTORS)
        return receiver_ctor_call(call, ctors)
