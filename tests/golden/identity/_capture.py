"""Deterministic identity-capture harness for the parity oracle (Task A).

Captures every *identity-bearing* output a Weft peer keys on, canonicalized so
re-running yields byte-identical JSON: stable named-array sorts, ``sort_keys``,
no absolute paths / timestamps / host data. Scans are rooted AT the fixture dir
so a finding ``path`` (and thus its fingerprint) is relative and
location-independent (``run.py`` relativises against the resolved root).

Imported by both ``regen.py`` (freeze) and ``test_identity_parity.py`` (gate)
via ``from golden.identity import _capture`` — the repo puts ``tests/`` on
``sys.path`` (pytest prepend mode), so the package is ``golden.identity``, NOT
``tests.golden.identity``.

Scope (user-confirmed): the corpus is a *cross-engine identity* contract, so it
freezes only identity-bearing policy findings (``PY-WL-* ∧ Kind.DEFECT``) plus
the taint-fact payload, SARIF, assure posture, and explain. Engine diagnostics
(``WLN-ENGINE-*`` / ``WLN-L3-*`` / ``Kind.METRIC`` / ``Kind.FACT``) are excluded:
a future Rust resolver may legitimately differ on them, and they are not what
downstream associations key on.
"""

from __future__ import annotations

import dataclasses
import json
from enum import Enum
from pathlib import Path
from typing import Any

from wardline.core.assure import build_posture
from wardline.core.explain import explanation_from_context
from wardline.core.finding import Finding, Kind
from wardline.core.run import run_scan
from wardline.core.sarif import build_sarif
from wardline.loomweave.facts import build_taint_facts

_VERSION_SENTINEL = "<normalized>"


def is_identity_bearing(f: Finding) -> bool:
    """The single positive predicate applied at every per-finding surface.

    A positive allowlist (not a denylist) so a future ``WLN-SECURITY-*`` DEFECT
    rule can't silently enter the frozen corpus, and a future ``PY-WL-*`` FACT
    rule can't be silently dropped from it.
    """
    return f.rule_id.startswith("PY-WL-") and f.kind is Kind.DEFECT


def _finding_sort_key(rec: dict[str, Any]) -> tuple[str, int, str, str, str]:
    loc = rec["location"]
    return (
        loc["path"] or "",
        loc["line_start"] if loc["line_start"] is not None else -1,
        rec["rule_id"],
        rec["fingerprint"],
        # Total tiebreaker: fingerprint is NOT a unique content key (the engine
        # documents that two findings can share a fingerprint), so without this a
        # tie would let Python's stable sort freeze engine-emission order — the
        # exact artifact a Rust engine won't reproduce. The record's own canonical
        # form makes the order content-derived.
        json.dumps(rec, sort_keys=True, ensure_ascii=False),
    )


def _capture_findings(result: Any) -> list[dict[str, Any]]:
    # Reuse the REAL wire format (Finding.to_jsonl) so the oracle is sensitive to
    # every identity-adjacent field (message/qualname/span/properties/...), then
    # re-parse for canonical re-serialization.
    recs = [json.loads(f.to_jsonl()) for f in result.findings if is_identity_bearing(f)]
    return sorted(recs, key=_finding_sort_key)


def _capture_facts(result: Any, root: Path) -> list[dict[str, Any]]:
    # build_taint_facts is the exact Loomweave payload; freeze it whole, but impose
    # a total order it does not guarantee (it emits in analyzer entity-insertion
    # order, a Python-walker artifact a Rust engine won't reproduce).
    facts = build_taint_facts(result, root)
    for fact in facts:
        inner = fact.get("wardline_json", {}).get("findings")
        if isinstance(inner, list):
            inner.sort(key=lambda d: (d.get("rule_id", ""), d.get("fingerprint", "")))
    return sorted(facts, key=lambda f: f["qualname"])


def _capture_sarif(result: Any) -> dict[str, Any]:
    # Pass the identity-filtered Finding objects (build_sarif itself only drops
    # Kind.METRIC, NOT Kind.FACT — so we must pre-filter or engine FACTs leak in).
    included = [f for f in result.findings if is_identity_bearing(f)]
    sarif = build_sarif(included, result.context)
    driver = sarif["runs"][0]["tool"]["driver"]
    # Normalise the MUTABLE tool version (drifts every release) — not an identity
    # signal. The static SARIF spec "version": "2.1.0" and $schema stay as-is.
    driver["version"] = _VERSION_SENTINEL
    driver["rules"] = sorted(driver["rules"], key=lambda r: r["id"])
    results = sarif["runs"][0]["results"]
    for res in results:
        # ruleIndex is assigned in emission order and would be corrupted by the
        # rules re-sort; it is fully recoverable from ruleId, so drop it. NOTE:
        # codeFlows location sequences are an ordered causal taint chain — never
        # sorted.
        res.pop("ruleIndex", None)
    results.sort(key=_sarif_result_sort_key)
    return sarif


def _sarif_result_sort_key(res: dict[str, Any]) -> tuple[str, int, str, str, str]:
    uri = res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    region = res["locations"][0]["physicalLocation"].get("region", {})
    start = region.get("startLine", -1)
    fp = res["partialFingerprints"]["wardlineFingerprint/v1"]
    # Total tiebreaker (see _finding_sort_key) — fingerprint can collide.
    return (uri or "", start, res["ruleId"], fp, json.dumps(res, sort_keys=True, ensure_ascii=False))


def _capture_entity_spans(result: Any) -> list[dict[str, Any]]:
    # Freeze the span of EVERY analyzed entity (qualname + full location), not
    # just entities that coincide with a finding. The brief's #1 migration risk
    # is a Rust parser rendering different spans; the stress fixture's span-edge
    # constructs (nested/async/overloaded/methods/comprehensions/unicode) produce
    # NO finding, so without this surface their spans would be unguarded and the
    # fixture would not actually exercise what it was built for.
    ctx = result.context
    if ctx is None:
        return []
    rows: list[dict[str, Any]] = []
    for qualname, entity in ctx.entities.items():
        loc = entity.location
        rows.append(
            {
                "qualname": qualname,
                "location": {
                    "path": loc.path,
                    "line_start": loc.line_start,
                    "line_end": loc.line_end,
                    "col_start": loc.col_start,
                    "col_end": loc.col_end,
                },
            }
        )
    return sorted(rows, key=lambda r: r["qualname"])  # qualname is unique per entity = total key


def _capture_explain(result: Any, findings: list[dict[str, Any]]) -> dict[str, Any]:
    # Deterministic target: first identity-bearing finding by sort key.
    if not findings or result.context is None:
        return {}
    target_fp = findings[0]["fingerprint"]
    live = next(f for f in result.findings if f.fingerprint == target_fp)
    exp = explanation_from_context(live, result.context)
    return {"fingerprint": target_fp, "explanation": dataclasses.asdict(exp)}


def capture(root: Path) -> dict[str, Any]:
    """Capture the full identity surface for one input root."""
    result = run_scan(root)
    findings = _capture_findings(result)
    return {
        "findings": findings,
        "entity_spans": _capture_entity_spans(result),
        "facts": _capture_facts(result, root),
        "sarif": _capture_sarif(result),
        "explain": _capture_explain(result, findings),
    }


def capture_assure(root: Path) -> dict[str, Any]:
    """Capture the assure posture totals (same path as ``wardline assure --format json``)."""
    return build_posture(root).to_dict()


def _strict_default(obj: Any) -> Any:
    # StrEnum (TaintState/Kind/Severity) already serialises as its str value, so
    # nothing should reach here; a non-str Enum is unwrapped to .value, and any
    # other unknown type RAISES rather than being silently stringified — a
    # default=str fallback would mask hash/address-dependent nondeterminism.
    #
    # CAVEAT — floats are JSON-native so they bypass this hook and are NOT
    # normalised. Float→text formatting is a classic cross-engine divergence. The
    # Rust-produced identity surface (findings/spans/facts) carries no float
    # except `confidence` (null for every current PY-WL DEFECT rule); `coverage_pct`
    # in the assure posture is a float but is computed in the Python orchestration
    # layer (`build_posture`), which stays Python. If a future surface freezes an
    # engine-produced float, add explicit float normalisation here.
    if isinstance(obj, Enum):
        return obj.value
    raise TypeError(f"non-serialisable {type(obj).__name__!r} in identity corpus: {obj!r}")


def to_json(obj: Any) -> str:
    """Canonical JSON: sorted keys, no host-specific data, strict (raises on unknowns)."""
    return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False, default=_strict_default) + "\n"
