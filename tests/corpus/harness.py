"""Labeled-corpus harness (T1.4): run the engine over tests/corpus/fixtures and
reconcile active DEFECT findings against MANIFEST.yaml ground truth.

Matching key = (path relative to fixtures, rule_id, qualname). Line numbers are
deliberately NOT part of the key so line edits can't break the corpus. The FP rate
is measured over *active DEFECT* findings only (the policy surface, PY-WL-*) —
engine FACTs/metrics are not findings a user triages.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from wardline.core.finding import Kind, Maturity, SuppressionState
from wardline.core.run import run_scan

CORPUS_ROOT = Path(__file__).parent / "fixtures"
MANIFEST_PATH = Path(__file__).parent / "MANIFEST.yaml"

TRUE_POSITIVE = "TRUE_POSITIVE"
FALSE_POSITIVE = "FALSE_POSITIVE"
_LABELS = frozenset({TRUE_POSITIVE, FALSE_POSITIVE})


@dataclass(frozen=True)
class Expectation:
    path: str
    rule_id: str
    qualname: str
    label: str
    note: str


@dataclass(frozen=True)
class Reconciliation:
    active_defects: int
    false_positives: int
    unaccounted: list[tuple[str, str, str]]  # (path, rule_id, qualname) findings with no manifest entry
    stale: list[Expectation]  # manifest entries that matched no finding

    @property
    def fp_rate(self) -> float:
        return 0.0 if self.active_defects == 0 else self.false_positives / self.active_defects


def load_manifest() -> list[Expectation]:
    raw = yaml.safe_load(MANIFEST_PATH.read_text()) or {}
    out: list[Expectation] = []
    for path, entries in (raw.get("fixtures") or {}).items():
        for entry in entries or []:
            label = entry["label"]
            if label not in _LABELS:
                raise ValueError(f"{path}: bad label {label!r} (want one of {sorted(_LABELS)})")
            out.append(
                Expectation(
                    path=path,
                    rule_id=entry["rule_id"],
                    qualname=entry["qualname"],
                    label=label,
                    note=entry.get("note", ""),
                )
            )
    return out


def reconcile() -> Reconciliation:
    result = run_scan(CORPUS_ROOT)
    expectations = load_manifest()
    by_key: dict[tuple[str, str, str], Expectation] = {(e.path, e.rule_id, e.qualname): e for e in expectations}
    matched_keys: set[tuple[str, str, str]] = set()
    active_defects = 0
    false_positives = 0
    unaccounted: list[tuple[str, str, str]] = []
    for finding in result.findings:
        if finding.kind is not Kind.DEFECT or finding.suppressed is not SuppressionState.ACTIVE:
            continue
        if finding.maturity is Maturity.PREVIEW:
            continue
        active_defects += 1
        key = (finding.location.path, finding.rule_id, finding.qualname or "")
        expectation = by_key.get(key)
        if expectation is None:
            unaccounted.append(key)
            continue
        matched_keys.add(key)
        if expectation.label == FALSE_POSITIVE:
            false_positives += 1
    stale = [e for e in expectations if (e.path, e.rule_id, e.qualname) not in matched_keys]
    return Reconciliation(
        active_defects=active_defects,
        false_positives=false_positives,
        unaccounted=unaccounted,
        stale=stale,
    )
