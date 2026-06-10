"""Labeled-corpus harness (T1.4): run the engine over tests/corpus/fixtures plus
tests/corpus/sentinels and reconcile active DEFECT findings against MANIFEST.yaml
ground truth.

Matching key = (path relative to the scan root, rule_id, qualname). Line numbers are
deliberately NOT part of the key so line edits can't break the corpus. The FP rate
is measured over *active DEFECT* findings only (the policy surface, PY-WL-*) —
engine FACTs/metrics are not findings a user triages.

Two scan roots: `fixtures/` carries the TRUE_POSITIVE defect shapes and is the
frozen substrate of the Track 2 byte-identity golden (tests/grammar) — it must not
grow casually. `sentinels/` carries the clean-shape FALSE_POSITIVE sentinels the
engine must stay silent on; it is reconciled into the same DEFECT pool but is
invisible to the golden, so sentinels can be added freely. File names must be
unique across both roots (the matching key is root-relative).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from wardline.core.finding import Kind, Maturity, SuppressionState
from wardline.core.run import run_scan

CORPUS_ROOT = Path(__file__).parent / "fixtures"
SENTINEL_ROOT = Path(__file__).parent / "sentinels"
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
    stale: list[Expectation]  # TRUE_POSITIVE entries that matched no finding (silent FP sentinels are passing)

    @property
    def fp_rate(self) -> float:
        return 0.0 if self.active_defects == 0 else self.false_positives / self.active_defects


def load_manifest() -> list[Expectation]:
    raw = yaml.safe_load(MANIFEST_PATH.read_text()) or {}
    out: list[Expectation] = []
    seen_paths: set[str] = set()
    for section in ("fixtures", "sentinels"):
        for path, entries in (raw.get(section) or {}).items():
            if path in seen_paths:
                raise ValueError(f"{path}: file name reused across scan roots — the matching key is root-relative")
            seen_paths.add(path)
            for entry in entries or []:
                label = entry["label"]
                if label not in _LABELS:
                    raise ValueError(f"{path}: bad label {label!r} (want one of {sorted(_LABELS)})")
                if section == "sentinels" and label != FALSE_POSITIVE:
                    raise ValueError(f"{path}: sentinels/ holds clean shapes only — label must be FALSE_POSITIVE")
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
    findings = [f for root in (CORPUS_ROOT, SENTINEL_ROOT) for f in run_scan(root).findings]
    expectations = load_manifest()
    by_key: dict[tuple[str, str, str], Expectation] = {(e.path, e.rule_id, e.qualname): e for e in expectations}
    matched_keys: set[tuple[str, str, str]] = set()
    active_defects = 0
    false_positives = 0
    unaccounted: list[tuple[str, str, str]] = []
    for finding in findings:
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
    # Staleness only applies to TRUE_POSITIVE entries: a FALSE_POSITIVE sentinel the
    # engine stays silent on is the engine behaving correctly, not a dead manifest row.
    stale = [
        e for e in expectations if e.label == TRUE_POSITIVE and (e.path, e.rule_id, e.qualname) not in matched_keys
    ]
    return Reconciliation(
        active_defects=active_defects,
        false_positives=false_positives,
        unaccounted=unaccounted,
        stale=stale,
    )
