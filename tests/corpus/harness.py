"""Labeled-corpus harness (T1.4): run the engine over tests/corpus/fixtures plus
tests/corpus/sentinels and reconcile active DEFECT findings against MANIFEST.yaml
ground truth.

Matching key = (path relative to the scan root, rule_id, qualname). Line numbers are
deliberately NOT part of the key so line edits can't break the corpus. The FP rate
is measured over *active DEFECT* findings only (the policy surface, PY-WL-*) —
engine FACTs/metrics are not findings a user triages.

The FP population includes PREVIEW-maturity DEFECTs (S0 P1): there is no maturity
blind spot. `maturity: preview` rules gate exactly like stable ones (the 2026-06-29
decision), so excluding them from the corpus denominator would have measured the FP
rate of a rule set the gate does not actually ship. Every manifest row therefore
declares the maturity it was written against, and the loader rejects drift — a rule
graduating from preview to stable must update its entries rather than silently
changing what the corpus measured.

Two scan roots: `fixtures/` carries the TRUE_POSITIVE defect shapes and is the
frozen substrate of the Track 2 byte-identity golden (tests/grammar) — it must not
grow casually. `sentinels/` carries the clean-shape FALSE_POSITIVE sentinels the
engine must stay silent on; it is reconciled into the same DEFECT pool but is
invisible to the golden, so sentinels can be added freely. File names must be
unique across both roots (the matching key is root-relative).

Rows also carry a `kind` (the analysis family the specimen belongs to) so the gate
can be evaluated PER KIND, not only in aggregate: a kind with a small population can
hide its own FP rate inside a large healthy total. `_ALLOWED_KINDS` is forward
vocabulary for the S1-S4 workstreams; only `core` is populated today, and a task that
introduces a new kind inherits that kind's sentinel/specimen floors.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

import yaml

from wardline.core.finding import Kind, SuppressionState
from wardline.core.run import run_scan

CORPUS_ROOT = Path(__file__).parent / "fixtures"
SENTINEL_ROOT = Path(__file__).parent / "sentinels"
MANIFEST_PATH = Path(__file__).parent / "MANIFEST.yaml"

TRUE_POSITIVE = "TRUE_POSITIVE"
FALSE_POSITIVE = "FALSE_POSITIVE"
_LABELS = frozenset({TRUE_POSITIVE, FALSE_POSITIVE})

_ALLOWED_KEYS = frozenset({"rule_id", "qualname", "label", "note", "maturity", "kind", "interaction"})
_REQUIRED_KEYS = frozenset({"rule_id", "qualname", "label"})
_ALLOWED_SECTIONS = frozenset({"fixtures", "sentinels"})
_MATURITIES = frozenset({"stable", "preview"})
_ALLOWED_KINDS = frozenset({"core", "contracts", "facets", "restoration", "sensitivity", "dependency_taint"})
_ALLOWED_INTERACTIONS = frozenset({"", "contradiction", "match"})

# Every value the loader membership-tests must be proven a `str` FIRST: an unhashable
# YAML value (`rule_id: [a, b]`) reaching `x not in frozenset(...)` raises TypeError,
# not the ValueError the loader promises its callers.
_STRING_FIELDS = ("rule_id", "qualname", "label", "note", "maturity", "kind", "interaction")


def _rule_maturities() -> dict[str, str]:
    from wardline.scanner.rules import BUILTIN_RULE_CLASSES

    return {cls.metadata.rule_id: cls.metadata.maturity.value for cls in BUILTIN_RULE_CLASSES}


@dataclass(frozen=True)
class Expectation:
    path: str
    rule_id: str
    qualname: str
    label: str
    note: str
    maturity: str = "stable"
    kind: str = "core"
    interaction: str = ""
    section: str = "fixtures"


@dataclass(frozen=True)
class Reconciliation:
    active_defects: int
    false_positives: int
    unaccounted: list[tuple[str, str, str]]  # (path, rule_id, qualname) findings with no manifest entry
    stale: list[Expectation]  # TRUE_POSITIVE entries that matched no finding (silent FP sentinels are passing)
    active_by_kind: dict[str, int] = field(default_factory=dict)
    fp_by_kind: dict[str, int] = field(default_factory=dict)

    @property
    def fp_rate(self) -> float:
        return 0.0 if self.active_defects == 0 else self.false_positives / self.active_defects


def load_manifest() -> list[Expectation]:
    raw = yaml.safe_load(MANIFEST_PATH.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"{MANIFEST_PATH}: manifest root must be a mapping, got {type(raw).__name__}")
    if set(raw) != set(_ALLOWED_SECTIONS):
        raise ValueError(
            f"{MANIFEST_PATH}: manifest sections must be exactly {sorted(_ALLOWED_SECTIONS)}, "
            f"got {sorted(map(str, raw))}"
        )
    # Bound locally (not at import) so tests can monkeypatch the roots.
    section_roots = {"fixtures": CORPUS_ROOT, "sentinels": SENTINEL_ROOT}
    maturities = _rule_maturities()
    out: list[Expectation] = []
    seen_paths: set[str] = set()
    seen_keys: set[tuple[str, str, str, str]] = set()
    for section in ("fixtures", "sentinels"):
        rows_by_path = raw[section]
        if not isinstance(rows_by_path, dict):
            raise ValueError(f"{section}: section must be a mapping, got {type(rows_by_path).__name__}")
        root = section_roots[section]
        for path, entries in rows_by_path.items():
            if not isinstance(path, str) or not path:
                raise ValueError(f"{section}: fixture path must be a non-empty string, got {path!r}")
            pure = PurePosixPath(path)
            if pure.is_absolute() or path.startswith(("/", "\\")):
                raise ValueError(f"{path}: fixture path must be relative to {section}/")
            if ".." in pure.parts:
                raise ValueError(f"{path}: fixture path must not contain '..' components")
            resolved = (root / path).resolve()
            if not resolved.is_relative_to(root.resolve()):
                raise ValueError(f"{path}: fixture path escapes the {section}/ root")
            if path in seen_paths:
                raise ValueError(f"{path}: file name reused across scan roots — the matching key is root-relative")
            seen_paths.add(path)
            if not isinstance(entries, list):
                raise ValueError(f"{path}: manifest rows must be a list, got {type(entries).__name__}")
            for entry in entries:
                if not isinstance(entry, dict):
                    raise ValueError(f"{path}: manifest entry must be a mapping, got {type(entry).__name__}")
                unknown = set(entry) - _ALLOWED_KEYS
                if unknown:
                    raise ValueError(f"{path}: unknown key(s) {sorted(unknown)} in manifest entry")
                missing = _REQUIRED_KEYS - set(entry)
                if missing:
                    raise ValueError(f"{path}: missing required key(s) {sorted(missing)}")
                for name in _STRING_FIELDS:
                    if name in entry and not isinstance(entry[name], str):
                        raise ValueError(f"{path}: {name} must be a string, got {type(entry[name]).__name__}")
                if not resolved.is_file():
                    raise ValueError(f"{path}: no such fixture under {section}/")
                if entry["rule_id"] not in maturities:
                    raise ValueError(f"{path}: unknown rule_id {entry['rule_id']!r}")
                maturity = entry.get("maturity", "stable")
                if maturity not in _MATURITIES:
                    raise ValueError(f"{path}: bad maturity {maturity!r} (want one of {sorted(_MATURITIES)})")
                if maturities[entry["rule_id"]] != maturity:
                    raise ValueError(
                        f"{path}: {entry['rule_id']} maturity is {maturities[entry['rule_id']]!r} but the "
                        f"manifest says {maturity!r} — a graduated rule must update its entries"
                    )
                kind = entry.get("kind", "core")
                if kind not in _ALLOWED_KINDS:
                    raise ValueError(f"{path}: bad kind {kind!r} (want one of {sorted(_ALLOWED_KINDS)})")
                interaction = entry.get("interaction", "")
                if interaction not in _ALLOWED_INTERACTIONS:
                    raise ValueError(f"{path}: bad interaction {interaction!r}")
                label = entry["label"]
                if label not in _LABELS:
                    raise ValueError(f"{path}: bad label {label!r} (want one of {sorted(_LABELS)})")
                if section == "sentinels" and label != FALSE_POSITIVE:
                    raise ValueError(f"{path}: sentinels/ holds clean shapes only — label must be FALSE_POSITIVE")
                if interaction == "contradiction" and label != TRUE_POSITIVE:
                    raise ValueError(
                        f"{path}: interaction 'contradiction' marks a true-positive interaction specimen — "
                        f"label must be {TRUE_POSITIVE}, got {label!r}"
                    )
                if interaction == "match" and label != FALSE_POSITIVE:
                    raise ValueError(
                        f"{path}: interaction 'match' marks the clean sentinel of an interaction pair — "
                        f"label must be {FALSE_POSITIVE}, got {label!r}"
                    )
                key = (section, path, entry["rule_id"], entry["qualname"])
                if key in seen_keys:
                    raise ValueError(f"{path}: duplicate manifest key {key!r} — one row per reconciliation key")
                seen_keys.add(key)
                out.append(
                    Expectation(
                        path=path,
                        rule_id=entry["rule_id"],
                        qualname=entry["qualname"],
                        label=label,
                        note=entry.get("note", ""),
                        maturity=maturity,
                        kind=kind,
                        interaction=interaction,
                        section=section,
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
    # Seeded from the manifest so a declared kind with zero findings still reports a 0
    # bucket, and an unaccounted finding (which has no expectation, hence no kind) is
    # never silently attributed to `core`.
    manifest_kinds = {e.kind for e in expectations}
    active_by_kind: dict[str, int] = {kind: 0 for kind in manifest_kinds}
    fp_by_kind: dict[str, int] = {kind: 0 for kind in manifest_kinds}
    for finding in findings:
        if finding.kind is not Kind.DEFECT or finding.suppressed is not SuppressionState.ACTIVE:
            continue
        active_defects += 1  # global population is counted before lookup
        key = (finding.location.path, finding.rule_id, finding.qualname or "")
        expectation = by_key.get(key)
        if expectation is None:
            unaccounted.append(key)
            continue
        kind = expectation.kind
        active_by_kind[kind] = active_by_kind.get(kind, 0) + 1
        matched_keys.add(key)
        if expectation.label == FALSE_POSITIVE:
            false_positives += 1
            fp_by_kind[kind] = fp_by_kind.get(kind, 0) + 1
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
        active_by_kind=active_by_kind,
        fp_by_kind=fp_by_kind,
    )
