#!/usr/bin/env python3
"""Generate the full WP-1.8 test corpus.

Creates TP+TN specimens for every non-SUPPRESS cell in the 9x8 matrix,
plus adversarial specimens.  Run from the repo root:

    uv run python scripts/generate_corpus.py
"""
from __future__ import annotations

import glob
import hashlib
import json
import os
import sys
from pathlib import Path

import yaml

from wardline.cli.corpus_cmds import _compute_corpus_hash
from wardline.core.matrix import SEVERITY_MATRIX
from wardline.core.severity import Exceptionability, RuleId, Severity
from wardline.core.taints import TAINT_CONTEXT, TaintState

sys.path.insert(0, str(Path(__file__).parent))
from migrate_expected_match import compute_expected_location  # noqa: E402

TAINT_ORDER = [
    TaintState.INTEGRAL,
    TaintState.ASSURED,
    TaintState.GUARDED,
    TaintState.EXTERNAL_RAW,
    TaintState.UNKNOWN_RAW,
    TaintState.UNKNOWN_GUARDED,
    TaintState.UNKNOWN_ASSURED,
    TaintState.MIXED_RAW,
]
RULES = [getattr(RuleId, f"PY_WL_{i:03d}") for i in range(1, 10)]
BASE = "corpus/specimens"

# Rules where taint does not affect severity/exceptionability/detection.
# These get a single specimen per verdict instead of 8.
TAINT_INVARIANT_RULES = {RuleId.PY_WL_008, RuleId.PY_WL_009}
# For taint-invariant rules, use this as the single representative taint state.
TAINT_INVARIANT_REPRESENTATIVE = "EXTERNAL_RAW"


# ---------------------------------------------------------------------------
# TP fragments — code that SHOULD trigger the rule
# ---------------------------------------------------------------------------
def _tp_fragment(rule: str, taint_name: str) -> str:
    """Generate a TP fragment with taint-specific function/variable names."""
    suffix, var = TAINT_CONTEXT[taint_name]
    templates: dict[str, str] = {
        "PY-WL-001": f'def dict_default_{suffix}({var}):\n    x = {var}.get("key", "default")\n',
        "PY-WL-002": f'def getattr_default_{suffix}({var}):\n    x = getattr({var}, "name", None)\n',
        "PY-WL-003": f'def key_check_{suffix}({var}):\n    if "key" in {var}:\n        pass\n',
        "PY-WL-004": f"def broad_except_{suffix}():\n    try:\n        pass\n    except Exception:\n        handle()\n",
        "PY-WL-005": f"def silent_except_{suffix}():\n    try:\n        pass\n    except Exception:\n        pass\n",
        "PY-WL-006": f'def audit_broad_{suffix}():\n    try:\n        risky()\n    except Exception:\n        logger.error("failed")\n',
        "PY-WL-007": f"def isinstance_check_{suffix}({var}):\n    if isinstance({var}, dict):\n        pass\n",
        "PY-WL-008": "def process(data):\n    result = validate(data)\n    return data\n",
        "PY-WL-009": 'def process(data):\n    if data["status"] == "active":\n        pass\n',
    }
    return templates[rule]


# ---------------------------------------------------------------------------
# TN fragments — code that should NOT trigger the rule
# ---------------------------------------------------------------------------
def _tn_fragment(rule: str, taint_name: str) -> str:
    """Generate a TN fragment with taint-specific function/variable names."""
    suffix, var = TAINT_CONTEXT[taint_name]
    templates: dict[str, str] = {
        "PY-WL-001": f'def no_default_{suffix}({var}):\n    x = {var}.get("key")\n',
        "PY-WL-002": f'def getattr_no_default_{suffix}({var}):\n    x = getattr({var}, "name")\n',
        "PY-WL-003": f'def direct_access_{suffix}({var}):\n    x = {var}["key"]\n',
        "PY-WL-004": f"def specific_except_{suffix}():\n    try:\n        pass\n    except ValueError:\n        handle()\n",
        "PY-WL-005": f"def silent_specific_{suffix}():\n    try:\n        pass\n    except ValueError:\n        pass\n",
        "PY-WL-006": f'def audit_specific_{suffix}():\n    try:\n        risky()\n    except ValueError:\n        logger.error("failed")\n',
        "PY-WL-007": f"def no_typecheck_{suffix}({var}):\n    x = len({var})\n",
        "PY-WL-008": 'def process(data):\n    result = validate(data)\n    if not result:\n        raise ValueError("invalid")\n',
        "PY-WL-009": 'from wardline.decorators import validates_semantic\n\n@validates_semantic\ndef validate_order(data):\n    if not isinstance(data, dict):\n        raise TypeError("expected dict")\n    if data["amount"] > 1000:\n        raise ValueError("amount exceeds limit")\n    return data\n',
    }
    return templates[rule]


# PY-WL-003 produces SUPPRESS severity at these taint states — the rule still
# fires, but findings are suppressed.  Specimens here are marked KFN.
PY_WL_003_ACTIVE_TAINTS = {"EXTERNAL_RAW", "UNKNOWN_RAW", "MIXED_RAW"}


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _write_specimen(path: str, data: dict) -> None:
    """Write YAML metadata and matching .py code file."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write("---\n")
        yaml.dump(data, f, Dumper=yaml.SafeDumper, default_flow_style=False, sort_keys=False)

    # Generate matching .py file from the fragment
    fragment = data.get("fragment", "")
    if fragment:
        py_path = path.rsplit(".", 1)[0] + ".py"
        with open(py_path, "w") as f:
            f.write(fragment)


def generate_matrix_specimens() -> dict[str, dict]:
    """Generate TP+TN for every non-SUPPRESS cell."""
    manifest: dict[str, dict] = {}
    tp_count = 0
    tn_count = 0
    kfn_count = 0

    for rule in RULES:
        rule_str = str(rule)
        for taint in TAINT_ORDER:
            cell = SEVERITY_MATRIX[(rule, taint)]
            taint_name = taint.name

            # Skip SUPPRESS cells
            if cell.severity == Severity.SUPPRESS:
                continue

            # For taint-invariant rules, only generate the representative taint state
            if rule in TAINT_INVARIANT_RULES and taint_name != TAINT_INVARIANT_REPRESENTATIVE:
                continue

            # PY-WL-003 is taint-gated: only fires at 3 taint states
            tp_will_fire = True
            if rule_str == "PY-WL-003" and taint_name not in PY_WL_003_ACTIVE_TAINTS:
                tp_will_fire = False

            # --- TP specimen ---
            tp_frag = _tp_fragment(rule_str, taint_name)
            tp_hash = _sha256(tp_frag)

            if rule in TAINT_INVARIANT_RULES:
                tp_id = f"{rule_str}-TP-standard"
            else:
                tp_id = f"{rule_str}-TP-{taint_name}"

            if tp_will_fire:
                verdict = "true_positive"
                exp_sev = cell.severity.name
                exp_exc = cell.exceptionability.name
                exp_rules = [rule_str]
                tp_count += 1
            else:
                verdict = "known_false_negative"
                exp_sev = None
                exp_exc = None
                exp_rules = []
                kfn_count += 1

            em = compute_expected_location(tp_frag, rule_str) if tp_will_fire else False
            tp_data: dict[str, object] = {
                "specimen_id": tp_id,
                "description": f"{rule_str} {verdict} at {taint_name}",
                "rule": rule_str,
                "fragment": tp_frag,
                "taint_state": taint_name,
                "expected_rules": exp_rules,
                "expected_severity": exp_sev,
                "expected_exceptionability": exp_exc,
                "expected_match": em if em is not None else tp_will_fire,
                "sha256": tp_hash,
                "verdict": verdict,
            }
            if isinstance(em, dict):
                tp_data["expected_match_source"] = "ast-reimplemented"
            tp_path = os.path.join(
                BASE, rule_str, taint_name, "positive", f"{tp_id}.yaml"
            )
            _write_specimen(tp_path, tp_data)
            manifest[tp_id] = {
                "path": os.path.relpath(tp_path, "corpus"),
                "sha256": tp_hash,
            }

            # --- TN specimen ---
            tn_frag = _tn_fragment(rule_str, taint_name)
            tn_hash = _sha256(tn_frag)

            if rule in TAINT_INVARIANT_RULES:
                tn_id = f"{rule_str}-TN-standard"
            else:
                tn_id = f"{rule_str}-TN-{taint_name}"

            tn_data = {
                "specimen_id": tn_id,
                "description": f"{rule_str} true negative at {taint_name}",
                "rule": rule_str,
                "fragment": tn_frag,
                "taint_state": taint_name,
                "expected_rules": [],
                "expected_severity": None,
                "expected_exceptionability": None,
                "expected_match": False,
                "sha256": tn_hash,
                "verdict": "true_negative",
            }
            tn_path = os.path.join(
                BASE, rule_str, taint_name, "negative", f"{tn_id}.yaml"
            )
            _write_specimen(tn_path, tn_data)
            manifest[tn_id] = {
                "path": os.path.relpath(tn_path, "corpus"),
                "sha256": tn_hash,
            }
            tn_count += 1

    print(f"Matrix specimens: {tp_count} TP, {kfn_count} KFN, {tn_count} TN")
    return manifest


def generate_adversarial_specimens() -> dict[str, dict]:
    """Generate adversarial / evasion specimens."""
    manifest: dict[str, dict] = {}
    ADV_DIR = os.path.join(BASE, "adversarial")

    long_body = "".join(f"    x{i} = {i}\n" for i in range(50))

    specimens = [
        {
            "specimen_id": "ADV-001-alias",
            "description": "Aliased dict.get via local variable",
            "rule": "PY-WL-001",
            "fragment": 'def process(data):\n    getter = data.get\n    x = getter("key", "default")\n',
            "taint_state": "EXTERNAL_RAW",
            "expected_rules": [],
            "expected_match": False,
            "verdict": "known_false_negative",
            "tags": ["adversarial", "alias"],
        },
        {
            "specimen_id": "ADV-002-dynamic-dispatch",
            "description": "Dynamic dispatch via getattr to call .get",
            "rule": "PY-WL-001",
            "fragment": 'def process(data):\n    method = getattr(data, "get")\n    x = method("key", "default")\n',
            "taint_state": "EXTERNAL_RAW",
            "expected_rules": [],
            "expected_match": False,
            "verdict": "known_false_negative",
            "tags": ["adversarial", "dynamic-dispatch"],
        },
        {
            "specimen_id": "ADV-003-nested-scope",
            "description": "Pattern inside nested function (visited separately)",
            "rule": "PY-WL-001",
            "fragment": 'def outer():\n    def inner(data):\n        x = data.get("key", "default")\n    return inner\n',
            "taint_state": "EXTERNAL_RAW",
            "expected_rules": ["PY-WL-001"],
            "expected_match": True,  # placeholder — computed below
            "verdict": "true_positive",
            "tags": ["adversarial", "nested-scope"],
        },
        {
            "specimen_id": "ADV-004-unicode-ident",
            "description": "Unicode identifiers in function name",
            "rule": "PY-WL-004",
            "fragment": "def pr\u00f6cess():\n    try:\n        pass\n    except Exception:\n        handle()\n",
            "taint_state": "EXTERNAL_RAW",
            "expected_rules": ["PY-WL-004"],
            "expected_match": True,  # placeholder — computed below
            "verdict": "true_positive",
            "tags": ["adversarial", "unicode"],
        },
        {
            "specimen_id": "ADV-007-async-get",
            "description": "Async function with dict.get pattern",
            "rule": "PY-WL-001",
            "fragment": 'async def adv_async_get(data):\n    x = data.get("key", "default")\n',
            "taint_state": "EXTERNAL_RAW",
            "expected_rules": ["PY-WL-001"],
            "expected_match": True,  # placeholder — computed below
            "verdict": "true_positive",
            "tags": ["adversarial", "async"],
        },
        {
            "specimen_id": "ADV-012-setdefault",
            "description": "dict.setdefault triggers PY-WL-001",
            "rule": "PY-WL-001",
            "fragment": 'def adv_setdefault(data):\n    x = data.setdefault("key", [])\n',
            "taint_state": "EXTERNAL_RAW",
            "expected_rules": ["PY-WL-001"],
            "expected_match": True,  # placeholder — computed below
            "verdict": "true_positive",
            "tags": ["adversarial", "setdefault"],
        },
        {
            "specimen_id": "ADV-013-defaultdict",
            "description": "defaultdict with factory triggers PY-WL-001",
            "rule": "PY-WL-001",
            "fragment": "from collections import defaultdict\ndef adv_defaultdict():\n    d = defaultdict(list)\n",
            "taint_state": "UNKNOWN_RAW",
            "expected_rules": ["PY-WL-001"],
            "expected_match": True,  # placeholder — computed below
            "verdict": "true_positive",
            "tags": ["adversarial", "defaultdict"],
        },
        {
            "specimen_id": "ADV-014-hasattr-taint-gate",
            "description": "hasattr in non-active taint state should not fire PY-WL-003",
            "rule": "PY-WL-003",
            "fragment": 'def process(obj):\n    if hasattr(obj, "name"):\n        pass\n',
            "taint_state": "INTEGRAL",
            "expected_rules": [],
            "expected_match": False,
            "verdict": "true_negative",
            "tags": ["adversarial", "taint-gate"],
        },
        {
            "specimen_id": "ADV-015-tuple-except",
            "description": "Tuple except with Exception triggers PY-WL-004",
            "rule": "PY-WL-004",
            "fragment": "def process():\n    try:\n        pass\n    except (ValueError, Exception):\n        handle()\n",
            "taint_state": "ASSURED",
            "expected_rules": ["PY-WL-004"],
            "expected_match": True,  # placeholder — computed below
            "verdict": "true_positive",
            "tags": ["adversarial", "tuple-except"],
        },
        # ── PY-WL-006 adversarial specimens ──
        {
            "specimen_id": "ADV-016-aliased-audit",
            "description": "Audit function aliased via local variable evades detection",
            "rule": "PY-WL-006",
            "fragment": (
                "def process():\n"
                "    writer = audit_ledger.record\n"
                "    try:\n"
                "        risky()\n"
                "    except Exception:\n"
                "        writer(event)\n"
            ),
            "taint_state": "EXTERNAL_RAW",
            "expected_rules": [],
            "expected_match": False,
            "verdict": "known_false_negative",
            "tags": ["adversarial", "alias", "audit"],
        },
        {
            "specimen_id": "ADV-017-audit-in-finally",
            "description": "Audit call in finally block inside broad handler still fires",
            "rule": "PY-WL-006",
            "fragment": (
                "def process():\n"
                "    try:\n"
                "        risky()\n"
                "    except Exception:\n"
                "        try:\n"
                '            audit_ledger.record("failed")\n'
                "        finally:\n"
                "            pass\n"
            ),
            "taint_state": "EXTERNAL_RAW",
            "expected_rules": ["PY-WL-006"],
            "expected_match": True,  # placeholder — computed below
            "verdict": "true_positive",
            "tags": ["adversarial", "nested-try", "audit"],
        },
        # ── PY-WL-007 adversarial specimens ──
        {
            "specimen_id": "ADV-018-isinstance-boundary",
            "description": "isinstance in declared boundary function is suppressed",
            "rule": "PY-WL-007",
            "fragment": (
                "from wardline.decorators import validates_shape\n"
                "\n"
                "@validates_shape\n"
                "def validate(data):\n"
                "    if not isinstance(data, dict):\n"
                '        raise TypeError("expected dict")\n'
            ),
            "taint_state": "ASSURED",
            "expected_rules": [],
            "expected_match": False,
            "verdict": "true_negative",
            "tags": ["adversarial", "boundary-suppression"],
        },
        {
            "specimen_id": "ADV-019-isinstance-dunder-eq",
            "description": "isinstance in __eq__ with NotImplemented is suppressed",
            "rule": "PY-WL-007",
            "fragment": (
                "class Value:\n"
                "    def __eq__(self, other):\n"
                "        if not isinstance(other, Value):\n"
                "            return NotImplemented\n"
                "        return self.x == other.x\n"
            ),
            "taint_state": "INTEGRAL",
            "expected_rules": [],
            "expected_match": False,
            "verdict": "true_negative",
            "tags": ["adversarial", "dunder-protocol"],
        },
    ]

    for spec in specimens:
        frag = spec["fragment"]
        sha = _sha256(frag)
        spec["sha256"] = sha

        # Compute structured expected_match for TP specimens
        if spec.get("expected_match") is True and spec["verdict"] == "true_positive":
            rule_str = spec["rule"]
            location = compute_expected_location(frag, rule_str)
            if location is not None:
                spec["expected_match"] = location
                spec["expected_match_source"] = "ast-reimplemented"

        # Populate severity/exceptionability from matrix for TP specimens
        if spec.get("expected_match"):
            rule = RuleId(spec["rule"])
            taint = TaintState[spec["taint_state"]]
            cell = SEVERITY_MATRIX[(rule, taint)]
            spec.setdefault("expected_severity", cell.severity.name)
            spec.setdefault("expected_exceptionability", cell.exceptionability.name)
        else:
            spec.setdefault("expected_severity", None)
            spec.setdefault("expected_exceptionability", None)

        path = os.path.join(ADV_DIR, f"{spec['specimen_id']}.yaml")
        _write_specimen(path, spec)
        manifest[spec["specimen_id"]] = {
            "path": os.path.relpath(path, "corpus"),
            "sha256": sha,
        }

    print(f"Adversarial specimens: {len(specimens)}")
    return manifest


def write_manifest() -> None:
    """Write the corpus manifest JSON from actual files on disk.

    Regenerates from disk to catch any manually-added specimens and
    prevent manifest drift.  Fails if orphaned .py files exist without
    corresponding .yaml metadata.
    """
    # Detect orphaned .py files (no matching .yaml)
    yaml_stems = {
        os.path.splitext(p)[0]
        for p in glob.glob(f"{BASE}/**/*.yaml", recursive=True)
    }
    orphans = [
        p for p in sorted(glob.glob(f"{BASE}/**/*.py", recursive=True))
        if os.path.splitext(p)[0] not in yaml_stems
    ]
    if orphans:
        print(f"ERROR: {len(orphans)} orphaned .py file(s) without YAML metadata:")
        for p in orphans:
            print(f"  {p}")
        sys.exit(1)

    # Scan disk for all YAML specimens (authoritative source)
    disk_entries = []
    for yaml_path in sorted(glob.glob(f"{BASE}/**/*.yaml", recursive=True)):
        with open(yaml_path) as f:
            data = yaml.safe_load(f)  # noqa: S506 — safe_load is safe
        if not isinstance(data, dict):
            continue
        py_path = yaml_path.rsplit(".", 1)[0] + ".py"
        rel = os.path.relpath(yaml_path, "corpus")
        disk_entries.append({
            "specimen_id": data.get("specimen_id", os.path.splitext(os.path.basename(yaml_path))[0]),
            "path": rel,
            "py_exists": os.path.exists(py_path),
            "rule": data.get("rule", ""),
            "taint_state": data.get("taint_state", ""),
            "verdict": data.get("verdict", ""),
            "expected_match": data.get("expected_match"),
            "sha256": data.get("sha256", ""),
        })

    out = {
        "version": "1.0",
        "spec_version": "1.0",
        "corpus_hash": _compute_corpus_hash(Path(BASE)),
        "generated": __import__("datetime").date.today().isoformat(),
        "specimen_count": len(disk_entries),
        "specimens": disk_entries,
    }
    path = "corpus/corpus_manifest.json"
    with open(path, "w") as f:
        json.dump(out, f, indent=2)
        f.write("\n")
    print(f"Manifest written: {len(disk_entries)} entries -> {path}")


def main() -> None:
    generate_matrix_specimens()
    generate_adversarial_specimens()
    write_manifest()


if __name__ == "__main__":
    main()
