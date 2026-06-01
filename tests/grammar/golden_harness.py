"""Byte-identity oracle harness (Track 2, Task 0).

Produces the canonical findings stream for the builtin grammar over the **T1.4
labeled corpus**, serialized exactly as `wardline scan` would (the shipped
per-finding serializer ``Finding.to_jsonl()`` — the same line format
``core.emit.JsonlEmitter`` writes; there is no module-level serializer). Used to
freeze a golden before the grammar refactor and to assert byte-for-byte
reproduction after it (design spec §5).

**Why corpus-only (a refinement of spec §5, made empirically in Task 0):** the
corpus is FIXED test data — all four builtin rules fire across it (21 DEFECTs over
PY-WL-101/102/103/104), and its full stream (DEFECTs + FACTs + METRICs) is immune
to source-tree growth. The *dogfood* tree is NOT a stable golden substrate: the
Track 2 refactor necessarily ADDS source files (``scanner/grammar.py``) and edits
others, which legitimately changes the dogfood scan's METRIC findings
(``taint_source_counts`` / ``scc_size_distribution``) without changing any rule
semantics. The dogfood byte-identity *intent* — "the tree stays finding-clean" — is
the correct DoD gate and is guarded by ``tests/test_self_hosting.py`` (zero DEFECT,
which tolerates source growth). So the byte-for-byte oracle pins the corpus; the
self-hosting test pins the dogfood. Together they cover the program-spec DoD.

Deterministic for a fixed input with no summary cache (``cache_hit_rate`` is 0.0;
the METRIC values are pure functions of the source; fingerprints are stable
SHA-256).
"""

from __future__ import annotations

from pathlib import Path

from wardline.core.config import WardlineConfig
from wardline.scanner.analyzer import WardlineAnalyzer

REPO_ROOT = Path(__file__).resolve().parents[2]
GOLDEN = Path(__file__).resolve().parent / "golden" / "builtin_findings.jsonl"

_CORPUS = "tests/corpus/fixtures"


def produce_stream() -> str:
    """Return the canonical builtin-grammar findings stream over the labeled corpus."""
    target = REPO_ROOT / _CORPUS
    files = sorted(target.rglob("*.py"))
    analyzer = WardlineAnalyzer()  # builtin grammar / default provider + registry
    findings = analyzer.analyze(files, WardlineConfig(), root=REPO_ROOT)
    return "\n".join(f.to_jsonl() for f in findings)
