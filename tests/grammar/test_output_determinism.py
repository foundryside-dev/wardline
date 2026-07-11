"""Run-to-run output determinism guard (wardline-e159060db7).

The product promises a stable finding stream (non-flaky gate, byte-stable
baselines/attestations). That property is currently held by convention scattered
across ~10 engine sites (sorted() discovery, Tarjan node/neighbor sorting,
least_trusted commutativity over unsorted callee sets, ...). The golden oracle
(``test_golden_oracle.py``) pins ONE run against a frozen golden, and only for
STABLE-maturity findings — it would catch drift, but a nondeterministic PREVIEW
rule or per-run engine state would slip past it.

This is the single guard at the output boundary: two INDEPENDENT analyzer runs
over the fixed corpus must produce byte-identical full streams (every maturity,
every kind), in identical order.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from wardline.core.config import WardlineConfig
from wardline.core.finding import ENGINE_PATH, Finding, Kind
from wardline.core.taints import TRUST_RANK, TaintState
from wardline.scanner.analyzer import WardlineAnalyzer

REPO_ROOT = Path(__file__).resolve().parents[2]
_CORPUS = REPO_ROOT / "tests" / "corpus" / "fixtures"


def _corpus_findings() -> Sequence[Finding]:
    """One complete, ordered analyzer run over the labeled corpus.

    Unlike ``golden_harness.produce_stream`` this does NOT filter to STABLE
    maturity: PREVIEW rules (PY-WL-116..126) must be order-deterministic too —
    they feed baselines and the delta gate even before graduation.
    """
    files = sorted(_CORPUS.rglob("*.py"))
    analyzer = WardlineAnalyzer()
    return analyzer.analyze(files, WardlineConfig(), root=REPO_ROOT)


def _full_stream() -> str:
    return "\n".join(f.to_jsonl() for f in _corpus_findings())


def test_analyzer_output_is_byte_identical_across_runs() -> None:
    first = _full_stream()
    second = _full_stream()
    assert first, "corpus produced an empty stream — fixture path broken"
    assert first == second, "analyzer output differs between identical runs"


def test_builtin_source_defects_have_source_lines() -> None:
    offenders = [
        (f.rule_id, f.location.path, f.qualname)
        for f in _corpus_findings()
        if f.kind is Kind.DEFECT and f.location.path != ENGINE_PATH and f.location.line_start is None
    ]
    assert offenders == []


def test_trust_rank_is_injective() -> None:
    # Load-bearing for order stability: callee sets are aggregated with the
    # rank-meet ``least_trusted`` via ``reduce`` over an UNSORTED set
    # (propagation.py); that is only order-independent (commutative +
    # associative) while TRUST_RANK assigns every TaintState a DISTINCT rank.
    # Two states sharing a rank would make the reduce pick whichever the set
    # yields first — silent per-run nondeterminism.
    ranks = [TRUST_RANK[t] for t in TaintState]
    assert len(set(ranks)) == len(list(TaintState))
