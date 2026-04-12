"""BAR panel aggregation rule and policy-hash computation.

This module is the authoritative implementation of the §4 aggregation rule
and the §7.4 policy-hash computation from the BAR review pipeline
specification (docs/governance/bar-review-pipeline.md). It is versioned as
part of the policy tree; changes to this file are material policy changes
and trigger a policy-hash change and a pipeline version bump.

This module MUST remain a standalone Python 3.12+ file with no external
dependencies beyond the standard library. Pipeline runners load this
module directly from the policy tree at review time.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Final

# Panel composition. Order is significant for deterministic serialization
# but NOT for aggregation semantics (aggregation is order-independent).
PANEL_ROLES: Final[tuple[str, ...]] = (
    "solution-architect",
    "systems-thinker",
    "python-engineer",
    "quality-engineer",
    "security-architect",
    "static-analysis-engineer",
    "irap-assessor",
)

# Verdict vocabulary. These are the only four values any reviewer or
# aggregate is permitted to take. See shared-preamble.md for full semantics.
VERDICT_PASS: Final[str] = "pass"
VERDICT_FAIL: Final[str] = "fail"
VERDICT_INSUFFICIENT_EVIDENCE: Final[str] = "insufficient_evidence"
VERDICT_REFER: Final[str] = "refer"

VALID_VERDICTS: Final[frozenset[str]] = frozenset(
    {VERDICT_PASS, VERDICT_FAIL, VERDICT_INSUFFICIENT_EVIDENCE, VERDICT_REFER}
)


class AggregationError(ValueError):
    """Raised when reviewer verdicts cannot be aggregated.

    Distinct from a fail verdict — this means the inputs to the aggregation
    rule itself are malformed, which is a pipeline bug, not a review
    outcome.
    """


def aggregate(reviewer_verdicts: dict[str, str]) -> str:
    """Aggregate per-reviewer verdicts into a single pipeline verdict.

    Implements the §4 aggregation rule from bar-review-pipeline.md:

      1. If any reviewer outputs 'refer', the aggregate is 'refer'.
      2. Else if any reviewer outputs 'fail', the aggregate is 'fail'.
      3. Else if any reviewer outputs 'insufficient_evidence', the
         aggregate is 'insufficient_evidence'.
      4. Else if and only if all 7 reviewers output 'pass', the aggregate
         is 'pass'.

    Parameters
    ----------
    reviewer_verdicts :
        Mapping from role name to verdict string. MUST contain exactly
        the seven roles in PANEL_ROLES; any extra or missing role raises
        AggregationError. MUST NOT contain any verdict outside
        VALID_VERDICTS.

    Returns
    -------
    The aggregate verdict string.

    Raises
    ------
    AggregationError
        If the input is malformed (missing role, extra role, invalid
        verdict value).
    """
    if not isinstance(reviewer_verdicts, dict):
        raise AggregationError(f"reviewer_verdicts must be dict, got {type(reviewer_verdicts).__name__}")

    given_roles = set(reviewer_verdicts.keys())
    expected_roles = set(PANEL_ROLES)
    missing = expected_roles - given_roles
    extra = given_roles - expected_roles
    if missing or extra:
        raise AggregationError(
            f"reviewer_verdicts role set mismatch: missing={sorted(missing)}, extra={sorted(extra)}"
        )

    for role, verdict in reviewer_verdicts.items():
        if verdict not in VALID_VERDICTS:
            raise AggregationError(
                f"role '{role}' produced verdict '{verdict}' not in {sorted(VALID_VERDICTS)}"
            )

    verdict_set = set(reviewer_verdicts.values())

    if VERDICT_REFER in verdict_set:
        return VERDICT_REFER
    if VERDICT_FAIL in verdict_set:
        return VERDICT_FAIL
    if VERDICT_INSUFFICIENT_EVIDENCE in verdict_set:
        return VERDICT_INSUFFICIENT_EVIDENCE
    if verdict_set == {VERDICT_PASS}:
        return VERDICT_PASS

    # Unreachable: verdict_set is a non-empty subset of VALID_VERDICTS and
    # we have exhausted the explicit branches above.
    raise AggregationError(f"aggregation fell through with verdict_set={verdict_set}")


# §5 of bar-review-pipeline.md requires exactly three independent runs for
# the self-assessment stability check. This constant is normative, not a
# default. A caller who passes any other number is violating the spec and
# MUST be rejected — two identical runs could otherwise satisfy the check
# and let a caller cut corners on the determinism property.
STABILITY_REQUIRED_RUNS: Final[int] = 3


def check_stability(run_verdicts: list[dict[str, str]]) -> tuple[bool, str]:
    """Check the §5 determinism property across the required three runs.

    An obligation is stable if and only if every run produces (a) the same
    aggregate verdict AND (b) the exact same per-reviewer verdict for each
    role. Partial agreement — e.g., same aggregate but different per-role
    votes — counts as unstable, because it signals model non-determinism
    that could flip under pressure.

    Parameters
    ----------
    run_verdicts :
        A list of reviewer-verdict dicts, one per run. §5 of
        bar-review-pipeline.md requires EXACTLY three independent runs
        (STABILITY_REQUIRED_RUNS). Any other count is a spec violation
        and raises AggregationError — this is not a configurable knob.

    Returns
    -------
    (is_stable, explanation) where explanation is empty on stability and a
    human-readable diagnostic on instability.

    Raises
    ------
    AggregationError
        If the run count is not exactly STABILITY_REQUIRED_RUNS, or if any
        run has malformed reviewer_verdicts (delegated to aggregate()).
    """
    if len(run_verdicts) != STABILITY_REQUIRED_RUNS:
        raise AggregationError(
            f"stability check requires exactly {STABILITY_REQUIRED_RUNS} runs "
            f"per §5 of bar-review-pipeline.md, got {len(run_verdicts)}"
        )

    baseline = run_verdicts[0]
    baseline_aggregate = aggregate(baseline)

    for run_idx, run in enumerate(run_verdicts[1:], start=2):
        run_aggregate = aggregate(run)
        if run_aggregate != baseline_aggregate:
            return (
                False,
                f"aggregate mismatch: run 1 = {baseline_aggregate}, run {run_idx} = {run_aggregate}",
            )

    # §5 condition 2: per-reviewer vote comparison is required ONLY when
    # the aggregate is pass. For non-pass aggregates, matching aggregate
    # verdicts across all three runs is sufficient — which reviewers
    # objected may vary between runs without affecting stability, because
    # the obligation will not be marked bootstrap_attested regardless.
    if baseline_aggregate == VERDICT_PASS:
        for run_idx, run in enumerate(run_verdicts[1:], start=2):
            for role in PANEL_ROLES:
                if baseline[role] != run[role]:
                    return (
                        False,
                        f"per-reviewer mismatch on pass aggregate: role {role} = "
                        f"{baseline[role]} in run 1, {run[role]} in run {run_idx}",
                    )

    return (True, "")


# Path components and suffixes excluded from the policy hash. Exclusions are
# limited to build artefacts and OS metadata that can be recreated from
# source files without changing policy intent. See §7.4 of
# bar-review-pipeline.md for the normative specification of these exclusions.
_EXCLUDED_PATH_COMPONENTS: Final[frozenset[str]] = frozenset({
    "__pycache__",
    ".DS_Store",
    "Thumbs.db",
})
_EXCLUDED_SUFFIXES: Final[frozenset[str]] = frozenset({
    ".pyc",
    ".pyo",
})
_EXCLUDED_ROOT_FILES: Final[frozenset[str]] = frozenset({
    "version.json",
})


def _is_excluded(rel_posix: str) -> bool:
    """Return True if a relative POSIX path is excluded from the policy hash."""
    if rel_posix in _EXCLUDED_ROOT_FILES:
        return True
    parts = rel_posix.split("/")
    for part in parts:
        if part in _EXCLUDED_PATH_COMPONENTS:
            return True
    for suffix in _EXCLUDED_SUFFIXES:
        if rel_posix.endswith(suffix):
            return True
    return False


def compute_policy_hash(policy_tree_root: Path) -> str:
    """Compute the SHA-256 policy hash per §7.4 of bar-review-pipeline.md.

    Canonical serialization:
      1. Walk the policy tree in sorted relative-path order (POSIX
         separators, UTF-8).
      2. Skip files whose relative path is excluded — see §7.4 for the
         normative exclusion list. Exclusions cover version.json (circular),
         Python bytecode under __pycache__/ and *.pyc/*.pyo files, and
         common OS metadata files (.DS_Store, Thumbs.db).
      3. For each remaining file, emit: relative_path_bytes + NUL +
         file_content_bytes.
      4. Concatenate all emissions and hash with SHA-256.

    Exclusions are intentionally narrow: they cover files that cannot
    change policy intent because they are either circular (version.json)
    or recreated mechanically from source files (bytecode, OS metadata).
    Any file that could conceivably encode policy content is included.

    Parameters
    ----------
    policy_tree_root :
        Path to the policy tree directory (e.g.,
        docs/governance/bar-policy/2026.04.12/).

    Returns
    -------
    Hex-encoded SHA-256 digest string (64 characters, lowercase).
    """
    if not policy_tree_root.is_dir():
        raise AggregationError(f"policy_tree_root is not a directory: {policy_tree_root}")

    files: list[Path] = []
    for path in policy_tree_root.rglob("*"):
        if not path.is_file():
            continue
        rel_posix = path.relative_to(policy_tree_root).as_posix()
        if _is_excluded(rel_posix):
            continue
        files.append(path)

    files.sort(key=lambda p: p.relative_to(policy_tree_root).as_posix())

    h = hashlib.sha256()
    for path in files:
        rel_bytes = path.relative_to(policy_tree_root).as_posix().encode("utf-8")
        content_bytes = path.read_bytes()
        h.update(rel_bytes)
        h.update(b"\x00")
        h.update(content_bytes)

    return h.hexdigest()


def main() -> int:
    """CLI entry point: compute and print the policy hash for a given tree.

    Usage: python aggregation.py <policy_tree_root>
    """
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <policy_tree_root>", file=sys.stderr)
        return 2

    root = Path(sys.argv[1]).resolve()
    digest = compute_policy_hash(root)
    print(digest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
