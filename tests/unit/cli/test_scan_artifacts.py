"""End-to-end CLI tests: default scan artifact anchoring to the weft-project root.

Covers the behaviour introduced by Tasks 1-3 of the weft-seam-conformance program:
``wardline scan <subdir>`` must write its artifact at ``<project-root>/.wardline/``,
not under the scanned subdirectory.

Harness pattern: ``CliRunner().invoke(cli, ["scan", str(path)])`` — same as
``tests/unit/cli/test_cli.py``; no custom fixtures needed.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from click.testing import CliRunner

from wardline.cli.main import cli
from wardline.cli.scan import _scan_manifest_record
from wardline.core.config import load as load_config
from wardline.core.paths import weft_config_path
from wardline.core.ruleset import ruleset_hash
from wardline.core.run import ScanResult, ScanSummary
from wardline.mcp.server import _scan as mcp_scan

_STAMPED_JSONL_RE = re.compile(r"^\d{8}T\d{6}Z(-\d{3})?-findings\.jsonl$")

# A trusted boundary returning an external-tainted value: PY-WL-101 ERROR defect on
# ``leaky``. Mirrors ``_LEAKY`` in tests/unit/cli/test_scan_affected_cli.py — a real
# per-file POLICY finding (not an engine fact), so its ``location.path`` is a genuine
# file in ``scanned_paths`` and must therefore appear in the manifest's covered_paths.
_LEAKY = (
    "from wardline.decorators import external_boundary, trusted\n"
    "@external_boundary\ndef read_raw(p):\n    return p\n"
    "@trusted\ndef leaky(p):\n    return read_raw(p)\n"
)


def _read_lines(artifact: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in artifact.read_text(encoding="utf-8").splitlines() if line.strip()]


def _manifest_line(artifact: Path) -> dict[str, object]:
    manifests = [rec for rec in _read_lines(artifact) if rec.get("kind") == "scan_manifest"]
    assert len(manifests) == 1, f"expected exactly one scan_manifest line, got {len(manifests)}"
    return manifests[0]


def _scan_artifacts_jsonl(project: Path) -> list[Path]:
    return sorted((project / ".wardline").glob("*-findings.jsonl"))


def _only_scan_artifact(project: Path) -> Path:
    paths = _scan_artifacts_jsonl(project)
    assert len(paths) == 1, f"expected exactly 1 artifact, got {paths}"
    return paths[0]


# ---------------------------------------------------------------------------
# Test 1: subdir scan writes artifact at <project-root>/.wardline/, NOT under sub
# ---------------------------------------------------------------------------


def test_cli_subdir_scan_writes_artifact_at_project_root(tmp_path: Path) -> None:
    """``wardline scan src/pkg`` (weft project at tmp_path) → artifact at
    ``tmp_path/.wardline/``, NOT at ``tmp_path/src/pkg/.wardline/``."""
    (tmp_path / "weft.toml").write_text('[wardline]\nsource_roots = ["."]\n', encoding="utf-8")
    sub = tmp_path / "src" / "pkg"
    sub.mkdir(parents=True)
    (sub / "m.py").write_text("x = 1\n", encoding="utf-8")

    result = CliRunner().invoke(cli, ["scan", str(sub)])

    assert result.exit_code == 0, result.output
    # Positive: artifact appeared at project root
    artifacts_dir = tmp_path / ".wardline"
    assert artifacts_dir.exists(), "expected .wardline/ at project root"
    jsonl_files = list(artifacts_dir.glob("*-findings.jsonl"))
    assert any(_STAMPED_JSONL_RE.match(p.name) for p in jsonl_files), (
        f"no timestamped findings artifact in {artifacts_dir!s}: {[p.name for p in jsonl_files]}"
    )
    # Negative: NO artifact written under the scanned subdirectory
    assert not (sub / ".wardline").exists(), "artifact was written under the subdir — anchoring is broken"


# ---------------------------------------------------------------------------
# Test 2: true-root scan writes artifact at <root>/.wardline/
# ---------------------------------------------------------------------------


def test_cli_true_root_scan_writes_artifact_at_root(tmp_path: Path) -> None:
    """``wardline scan <root>`` where root carries ``weft.toml`` → artifact at
    ``<root>/.wardline/``."""
    (tmp_path / "weft.toml").write_text('[wardline]\nsource_roots = ["."]\n', encoding="utf-8")
    (tmp_path / "app.py").write_text("def ok():\n    return 1\n", encoding="utf-8")

    result = CliRunner().invoke(cli, ["scan", str(tmp_path)])

    assert result.exit_code == 0, result.output
    artifact = _only_scan_artifact(tmp_path)
    assert artifact.parent == tmp_path / ".wardline"
    assert _STAMPED_JSONL_RE.match(artifact.name)
    assert str(artifact) in result.output


# ---------------------------------------------------------------------------
# Test 3: unfederated tree (no weft.toml up the chain) → fallback to <scan-path>/.wardline/
# ---------------------------------------------------------------------------


def test_cli_unfederated_tree_falls_back_to_scan_path(tmp_path: Path) -> None:
    """No ``weft.toml`` anywhere in the ancestry → ``project_root_for`` returns
    ``scan_path`` itself, so the artifact lands at ``<scan_path>/.wardline/``."""
    # tmp_path is deeply nested under /tmp — well outside any weft project root.
    # Do NOT create a weft.toml.
    (tmp_path / "app.py").write_text("def ok():\n    return 1\n", encoding="utf-8")

    result = CliRunner().invoke(cli, ["scan", str(tmp_path)])

    assert result.exit_code == 0, result.output
    artifact = _only_scan_artifact(tmp_path)
    assert artifact.parent == tmp_path / ".wardline"
    assert _STAMPED_JSONL_RE.match(artifact.name)


# ---------------------------------------------------------------------------
# Test 4: custom artifacts.dir anchors to <project-root>/out/wl
# ---------------------------------------------------------------------------


def test_cli_custom_artifacts_dir_anchors_to_project_root(tmp_path: Path) -> None:
    """``[wardline.artifacts] dir = "out/wl"`` in weft.toml (root scan) → artifact at
    ``<project-root>/out/wl/``, NOT at ``<project-root>/.wardline/``.

    Subdir scans don't load the project root's config (by design — the docstring and
    task 3 message both say subdir scans don't load project policy). Root scans do.
    """
    (tmp_path / "weft.toml").write_text(
        '[wardline]\nsource_roots = ["."]\n\n[wardline.artifacts]\ndir = "out/wl"\n',
        encoding="utf-8",
    )
    (tmp_path / "app.py").write_text("def ok():\n    return 1\n", encoding="utf-8")

    result = CliRunner().invoke(cli, ["scan", str(tmp_path)])

    assert result.exit_code == 0, result.output
    artifact_dir = tmp_path / "out" / "wl"
    assert artifact_dir.exists(), f"expected artifact dir at {artifact_dir}"
    jsonl_files = sorted(artifact_dir.glob("*-findings.jsonl"))
    assert jsonl_files, f"no artifacts in {artifact_dir}"
    assert _STAMPED_JSONL_RE.match(jsonl_files[0].name)
    # No default .wardline at project root (custom dir takes over)
    assert not (tmp_path / ".wardline").exists()


# ---------------------------------------------------------------------------
# Test 5: explicit --output is unaffected (verbatim) and no .wardline/ is created
# ---------------------------------------------------------------------------


def test_cli_explicit_output_unaffected(tmp_path: Path) -> None:
    """``--output path/to/findings.jsonl`` writes exactly there and NEVER creates a
    ``.wardline/`` directory under the project root."""
    (tmp_path / "weft.toml").write_text("[wardline]\n", encoding="utf-8")
    (tmp_path / "app.py").write_text("def ok():\n    return 1\n", encoding="utf-8")
    out_dir = tmp_path / "ci"
    out_dir.mkdir()
    out = out_dir / "findings.jsonl"

    result = CliRunner().invoke(cli, ["scan", str(tmp_path), "--output", str(out)])

    assert result.exit_code == 0, result.output
    assert out.exists(), f"expected output at {out}"
    # No automatic .wardline/ when --output is explicit
    assert not (tmp_path / ".wardline").exists(), ".wardline/ was created even though --output was explicit"


# ---------------------------------------------------------------------------
# Test 6: MCP _scan() writes NO disk artifact (regression guard)
# ---------------------------------------------------------------------------


def test_mcp_scan_writes_no_disk_artifact(tmp_path: Path) -> None:
    """The MCP ``scan`` tool must NEVER write a ``.wardline/`` disk artifact.

    The MCP surface returns findings in-band over JSON-RPC; disk writes are the
    CLI's job.  This is a regression guard: any change that wires write_scan_artifact
    into the MCP path would be caught here."""
    (tmp_path / "app.py").write_text("def ok():\n    return 1\n", encoding="utf-8")

    result = mcp_scan(args={}, root=tmp_path)

    # Sanity check: scan actually ran and returned a result dict
    assert isinstance(result, dict), f"expected dict result, got {type(result)}"
    # No .wardline/ may exist after an MCP scan
    assert not (tmp_path / ".wardline").exists(), (
        "MCP _scan() created a .wardline/ directory — disk writes must be CLI-only"
    )


# ---------------------------------------------------------------------------
# Test 7: the default findings JSONL carries a scan_manifest header record with the
#         exact shape plainweave's wardline_adapter keys on.
# ---------------------------------------------------------------------------


def test_default_jsonl_emits_scan_manifest_with_exact_shape(tmp_path: Path) -> None:
    """The default ``.wardline/*-findings.jsonl`` artifact carries a single
    ``scan_manifest`` line of shape
    ``{"kind":"scan_manifest","scope":{"covered_paths":[...]},"ruleset_id":"sha256:..."}``
    — covered_paths NESTED under scope, ruleset_id TOP-LEVEL — and ruleset_id equals
    ``ruleset_hash(loaded_config)``."""
    (tmp_path / "weft.toml").write_text('[wardline]\nsource_roots = ["."]\n', encoding="utf-8")
    (tmp_path / "leaky.py").write_text(_LEAKY, encoding="utf-8")

    result = CliRunner().invoke(cli, ["scan", str(tmp_path)])
    assert result.exit_code in (0, 1), result.output  # 1 = gate tripped on the PY-WL defect

    artifact = _only_scan_artifact(tmp_path)
    manifest = _manifest_line(artifact)

    # Exact contract shape.
    assert set(manifest) == {"kind", "scope", "ruleset_id"}, manifest
    assert manifest["kind"] == "scan_manifest"
    scope = manifest["scope"]
    assert isinstance(scope, dict) and set(scope) == {"covered_paths"}, scope
    covered = scope["covered_paths"]
    assert isinstance(covered, list) and all(isinstance(p, str) for p in covered)

    # ruleset_id is TOP-LEVEL and equals ruleset_hash(config) (== legis rule_set_version).
    rid = manifest["ruleset_id"]
    assert isinstance(rid, str) and rid.startswith("sha256:")
    assert rid == ruleset_hash(load_config(weft_config_path(tmp_path)))


def test_manifest_covered_paths_match_finding_location_format(tmp_path: Path) -> None:
    """The one subtle correctness point: covered_paths use the SAME format/relativity as
    a finding's ``location.path``. A real per-file POLICY finding's location.path MUST be
    a member of covered_paths (membership, not equality — engine facts use other path
    forms), and covered_paths are relative POSIX (no leading slash, no backslash)."""
    (tmp_path / "weft.toml").write_text('[wardline]\nsource_roots = ["."]\n', encoding="utf-8")
    (tmp_path / "leaky.py").write_text(_LEAKY, encoding="utf-8")

    result = CliRunner().invoke(cli, ["scan", str(tmp_path)])
    assert result.exit_code in (0, 1), result.output

    artifact = _only_scan_artifact(tmp_path)
    records = _read_lines(artifact)
    manifest = _manifest_line(artifact)
    covered = set(manifest["scope"]["covered_paths"])  # type: ignore[index]

    # covered_paths are repo-relative POSIX paths.
    assert all(not p.startswith("/") and "\\" not in p for p in covered), covered
    assert "leaky.py" in covered, f"the scanned file is not in covered_paths: {covered}"

    # The real policy finding (PY-WL-* on a concrete file) must have its location.path
    # in covered_paths — this is exactly what the consumer's RESOLVED logic depends on.
    policy = [
        rec
        for rec in records
        if rec.get("kind") != "scan_manifest"
        and str(rec.get("rule_id", "")).startswith("PY-WL-")
        and isinstance(rec.get("location"), dict)
    ]
    assert policy, "fixture produced no PY-WL policy finding"
    for rec in policy:
        path = rec["location"]["path"]  # type: ignore[index]
        assert path in covered, f"finding location.path {path!r} absent from covered_paths {covered}"


def test_clean_scan_still_emits_manifest(tmp_path: Path) -> None:
    """Regression guard for the empty-artifact bug: a CLEAN scan (zero findings) MUST
    still emit the manifest line — that is precisely when RESOLVED detection matters
    (prior findings now absent, their path still in covered_paths). The artifact must
    never be empty, so the consumer's scan-identity-absent degrade only fires for
    pre-manifest snapshots, not for fresh clean scans."""
    (tmp_path / "weft.toml").write_text('[wardline]\nsource_roots = ["."]\n', encoding="utf-8")
    (tmp_path / "clean.py").write_text("def ok():\n    return 1\n", encoding="utf-8")

    result = CliRunner().invoke(cli, ["scan", str(tmp_path)])
    assert result.exit_code == 0, result.output

    artifact = _only_scan_artifact(tmp_path)
    records = _read_lines(artifact)
    # No policy defects on this clean tree (engine facts may still appear, but the
    # manifest must be present regardless).
    manifest = _manifest_line(artifact)
    assert manifest["scope"]["covered_paths"], "covered_paths empty on a non-empty scan"  # type: ignore[index]
    assert "clean.py" in set(manifest["scope"]["covered_paths"])  # type: ignore[index]
    assert manifest == records[0], "manifest should be the header (first) record"


def test_scan_manifest_covered_paths_narrows_to_analyzed_set() -> None:
    """covered_paths DEFAULTS to the analyzed set, so a discovered-but-not-re-analyzed file
    in --affected delta mode is not over-claimed as coverage (a prior finding there stays
    indeterminate, not falsely resolved); --manifest-full-coverage restores the full
    discovered inventory. This fixture forces analyzed != discovered (a full scan has
    analyzed == discovered, so the two coincide there and the default is unchanged)."""
    result = ScanResult(
        findings=[],
        summary=ScanSummary(total=0, active=0, baselined=0, waived=0, judged=0),
        files_scanned=2,
        context=None,
        scanned_paths=("a.py", "b.py"),  # discovered
        analyzed_paths=("a.py",),  # only a.py re-analyzed (delta)
    )
    default = _scan_manifest_record(result, "sha256:deadbeef", full_coverage=False)
    assert default == {
        "kind": "scan_manifest",
        "scope": {"covered_paths": ["a.py"]},  # narrowed to the analyzed set
        "ruleset_id": "sha256:deadbeef",
    }
    full = _scan_manifest_record(result, "sha256:deadbeef", full_coverage=True)
    assert full["scope"] == {"covered_paths": ["a.py", "b.py"]}  # full discovered inventory


def test_manifest_full_coverage_flag_is_wired(tmp_path: Path) -> None:
    """The --manifest-full-coverage flag threads click -> scan() param -> _scan_manifest_record
    and produces a valid manifest. On a full scan analyzed == discovered, so covered_paths is
    unchanged — this guards the wiring, not the (delta-only) narrowing the unit test covers."""
    (tmp_path / "weft.toml").write_text('[wardline]\nsource_roots = ["."]\n', encoding="utf-8")
    (tmp_path / "leaky.py").write_text("eval(input())\n", encoding="utf-8")

    result = CliRunner().invoke(cli, ["scan", str(tmp_path), "--manifest-full-coverage"])
    assert result.exit_code == 0, result.output

    manifest = _manifest_line(_only_scan_artifact(tmp_path))
    assert "leaky.py" in set(manifest["scope"]["covered_paths"])  # type: ignore[index]
