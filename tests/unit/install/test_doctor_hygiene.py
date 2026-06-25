import os
from pathlib import Path

from wardline.install.doctor import DoctorCheck, _check_gitignore, _sweep_stray_artifacts, machine_readable_doctor
from wardline.mcp.server import _DOCTOR_TOOL


def test_doctorcheck_to_dict_includes_payload_when_present():
    c = DoctorCheck("stray_artifacts", "ok", fixed=True, removed=["a/.wardline/x"], review=["findings.jsonl"])
    d = c.to_dict()
    assert d["removed"] == ["a/.wardline/x"]
    assert d["review"] == ["findings.jsonl"]


def test_doctorcheck_to_dict_omits_empty_payload():
    c = DoctorCheck("gitignore", "ok")
    assert "removed" not in c.to_dict() and "review" not in c.to_dict()


def _proj(tmp_path: Path) -> Path:
    (tmp_path / "weft.toml").write_text("[wardline]\n", encoding="utf-8")
    return tmp_path


def test_gitignore_created_then_idempotent(tmp_path):
    proj = _proj(tmp_path)
    c1 = _check_gitignore(proj, fix=True)
    assert c1.status == "ok" and c1.fixed is True and "added" in (c1.message or "")
    # success => ok (not created/updated)
    body = (proj / ".gitignore").read_text(encoding="utf-8")
    assert ".wardline/" in body and "findings.jsonl" in body
    c2 = _check_gitignore(proj, fix=True)
    assert c2.status == "ok"
    assert (proj / ".gitignore").read_text(encoding="utf-8") == body  # no duplicate append


def test_gitignore_tolerates_existing_bare_entry(tmp_path):
    proj = _proj(tmp_path)
    (proj / ".gitignore").write_text(".wardline\n", encoding="utf-8")  # no slash
    _check_gitignore(proj, fix=True)
    body = (proj / ".gitignore").read_text(encoding="utf-8")
    # bare ".wardline" satisfies ".wardline/" (trailing-slash tolerant) — not re-added
    assert body.count(".wardline") == 1
    assert "findings.jsonl" in body


def test_gitignore_crlf_idempotent(tmp_path):
    proj = _proj(tmp_path)
    (proj / ".gitignore").write_text(".wardline/\r\nfindings.jsonl\r\n", encoding="utf-8")
    c = _check_gitignore(proj, fix=True)
    assert c.status == "ok"  # both already present despite CRLF


def test_gitignore_preserves_existing_content(tmp_path):
    proj = _proj(tmp_path)
    (proj / ".gitignore").write_text("# mine\n*.log\n", encoding="utf-8")
    _check_gitignore(proj, fix=True)
    body = (proj / ".gitignore").read_text(encoding="utf-8")
    assert "*.log" in body and "# mine" in body


def test_gitignore_check_only_no_write(tmp_path):
    proj = _proj(tmp_path)
    c = _check_gitignore(proj, fix=False)
    assert c.status == "ok"                       # advisory — does NOT fail aggregation
    assert "missing" in (c.message or "")         # but the gap is reported
    assert not (proj / ".gitignore").exists()


def test_gitignore_commented_entry_does_not_satisfy(tmp_path):
    proj = _proj(tmp_path)
    (proj / ".gitignore").write_text("#.wardline/\n!findings.jsonl\n", encoding="utf-8")
    c = _check_gitignore(proj, fix=False)
    assert "missing" in (c.message or "")         # commented/negated lines don't count as present


def test_gitignore_symlink_reports_error_not_abort(tmp_path):
    import os
    proj = _proj(tmp_path)
    target = tmp_path.parent / "evil"
    target.write_text("", encoding="utf-8")
    os.symlink(target, proj / ".gitignore")       # untrusted-repo surface
    c = _check_gitignore(proj, fix=True)
    assert c.status == "error" and "symlink" in (c.message or "")
    assert target.read_text(encoding="utf-8") == ""  # never written through the link


# ---------------------------------------------------------------------------
# _sweep_stray_artifacts
# ---------------------------------------------------------------------------

STAMP = "20260624T111539Z"


def _stray(proj: Path, rel: str) -> Path:
    p = proj / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("{}\n", encoding="utf-8")
    return p


def test_sweep_removes_nested_wardline_managed_file(tmp_path):
    proj = _proj(tmp_path)
    stray = _stray(proj, f"src/pkg/.wardline/{STAMP}-findings.jsonl")
    c = _sweep_stray_artifacts(proj, fix=True)
    assert not stray.exists()
    assert not stray.parent.exists()              # emptied .wardline removed
    assert any(str(stray) in r or "src/pkg/.wardline" in r for r in c.removed)


def test_sweep_keeps_standard_dir(tmp_path):
    proj = _proj(tmp_path)
    keep = _stray(proj, f".wardline/{STAMP}-findings.jsonl")
    _sweep_stray_artifacts(proj, fix=True)
    assert keep.exists()                           # standard dir is skipped


def test_sweep_reports_unstamped_and_bare_managed(tmp_path):
    proj = _proj(tmp_path)
    bare = _stray(proj, "findings.jsonl")
    bare_managed = _stray(proj, f"logs/{STAMP}-findings.jsonl")   # managed name, NOT in a .wardline/ dir
    c = _sweep_stray_artifacts(proj, fix=True)
    assert bare.exists() and bare_managed.exists()
    assert any("findings.jsonl" in r for r in c.review)
    assert any(f"{STAMP}-findings.jsonl" in r for r in c.review)


def test_sweep_check_only_no_delete(tmp_path):
    proj = _proj(tmp_path)
    stray = _stray(proj, f"src/.wardline/{STAMP}-findings.jsonl")
    c = _sweep_stray_artifacts(proj, fix=False)
    assert stray.exists()
    assert not c.fixed


def test_sweep_does_not_descend_symlinked_dir(tmp_path):
    proj = _proj(tmp_path)
    outside = tmp_path.parent / "outside_wl"
    (outside / ".wardline").mkdir(parents=True)
    target = outside / ".wardline" / f"{STAMP}-findings.jsonl"
    target.write_text("{}\n", encoding="utf-8")
    os.symlink(outside, proj / "linked")
    _sweep_stray_artifacts(proj, fix=True)
    assert target.exists()                         # never followed out of root


def test_sweep_does_not_unlink_symlinked_managed_file(tmp_path):
    proj = _proj(tmp_path)
    real = tmp_path.parent / "real.jsonl"
    real.write_text("{}\n", encoding="utf-8")
    wd = proj / "src" / ".wardline"
    wd.mkdir(parents=True)
    os.symlink(real, wd / f"{STAMP}-findings.jsonl")
    _sweep_stray_artifacts(proj, fix=True)
    assert real.exists()                           # symlink skipped, target intact


def test_sweep_stops_at_nested_project_root(tmp_path):
    proj = _proj(tmp_path)
    nested = proj / "vendor" / "subproj"
    nested.mkdir(parents=True)
    (nested / "weft.toml").write_text("[wardline]\n", encoding="utf-8")
    keep = _stray(proj, f"vendor/subproj/.wardline/{STAMP}-findings.jsonl")
    _sweep_stray_artifacts(proj, fix=True)
    assert keep.exists()                           # nested project's artifacts untouched


# ---------------------------------------------------------------------------
# machine_readable_doctor wiring (Task 9)
# ---------------------------------------------------------------------------

def _isolated_repair(monkeypatch, proj):
    """Apply the same home/command/which isolation the CLI doctor tests use."""
    home = proj / "_fake_home"
    monkeypatch.setattr("wardline.install.mcp_json.Path.home", lambda: home)
    monkeypatch.setattr("wardline.install.mcp_json._find_wardline_command", lambda: "/bin/wardline")
    monkeypatch.setattr("wardline.install.detect.shutil.which", lambda _: None)
    monkeypatch.delenv("WARDLINE_LOOMWEAVE_URL", raising=False)
    monkeypatch.delenv("WARDLINE_FILIGREE_URL", raising=False)
    monkeypatch.delenv("WARDLINE_LOOMWEAVE_TOKEN", raising=False)


def test_machine_readable_includes_new_checks(tmp_path, monkeypatch):
    proj = _proj(tmp_path)
    _isolated_repair(monkeypatch, proj)
    _stray(proj, f"src/.wardline/{STAMP}-findings.jsonl")
    payload = machine_readable_doctor(proj, fix=True)
    ids = {c["id"] for c in payload["checks"]}
    assert {"gitignore", "stray_artifacts"} <= ids


def test_successful_repair_new_checks_report_ok(tmp_path, monkeypatch):
    # Must-fix (plan review): a SUCCESSFUL repair must return status "ok" so it does not
    # flip machine_readable_doctor's all(check.ok) aggregation and make `doctor --fix` /
    # MCP doctor exit 1 on success. (Asserting payload["ok"] is True would be wrong here —
    # other checks fail on a bare project — so pin the two new checks specifically.)
    proj = _proj(tmp_path)
    _isolated_repair(monkeypatch, proj)
    _stray(proj, f"src/.wardline/{STAMP}-findings.jsonl")
    by_id = {c["id"]: c for c in machine_readable_doctor(proj, fix=True)["checks"]}
    assert by_id["gitignore"]["status"] == "ok" and by_id["gitignore"]["fixed"] is True
    assert by_id["stray_artifacts"]["status"] == "ok"


def test_check_only_does_not_mutate(tmp_path, monkeypatch):
    proj = _proj(tmp_path)
    _isolated_repair(monkeypatch, proj)
    stray = _stray(proj, f"src/.wardline/{STAMP}-findings.jsonl")
    payload = machine_readable_doctor(proj, fix=False)
    assert stray.exists()                           # no delete
    assert not (proj / ".gitignore").exists()       # no write
    sweep = next(c for c in payload["checks"] if c["id"] == "stray_artifacts")
    assert sweep["fixed"] is False


def test_subdir_root_climbs_to_project(tmp_path, monkeypatch):
    proj = _proj(tmp_path)
    _isolated_repair(monkeypatch, proj)
    sub = proj / "src" / "pkg"
    sub.mkdir(parents=True)
    stray = _stray(proj, f"src/.wardline/{STAMP}-findings.jsonl")
    machine_readable_doctor(sub, fix=True)          # invoked at the SUBDIR
    assert (proj / ".gitignore").exists()           # gitignore written at the PROJECT root
    assert not stray.exists()                       # swept at the project root


# ---------------------------------------------------------------------------
# MCP tool advertisement + confinement (Task 10)
# ---------------------------------------------------------------------------

def test_doctor_tool_advertises_destructive():
    """_DOCTOR_TOOL must advertise destructiveHint: True now that repair:true deletes
    stray managed scan artifacts."""
    assert _DOCTOR_TOOL["annotations"]["destructiveHint"] is True


def test_custom_dir_project_protects_default_wardline_dir(tmp_path):
    """A project with a custom artifacts dir must not sweep the default .wardline/ dir.

    Root cause: a subdir scan loads config from the scan path; if no weft.toml is
    present there, it defaults to .wardline/ for output. When the project root's
    weft.toml sets a custom dir, doctor must treat BOTH the custom dir AND the default
    .wardline/ as standard (protected), not sweep the default dir's contents.
    """
    proj = _proj(tmp_path)
    # Overwrite with a custom artifacts dir so doctor loads "out/wl" from the project root.
    (proj / "weft.toml").write_text("[wardline.artifacts]\ndir = \"out/wl\"\n", encoding="utf-8")

    # A subdir-scan artifact in the default .wardline/ location — must NOT be deleted.
    default_artifact = _stray(proj, f".wardline/{STAMP}-findings.jsonl")

    # A genuine nested stray in src/.wardline/ — must be deleted.
    nested_stray = _stray(proj, f"src/.wardline/{STAMP}-findings.jsonl")

    _sweep_stray_artifacts(proj, fix=True)
    _check_gitignore(proj, fix=True)

    # Default .wardline artifact survives (it's tool-owned output, not a stray).
    assert default_artifact.exists(), ".wardline/ artifact must survive (standard dir)"

    # Nested stray is removed (genuine stray — not a standard dir).
    assert not nested_stray.exists(), "src/.wardline/ stray must be deleted"

    # .gitignore must cover BOTH the custom dir AND the default .wardline/.
    gitignore_body = (proj / ".gitignore").read_text(encoding="utf-8")
    assert "out/wl/" in gitignore_body, "custom dir must be gitignored"
    assert ".wardline/" in gitignore_body, "default .wardline/ must also be gitignored"
    assert "findings.jsonl" in gitignore_body


def test_mcp_path_deletes_confined_managed_only(tmp_path, monkeypatch):
    """Drive the sweep through machine_readable_doctor(fix=True) exactly as the MCP
    _doctor handler does, and verify:
      (a) a managed timestamped file inside <proj>/src/.wardline/ is deleted,
      (b) an unstamped bare findings.jsonl is kept (REVIEW, not deleted),
      (c) a symlinked managed file inside .wardline/ is NOT unlinked; its target intact.
    Uses the same HOME/which/command isolation as the existing doctor tests."""
    proj = _proj(tmp_path)
    _isolated_repair(monkeypatch, proj)

    # (a) managed stray inside a .wardline/ dir -> must be deleted
    inside = _stray(proj, f"src/.wardline/{STAMP}-findings.jsonl")

    # (b) unstamped bare findings.jsonl at project root -> kept (REVIEW)
    bare = _stray(proj, "findings.jsonl")

    # (c) symlinked managed file inside a .wardline/ dir -> NOT unlinked; target intact
    real = tmp_path.parent / "real_task10.jsonl"
    real.write_text("x", encoding="utf-8")
    wd = proj / "lib" / ".wardline"
    wd.mkdir(parents=True)
    os.symlink(real, wd / f"{STAMP}-findings.jsonl")

    machine_readable_doctor(proj, fix=True)

    assert not inside.exists(), "managed stray inside .wardline/ must be deleted"
    assert bare.exists(), "unstamped findings.jsonl must NOT be deleted (REVIEW only)"
    assert real.exists(), "symlink target must not be unlinked"
