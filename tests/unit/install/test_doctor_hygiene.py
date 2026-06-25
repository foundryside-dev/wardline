import os
from pathlib import Path

from wardline.install.doctor import DoctorCheck, _check_gitignore, _sweep_stray_artifacts


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
