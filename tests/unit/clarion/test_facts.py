from pathlib import Path

from wardline.clarion.facts import SCHEMA_VERSION, build_taint_facts
from wardline.core.run import run_scan

_LEAKY = (
    "from wardline.decorators import external_boundary, trusted\n"
    "@external_boundary\ndef read_raw(p):\n    return p\n"
    "@trusted\ndef leaky(p):\n    return read_raw(p)\n"
)


def _scan_leaky(tmp_path: Path):
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "svc.py").write_text(_LEAKY, encoding="utf-8")
    return proj, run_scan(proj)


def test_builds_one_fact_per_function_entity(tmp_path):
    proj, result = _scan_leaky(tmp_path)
    facts = build_taint_facts(result, proj)
    quals = {f["qualname"] for f in facts}
    assert "svc.read_raw" in quals
    assert "svc.leaky" in quals


def test_leaky_fact_carries_the_taint_projection(tmp_path):
    proj, result = _scan_leaky(tmp_path)
    facts = {f["qualname"]: f for f in build_taint_facts(result, proj)}
    leaky = facts["svc.leaky"]
    blob = leaky["wardline_json"]
    assert blob["schema_version"] == SCHEMA_VERSION
    assert blob["qualname"] == "svc.leaky"
    assert blob["taint"]["actual_return"] == "EXTERNAL_RAW"
    assert blob["taint"]["contributing_callee_qualname"] == "svc.read_raw"
    leaky_finding = next(f for f in blob["findings"] if f["rule_id"] == "PY-WL-101")
    assert leaky_finding["path"] == "svc.py"
    read_raw = facts["svc.read_raw"]["wardline_json"]
    assert read_raw["taint"]["contributing_callee_qualname"] is None


def test_content_hash_is_blake3_whole_file_and_top_level_and_in_blob(tmp_path):
    proj, result = _scan_leaky(tmp_path)
    import blake3

    expected = blake3.blake3((proj / "svc.py").read_bytes()).hexdigest()
    fact = next(f for f in build_taint_facts(result, proj) if f["qualname"] == "svc.leaky")
    assert fact["content_hash_at_compute"] == expected
    assert fact["wardline_json"]["content_hash_at_compute"] == expected
    assert len(expected) == 64


def test_per_file_hash_is_memoized(tmp_path, monkeypatch):
    proj, result = _scan_leaky(tmp_path)
    import wardline.clarion.facts as facts_mod

    calls = {"n": 0}
    real = facts_mod._read_bytes

    def counting(path):
        calls["n"] += 1
        return real(path)

    monkeypatch.setattr(facts_mod, "_read_bytes", counting)
    build_taint_facts(result, proj)
    assert calls["n"] == 1
