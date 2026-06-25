from wardline.install.doctor import DoctorCheck


def test_doctorcheck_to_dict_includes_payload_when_present():
    c = DoctorCheck("stray_artifacts", "ok", fixed=True, removed=["a/.wardline/x"], review=["findings.jsonl"])
    d = c.to_dict()
    assert d["removed"] == ["a/.wardline/x"]
    assert d["review"] == ["findings.jsonl"]


def test_doctorcheck_to_dict_omits_empty_payload():
    c = DoctorCheck("gitignore", "ok")
    assert "removed" not in c.to_dict() and "review" not in c.to_dict()
