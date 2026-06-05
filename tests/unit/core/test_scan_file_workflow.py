"""One-shot scan -> emit -> file workflow."""

from __future__ import annotations

from wardline.core.filigree_emit import EmitResult
from wardline.core.filigree_issue import FileResult
from wardline.core.scan_file_workflow import scan_file_findings

_LEAKY = (
    "from wardline.decorators import external_boundary, trusted\n"
    "@external_boundary\n"
    "def read_raw(p):\n"
    "    return p\n"
    "@trusted\n"
    "def leaky(p):\n"
    "    return read_raw(p)\n"
)


class FakeEmitter:
    def __init__(self, result: EmitResult):
        self.result = result
        self.calls: list[dict] = []

    def emit(self, findings, *, scanned_paths=()):
        self.calls.append({"count": len(findings), "scanned_paths": tuple(scanned_paths)})
        return self.result


class FakeFiler:
    def __init__(self, result: FileResult):
        self.result = result
        self.calls: list[dict] = []

    def file(self, fingerprint, *, scan_source="wardline", priority=None, labels=None):
        self.calls.append({"fingerprint": fingerprint, "priority": priority, "labels": labels})
        return self.result


class DownLoomweave:
    def capabilities(self):
        return None

    def resolve(self, qualnames):
        return None


def _project(tmp_path):
    (tmp_path / "svc.py").write_text(_LEAKY, encoding="utf-8")
    return tmp_path


def test_scan_file_findings_dry_run_lists_active_defects_without_promoting(tmp_path):
    root = _project(tmp_path)
    filer = FakeFiler(FileResult(reachable=True, issue_id="wardline-1", created=True))

    out = scan_file_findings(root, filigree_filer=filer)

    assert out["mode"] == "dry_run"
    assert out["summary"]["active"] == 1
    assert out["selected_count"] == 0
    assert out["active_defects"][0]["rule_id"] == "PY-WL-101"
    assert out["active_defects"][0]["explanation"]["source_boundary_qualname"] == "svc.read_raw"
    assert out["active_defects"][0]["promotion"]["attempted"] is False
    assert filer.calls == []


def test_scan_file_findings_selected_fingerprint_emits_and_promotes(tmp_path):
    root = _project(tmp_path)
    dry = scan_file_findings(root)
    fp = dry["active_defects"][0]["fingerprint"]
    emitter = FakeEmitter(EmitResult(reachable=True, created=1, updated=0))
    filer = FakeFiler(FileResult(reachable=True, issue_id="wardline-1", created=True))

    out = scan_file_findings(
        root,
        fingerprints=(fp,),
        filigree_emitter=emitter,
        filigree_filer=filer,
        dry_run=False,
        priority="P2",
        labels=("agent-workflow",),
    )

    finding = out["active_defects"][0]
    assert out["mode"] == "fingerprints"
    assert out["selected_count"] == 1
    assert out["filigree_emit"]["reachable"] is True
    assert finding["promotion"]["issue_id"] == "wardline-1"
    assert finding["promotion"]["created"] is True
    assert finding["identity_attach"]["attempted"] is False
    assert filer.calls == [{"fingerprint": fp, "priority": "P2", "labels": ["agent-workflow"]}]
    assert emitter.calls and emitter.calls[0]["count"] >= 1


def test_scan_file_findings_surfaces_partial_failures(tmp_path):
    root = _project(tmp_path)
    dry = scan_file_findings(root)
    fp = dry["active_defects"][0]["fingerprint"]
    emitter = FakeEmitter(EmitResult(reachable=False))
    filer = FakeFiler(FileResult(reachable=False, disabled_reason="filigree unreachable"))

    out = scan_file_findings(
        root,
        fingerprints=(fp, "0" * 64),
        filigree_emitter=emitter,
        filigree_filer=filer,
        loomweave_client=DownLoomweave(),
        dry_run=False,
    )

    finding = out["active_defects"][0]
    assert out["unknown_fingerprints"] == ["0" * 64]
    assert out["filigree_emit"]["reachable"] is False
    assert finding["promotion"]["reachable"] is False
    assert finding["promotion"]["disabled_reason"] == "filigree unreachable"
    assert finding["identity_attach"]["attempted"] is False
    assert "no issue_id" in finding["identity_attach"]["reason"]
