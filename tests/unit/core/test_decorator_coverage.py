from __future__ import annotations

from pathlib import Path

from wardline.core.baseline import write_baseline
from wardline.core.decorator_coverage import build_decorator_coverage
from wardline.core.dossier import TicketRef, WorkSection
from wardline.core.identity import ContentStatus, EntityBinding, IdentityStatus
from wardline.core.run import run_scan

_SRC = (
    "from wardline.decorators import external_boundary, trusted\n"
    "@external_boundary\n"
    "def raw(p):\n"
    "    return p\n"
    "@trusted\n"
    "def clean():\n"
    "    return 1\n"
    "@trusted\n"
    "def leaky(p):\n"
    "    return raw(p)\n"
)


def _project(tmp_path: Path) -> Path:
    (tmp_path / "svc.py").write_text(_SRC, encoding="utf-8")
    return tmp_path


class _Bindings:
    def binding_for(self, qualname: str) -> EntityBinding:
        return EntityBinding(
            locator=f"python:function:{qualname}",
            sei=f"loomweave:eid:{qualname}",
            identity=IdentityStatus.ALIVE,
            content=ContentStatus.FRESH,
            content_hash=f"hash:{qualname}",
        )


class _Work:
    def work(self, binding: EntityBinding) -> WorkSection:
        if binding.locator.endswith("svc.leaky"):
            return WorkSection(
                available=True,
                tickets=[TicketRef(issue_id="wardline-1", status="open", priority="P2", title="fix leak")],
                identity_status=IdentityStatus.ALIVE,
                content_status=ContentStatus.FRESH,
            )
        return WorkSection(
            available=True,
            tickets=[],
            identity_status=IdentityStatus.ALIVE,
            content_status=ContentStatus.FRESH,
        )


def test_decorator_coverage_lists_all_trust_decorated_entities(tmp_path: Path) -> None:
    report = build_decorator_coverage(_project(tmp_path), binding_provider=_Bindings(), work_provider=_Work())
    out = report.to_dict()

    assert out["summary"] == {"total": 3, "clean": 2, "defect": 1, "unknown": 0, "suppressed": 0}
    rows = {row["qualname"]: row for row in out["rows"]}
    assert set(rows) == {"svc.clean", "svc.leaky", "svc.raw"}

    clean = rows["svc.clean"]
    assert clean["path"] == "svc.py"
    assert clean["line"] == 6
    assert clean["decorators"] == ["@trusted"]
    assert clean["declared_tier"] == "INTEGRAL"
    assert clean["actual_tier"] == "INTEGRAL"
    assert clean["verdict"] == "clean"
    assert clean["finding_state"] == "clean"
    assert clean["active_finding_fingerprints"] == []
    assert clean["identity"]["sei"] == "loomweave:eid:svc.clean"
    assert clean["identity"]["content_status"] == "fresh"
    assert clean["work"]["available"] is True
    assert clean["work"]["tickets"] == []

    leaky = rows["svc.leaky"]
    assert leaky["verdict"] == "defect"
    assert leaky["finding_state"] == "defect"
    assert len(leaky["active_finding_fingerprints"]) == 1
    assert leaky["work"]["tickets"][0]["issue_id"] == "wardline-1"


def test_decorator_coverage_reports_unavailable_integrations_explicitly(tmp_path: Path) -> None:
    report = build_decorator_coverage(_project(tmp_path))
    row = report.to_dict()["rows"][0]

    assert row["identity"] == {
        "available": False,
        "locator": f"python:function:{row['qualname']}",
        "sei": None,
        "identity_status": "unavailable",
        "content_status": "unknown",
        "content_hash": None,
        "reason": "loomweave not configured",
    }
    assert row["work"]["available"] is False
    assert row["work"]["reason"] == "filigree not configured"


def test_decorator_coverage_surfaces_suppressed_defects(tmp_path: Path) -> None:
    root = _project(tmp_path)
    leak = next(f for f in run_scan(root).findings if f.rule_id == "PY-WL-101")
    write_baseline(root / ".wardline" / "baseline.yaml", [leak])

    rows = {row.qualname: row for row in build_decorator_coverage(root).rows}

    assert rows["svc.leaky"].verdict == "clean"
    assert rows["svc.leaky"].finding_state == "suppressed"
    assert rows["svc.leaky"].active_finding_fingerprints == []
    assert rows["svc.leaky"].suppressed_finding_fingerprints == [leak.fingerprint]
