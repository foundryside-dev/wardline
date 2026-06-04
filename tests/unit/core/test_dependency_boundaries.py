from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]


def test_dossier_core_and_filigree_do_not_depend_on_clarion_identity() -> None:
    for rel in (
        "src/wardline/core/dossier.py",
        "src/wardline/filigree/dossier_client.py",
    ):
        text = (ROOT / rel).read_text(encoding="utf-8")
        assert "wardline.clarion.identity" not in text


def test_loom_dossier_uses_neutral_identity_types() -> None:
    text = (ROOT / "src/wardline/loom_dossier.py").read_text(encoding="utf-8")
    assert "from wardline.core.identity import ContentStatus, EntityBinding, IdentityStatus" in text
    assert "from wardline.clarion.identity import ContentStatus" not in text
    assert "from wardline.clarion.identity import EntityBinding" not in text
    assert "from wardline.clarion.identity import IdentityStatus" not in text


def test_clarion_identity_reexports_neutral_core_identity_types() -> None:
    from wardline.clarion.identity import ContentStatus as ClarionContentStatus
    from wardline.clarion.identity import EntityBinding as ClarionEntityBinding
    from wardline.clarion.identity import IdentityStatus as ClarionIdentityStatus
    from wardline.core.identity import ContentStatus, EntityBinding, IdentityStatus

    assert ClarionContentStatus is ContentStatus
    assert ClarionEntityBinding is EntityBinding
    assert ClarionIdentityStatus is IdentityStatus


def test_core_protocols_are_wired_into_orchestration_and_rule_registry() -> None:
    run_text = (ROOT / "src/wardline/core/run.py").read_text(encoding="utf-8")
    context_text = (ROOT / "src/wardline/scanner/context.py").read_text(encoding="utf-8")

    assert "from wardline.core.protocols import Analyzer" in run_text
    assert "analyzer: Analyzer" in run_text
    assert "from wardline.core.protocols import Rule" in context_text
    assert "class _Rule(Protocol)" not in context_text


def test_pack_tests_use_monkeypatch_for_syspath() -> None:
    for rel in (
        "tests/unit/core/test_packs.py",
        "tests/unit/core/test_judge_run.py",
        "tests/unit/cli/test_cli.py",
    ):
        text = (ROOT / rel).read_text(encoding="utf-8")
        assert "sys.path.insert" not in text
        assert "sys.path.remove" not in text
