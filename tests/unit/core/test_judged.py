from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml

from wardline.core.errors import ConfigError, SchemeMismatchError
from wardline.core.finding import FINGERPRINT_SCHEME
from wardline.core.judge_types import JudgeTransport
from wardline.core.judged import JudgedFP, build_judged_document, load_judged, write_judged

_SCHEME = f"fingerprint_scheme: {FINGERPRINT_SCHEME}\n"


def _fp(**kw: object) -> JudgedFP:
    base: dict[str, object] = dict(
        fingerprint="a" * 64,
        rule_id="PY-WL-101",
        path="src/m.py",
        message="m",
        rationale="constructor over-taint floor",
        model_id="anthropic/claude-opus-4-8",
        judge_transport=JudgeTransport.OPENROUTER,
        confidence=0.9,
        recorded_at=datetime(2026, 5, 30, tzinfo=UTC),
        policy_hash="sha256:abc",
    )
    base.update(kw)
    return JudgedFP(**base)  # type: ignore[arg-type]


def test_roundtrip(tmp_path: Path) -> None:
    path = tmp_path / ".wardline" / "judged.yaml"
    write_judged(path, [_fp()])
    loaded = load_judged(path)
    match = loaded.match("a" * 64)
    assert match is not None and match.rationale == "constructor over-taint floor"
    assert loaded.match("b" * 64) is None


def test_v2_roundtrip_preserves_concrete_transport(tmp_path: Path) -> None:
    path = tmp_path / "judged.yaml"
    write_judged(path, [_fp(judge_transport=JudgeTransport.CODEX_CLI)])

    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    loaded = load_judged(path).match("a" * 64)

    assert document["version"] == 2
    assert document["findings"][0]["judge_transport"] == "codex-cli"
    assert loaded is not None and loaded.judge_transport is JudgeTransport.CODEX_CLI


def test_legacy_v1_record_infers_openrouter_without_rewrite(tmp_path: Path) -> None:
    path = tmp_path / "judged.yaml"
    path.write_text(
        _SCHEME
        + "version: 1\nfindings:\n"
        + f"  - fingerprint: {'a' * 64}\n"
        + "    verdict: FALSE_POSITIVE\n    rationale: legacy\n    model_id: old/model\n"
        + "    policy_hash: sha256:old\n    confidence: 0.9\n"
        + "    recorded_at: 2026-05-30T00:00:00+00:00\n",
        encoding="utf-8",
    )
    before = path.read_bytes()

    loaded = load_judged(path).match("a" * 64)

    assert loaded is not None and loaded.judge_transport is JudgeTransport.OPENROUTER
    assert path.read_bytes() == before


@pytest.mark.parametrize(
    ("include_transport", "value"),
    [
        (False, None),
        (True, None),
        (True, ""),
        (True, "auto"),
        (True, "codex"),
        (True, "OPENROUTER"),
        (True, "unknown"),
    ],
)
def test_v2_rejects_missing_or_nonconcrete_transport(tmp_path: Path, include_transport: bool, value: object) -> None:
    entry: dict[str, object] = {
        "fingerprint": "a" * 64,
        "rule_id": "PY-WL-101",
        "path": "src/m.py",
        "message": "m",
        "verdict": "FALSE_POSITIVE",
        "rationale": "x",
        "model_id": "m",
        "confidence": 0.9,
        "recorded_at": "2026-05-30T00:00:00+00:00",
        "policy_hash": "sha256:x",
    }
    if include_transport:
        entry["judge_transport"] = value
    path = tmp_path / "judged.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "fingerprint_scheme": FINGERPRINT_SCHEME,
                "version": 2,
                "findings": [entry],
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )

    with pytest.raises(ConfigError, match="judge_transport"):
        load_judged(path)


@pytest.mark.parametrize("version", [None, 0, True, False, 3, "2"])
def test_nonempty_store_rejects_missing_unknown_or_noninteger_version(tmp_path: Path, version: object) -> None:
    path = tmp_path / "judged.yaml"
    document: dict[str, object] = {
        "fingerprint_scheme": FINGERPRINT_SCHEME,
        "findings": [],
    }
    if version is not None:
        document["version"] = version
    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")

    with pytest.raises(ConfigError, match="version"):
        load_judged(path)


def test_constructor_rejects_auto_transport() -> None:
    with pytest.raises(ValueError, match="concrete"):
        _fp(judge_transport=JudgeTransport.AUTO)


def test_constructor_rejects_raw_string_transport() -> None:
    with pytest.raises(TypeError, match="JudgeTransport"):
        _fp(judge_transport="openrouter")


@pytest.mark.parametrize(
    ("transport", "error_type"),
    [
        (JudgeTransport.AUTO, ValueError),
        ("openrouter", TypeError),
    ],
)
def test_writer_rejects_runtime_corrupted_transport(
    tmp_path: Path, transport: object, error_type: type[Exception]
) -> None:
    entry = _fp()
    object.__setattr__(entry, "judge_transport", transport)
    path = tmp_path / "judged.yaml"

    with pytest.raises(error_type):
        write_judged(path, [entry])

    assert not path.exists()


def test_missing_file_is_empty(tmp_path: Path) -> None:
    assert load_judged(tmp_path / "nope.yaml").match("a" * 64) is None


def test_write_is_rule_then_fingerprint_sorted(tmp_path: Path) -> None:
    path = tmp_path / "judged.yaml"
    # same rule_id -> tiebreak is fingerprint
    write_judged(path, [_fp(fingerprint="b" * 64), _fp(fingerprint="a" * 64)])
    doc = yaml.safe_load(path.read_text())
    assert [e["fingerprint"] for e in doc["findings"]] == ["a" * 64, "b" * 64]


def test_malformed_version_raises(tmp_path: Path) -> None:
    path = tmp_path / "judged.yaml"
    path.write_text(_SCHEME + "version: 999\nfindings: []\n")
    with pytest.raises(ConfigError):
        load_judged(path)


def test_bad_fingerprint_raises(tmp_path: Path) -> None:
    path = tmp_path / "judged.yaml"
    path.write_text(_SCHEME + "version: 1\nfindings:\n  - fingerprint: short\n    rationale: x\n")
    with pytest.raises(ConfigError):
        load_judged(path)


def test_build_document_carries_scheme_and_bare_fp(tmp_path: Path) -> None:
    doc = build_judged_document([_fp()])
    assert doc["fingerprint_scheme"] == FINGERPRINT_SCHEME == "wlfp2"
    assert ":" not in doc["findings"][0]["fingerprint"]  # entry stays bare


def test_missing_scheme_raises_scheme_mismatch_not_version(tmp_path: Path) -> None:
    path = tmp_path / "judged.yaml"
    path.write_text("version: 999\nfindings: []\n")  # header-less, like an old store
    with pytest.raises(SchemeMismatchError) as ei:
        load_judged(path)
    assert "wardline rekey" in str(ei.value)


def test_wrong_scheme_raises_scheme_mismatch(tmp_path: Path) -> None:
    path = tmp_path / "judged.yaml"
    path.write_text("fingerprint_scheme: wlfp1\nversion: 1\nfindings: []\n")
    with pytest.raises(SchemeMismatchError):
        load_judged(path)


def test_empty_mapping_is_empty_no_scheme_error(tmp_path: Path) -> None:
    path = tmp_path / "judged.yaml"
    path.write_text("{}\n")
    assert load_judged(path).match("a" * 64) is None


@pytest.mark.parametrize("contents", ["false\n", "0\n", "[]\n", '""\n'])
def test_falsey_nonmapping_top_level_is_rejected(tmp_path: Path, contents: str) -> None:
    path = tmp_path / "judged.yaml"
    path.write_text(contents, encoding="utf-8")

    with pytest.raises(ConfigError, match="mapping at top level"):
        load_judged(path)


@pytest.mark.parametrize("contents", ["", "null\n"])
def test_empty_or_null_document_remains_empty(tmp_path: Path, contents: str) -> None:
    path = tmp_path / "judged.yaml"
    path.write_text(contents, encoding="utf-8")

    assert load_judged(path).fingerprints() == frozenset()


@pytest.mark.parametrize("findings", [False, 0, None, {}])
def test_present_findings_must_be_an_actual_list(tmp_path: Path, findings: object) -> None:
    path = tmp_path / "judged.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "fingerprint_scheme": FINGERPRINT_SCHEME,
                "version": 2,
                "findings": findings,
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )

    with pytest.raises(ConfigError, match="findings.*list"):
        load_judged(path)


def test_roundtrip_preserves_all_provenance(tmp_path: Path) -> None:
    path = tmp_path / "judged.yaml"
    write_judged(path, [_fp()])
    m = load_judged(path).match("a" * 64)
    assert m is not None
    assert m.rationale == "constructor over-taint floor"
    assert m.model_id == "anthropic/claude-opus-4-8"
    assert m.policy_hash == "sha256:abc"
    assert m.confidence == 0.9
    assert m.recorded_at == datetime(2026, 5, 30, tzinfo=UTC)


def test_rejudge_updates_existing_record(tmp_path: Path) -> None:
    path = tmp_path / "judged.yaml"
    write_judged(path, [_fp(rationale="first")])
    write_judged(path, [_fp(rationale="second")])  # same fingerprint, new verdict
    match = load_judged(path).match("a" * 64)
    assert match is not None and match.rationale == "second"


def test_missing_provenance_raises(tmp_path: Path) -> None:
    # model_id / policy_hash / confidence are the audit primitive — never defaulted.
    # verdict is present so this exercises the PROVENANCE guard, not the verdict guard.
    path = tmp_path / "judged.yaml"
    path.write_text(
        _SCHEME + "version: 1\nfindings:\n"
        f"  - fingerprint: {'a' * 64}\n    verdict: FALSE_POSITIVE\n    rationale: x\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError):
        load_judged(path)


def test_out_of_range_confidence_raises(tmp_path: Path) -> None:
    # verdict is present so this reaches the confidence range check, not the verdict guard.
    path = tmp_path / "judged.yaml"
    path.write_text(
        _SCHEME + "version: 1\nfindings:\n"
        f"  - fingerprint: {'a' * 64}\n    verdict: FALSE_POSITIVE\n    rationale: x\n    model_id: m\n"
        "    policy_hash: sha256:x\n    confidence: 1.5\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError):
        load_judged(path)


def test_missing_verdict_raises(tmp_path: Path) -> None:
    # A judged record with no verdict cannot be trusted as a FALSE_POSITIVE suppression.
    path = tmp_path / "judged.yaml"
    path.write_text(
        _SCHEME + "version: 1\nfindings:\n"
        f"  - fingerprint: {'a' * 64}\n    rationale: x\n    model_id: m\n"
        "    policy_hash: sha256:x\n    confidence: 0.9\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="verdict"):
        load_judged(path)


def test_non_false_positive_verdict_rejected(tmp_path: Path) -> None:
    # A hand-edited TRUE_POSITIVE (or any non-FP) verdict must not be smuggled in as a
    # silent suppression — judged.yaml only ever records FALSE_POSITIVE.
    path = tmp_path / "judged.yaml"
    path.write_text(
        _SCHEME + "version: 1\nfindings:\n"
        f"  - fingerprint: {'a' * 64}\n    verdict: TRUE_POSITIVE\n    rationale: x\n    model_id: m\n"
        "    policy_hash: sha256:x\n    confidence: 0.9\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="FALSE_POSITIVE"):
        load_judged(path)


def test_write_judged_roundtrip_loads_with_verdict(tmp_path: Path) -> None:
    # build_judged_document always emits verdict: FALSE_POSITIVE, so a machine round-trip
    # stays valid under the new verdict requirement.
    path = tmp_path / ".wardline" / "judged.yaml"
    write_judged(path, [_fp()])
    doc = yaml.safe_load(path.read_text())
    assert doc["findings"][0]["verdict"] == "FALSE_POSITIVE"
    assert load_judged(path).match("a" * 64) is not None
