"""Tests for wardline.manifest.exceptions — exception register loading."""

from __future__ import annotations

import json
from datetime import date, timedelta
from typing import TYPE_CHECKING

import pytest

from wardline.manifest.exceptions import check_exception_ages, load_exceptions
from wardline.manifest.loader import ManifestLoadError
from wardline.manifest.models import ExceptionEntry

if TYPE_CHECKING:
    from pathlib import Path


def _write_exceptions(path: Path, entries: list[dict]) -> None:
    data = {
        "$id": "https://wardline.dev/schemas/1.0/exceptions.schema.json",
        "exceptions": entries,
    }
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _valid_entry(**overrides) -> dict:
    base = {
        "id": "EXC-001",
        "rule": "PY-WL-001",
        "taint_state": "EXTERNAL_RAW",
        "location": "src/adapters/client.py::Client.handle",
        "exceptionability": "STANDARD",
        "severity_at_grant": "ERROR",
        "rationale": "Schema fallback approved",
        "reviewer": "jsmith",
        "ast_fingerprint": "a1b2c3d4e5f6",
    }
    base.update(overrides)
    return base


class TestLoadExceptions:
    def test_file_not_found_returns_empty(self, tmp_path: Path) -> None:
        assert load_exceptions(tmp_path) == ()

    def test_valid_file_returns_entries(self, tmp_path: Path) -> None:
        _write_exceptions(tmp_path / "wardline.exceptions.json", [_valid_entry()])
        result = load_exceptions(tmp_path)
        assert len(result) == 1
        assert result[0].id == "EXC-001"
        assert result[0].rule == "PY-WL-001"

    def test_blank_ast_fingerprint_raises(self, tmp_path: Path) -> None:
        entry = _valid_entry(ast_fingerprint="")
        _write_exceptions(tmp_path / "wardline.exceptions.json", [entry])
        with pytest.raises(ManifestLoadError, match="blank ast_fingerprint"):
            load_exceptions(tmp_path)

    def test_ast_fingerprint_preserved(self, tmp_path: Path) -> None:
        entry = _valid_entry(ast_fingerprint="abcdef0123456789")
        _write_exceptions(tmp_path / "wardline.exceptions.json", [entry])
        result = load_exceptions(tmp_path)
        assert result[0].ast_fingerprint == "abcdef0123456789"

    def test_invalid_schema_raises(self, tmp_path: Path) -> None:
        bad = {"$id": "https://wardline.dev/schemas/1.0/exceptions.schema.json", "exceptions": [{"bad": True}]}
        (tmp_path / "wardline.exceptions.json").write_text(json.dumps(bad), encoding="utf-8")
        with pytest.raises(ManifestLoadError):
            load_exceptions(tmp_path)

    def test_unconditional_cell_raises(self, tmp_path: Path) -> None:
        # PY-WL-001 with INTEGRAL is UNCONDITIONAL in the severity matrix
        entry = _valid_entry(rule="PY-WL-001", taint_state="INTEGRAL")
        _write_exceptions(tmp_path / "wardline.exceptions.json", [entry])
        with pytest.raises(ManifestLoadError, match="UNCONDITIONAL"):
            load_exceptions(tmp_path)

    def test_optional_fields_default(self, tmp_path: Path) -> None:
        _write_exceptions(tmp_path / "wardline.exceptions.json", [_valid_entry()])
        result = load_exceptions(tmp_path)
        assert result[0].recurrence_count == 0
        assert result[0].governance_path == "standard"
        assert result[0].expires is None


def _make_exception_entry(
    *,
    exceptionability: str = "STANDARD",
    expires: str | None = None,
    last_refreshed_at: str | None = None,
) -> ExceptionEntry:
    """Build a minimal ExceptionEntry for age-limit tests."""
    return ExceptionEntry(
        id="EXC-AGE-001",
        rule="PY-WL-001",
        taint_state="EXTERNAL_RAW",
        location="src/foo.py::bar",
        exceptionability=exceptionability,
        severity_at_grant="ERROR",
        rationale="test",
        reviewer="tester",
        ast_fingerprint="abc123",
        expires=expires,
        last_refreshed_at=last_refreshed_at,
    )


class TestExceptionAgeLimits:
    def test_within_class_limit_no_warning(self) -> None:
        """Exception within its class limit produces no warning."""
        today = date.today()
        grant = today - timedelta(days=100)
        expires = (grant + timedelta(days=180)).isoformat()
        entry = _make_exception_entry(
            exceptionability="STANDARD",
            expires=expires,
            last_refreshed_at=grant.isoformat(),
        )
        warnings = check_exception_ages(
            (entry,), age_limits={"STANDARD": 180}, global_max_days=365
        )
        assert warnings == ()

    def test_exceeds_class_limit_produces_warning(self) -> None:
        """STANDARD exception older than 180 days produces a warning."""
        today = date.today()
        grant = today - timedelta(days=200)
        expires = (grant + timedelta(days=180)).isoformat()
        entry = _make_exception_entry(
            exceptionability="STANDARD",
            expires=expires,
            last_refreshed_at=grant.isoformat(),
        )
        warnings = check_exception_ages(
            (entry,), age_limits={"STANDARD": 180}, global_max_days=365
        )
        assert len(warnings) == 1
        assert "200 days old" in warnings[0]
        assert "STANDARD" in warnings[0]
        assert "180 days" in warnings[0]

    def test_global_fallback_when_no_class_limit(self) -> None:
        """RELAXED exception with no class limit uses global max."""
        today = date.today()
        grant = today - timedelta(days=400)
        expires = (grant + timedelta(days=365)).isoformat()
        entry = _make_exception_entry(
            exceptionability="RELAXED",
            expires=expires,
            last_refreshed_at=grant.isoformat(),
        )
        # No RELAXED key in age_limits -- falls back to global_max_days=365
        warnings = check_exception_ages(
            (entry,), age_limits={"STANDARD": 180}, global_max_days=365
        )
        assert len(warnings) == 1
        assert "400 days old" in warnings[0]
        assert "365 days" in warnings[0]

    def test_no_expires_no_warning(self) -> None:
        """Exception without expires field produces no warning."""
        entry = _make_exception_entry(expires=None)
        warnings = check_exception_ages(
            (entry,), age_limits={"STANDARD": 180}, global_max_days=365
        )
        assert warnings == ()

    def test_grant_date_inferred_from_expires(self) -> None:
        """Without last_refreshed_at, grant date is inferred from expires - limit."""
        today = date.today()
        # expires is today (so grant = today - 180 = 180 days ago), limit is 180
        # age_days == 180 which is NOT > 180, so no warning
        expires = today.isoformat()
        entry = _make_exception_entry(
            exceptionability="STANDARD",
            expires=expires,
            last_refreshed_at=None,
        )
        warnings = check_exception_ages(
            (entry,), age_limits={"STANDARD": 180}, global_max_days=365
        )
        assert warnings == ()

    def test_grant_date_inferred_exceeds_limit(self) -> None:
        """Inferred grant date that exceeds limit produces warning."""
        today = date.today()
        # expires is yesterday, so grant = yesterday - 180 = 181 days ago
        expires = (today - timedelta(days=1)).isoformat()
        entry = _make_exception_entry(
            exceptionability="STANDARD",
            expires=expires,
            last_refreshed_at=None,
        )
        warnings = check_exception_ages(
            (entry,), age_limits={"STANDARD": 180}, global_max_days=365
        )
        assert len(warnings) == 1
        assert "181 days old" in warnings[0]

    def test_multiple_entries_multiple_warnings(self) -> None:
        """Multiple expired exceptions each produce their own warning."""
        today = date.today()
        grant = today - timedelta(days=200)
        expires = (grant + timedelta(days=180)).isoformat()
        e1 = _make_exception_entry(
            exceptionability="STANDARD",
            expires=expires,
            last_refreshed_at=grant.isoformat(),
        )
        e2 = ExceptionEntry(
            id="EXC-AGE-002",
            rule="PY-WL-002",
            taint_state="EXTERNAL_RAW",
            location="src/bar.py::baz",
            exceptionability="RELAXED",
            severity_at_grant="WARNING",
            rationale="test2",
            reviewer="tester",
            ast_fingerprint="def456",
            expires=expires,
            last_refreshed_at=grant.isoformat(),
        )
        warnings = check_exception_ages(
            (e1, e2), age_limits={"STANDARD": 180, "RELAXED": 180}, global_max_days=365
        )
        assert len(warnings) == 2
