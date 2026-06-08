"""Wave 3 — Deferred Coverage Rules tests.

Tests for:
- PY-WL-116 (Path/filesystem-traversal sinks)
- PY-WL-117 (SSRF HTTP client sinks)
- PY-WL-118 (SQL-injection execution sinks)
- PY-WL-119 (Degenerate / no-op boundaries)
- PY-WL-120 (Stored-taint reaches trusted state without validation)
"""

from __future__ import annotations

import textwrap
from collections.abc import Sequence
from pathlib import Path

from wardline.core.config import WardlineConfig
from wardline.core.finding import Finding, Kind
from wardline.scanner.analyzer import WardlineAnalyzer


def _analyze_files(tmp_path: Path, files: dict[str, str]) -> Sequence[Finding]:
    for name, content in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        header = (
            "from wardline.decorators import external_boundary, trust_boundary, trusted\n"
            "import os\nimport pathlib\nimport requests\nimport httpx\nimport urllib.request\n"
            "@external_boundary\ndef read_raw(p):\n    return p\n"
            "@trust_boundary(to_level='ASSURED')\n"
            "def validate(x):\n"
            "    if not x:\n        raise ValueError\n    return x\n"
        )
        p.write_text(header + textwrap.dedent(content), encoding="utf-8")

    analyzer = WardlineAnalyzer()
    file_paths = [tmp_path / name for name in files]
    findings = analyzer.analyze(file_paths, WardlineConfig(), root=tmp_path)
    return findings


# ── PY-WL-116: Path Traversal ──────────────────────────────────────────────


def test_path_traversal_fires_on_open(tmp_path: Path) -> None:
    findings = _analyze_files(
        tmp_path,
        {
            "m.py": """
            @trusted(level='ASSURED')
            def test_pt(p):
                open(read_raw(p))
            """
        },
    )
    defects = [f for f in findings if f.kind is Kind.DEFECT]
    pt_findings = [f for f in defects if f.rule_id == "PY-WL-116"]
    assert len(pt_findings) == 1
    assert pt_findings[0].qualname == "m.test_pt"


def test_path_traversal_fires_on_os_path_join(tmp_path: Path) -> None:
    findings = _analyze_files(
        tmp_path,
        {
            "m.py": """
            @trusted(level='ASSURED')
            def test_pt(p):
                os.path.join('/tmp', read_raw(p))
            """
        },
    )
    defects = [f for f in findings if f.kind is Kind.DEFECT]
    pt_findings = [f for f in defects if f.rule_id == "PY-WL-116"]
    assert len(pt_findings) == 1


# ── PY-WL-117: SSRF ────────────────────────────────────────────────────────


def test_ssrf_fires_on_requests_get(tmp_path: Path) -> None:
    findings = _analyze_files(
        tmp_path,
        {
            "m.py": """
            @trusted(level='ASSURED')
            def test_ssrf(p):
                requests.get(read_raw(p))
            """
        },
    )
    defects = [f for f in findings if f.kind is Kind.DEFECT]
    ssrf_findings = [f for f in defects if f.rule_id == "PY-WL-117"]
    assert len(ssrf_findings) == 1
    assert ssrf_findings[0].qualname == "m.test_ssrf"


def test_ssrf_fires_on_httpx_post(tmp_path: Path) -> None:
    findings = _analyze_files(
        tmp_path,
        {
            "m.py": """
            @trusted(level='ASSURED')
            def test_ssrf(p):
                httpx.post(read_raw(p))
            """
        },
    )
    defects = [f for f in findings if f.kind is Kind.DEFECT]
    ssrf_findings = [f for f in defects if f.rule_id == "PY-WL-117"]
    assert len(ssrf_findings) == 1


def test_ssrf_fires_on_nested_module_alias(tmp_path: Path) -> None:
    findings = _analyze_files(
        tmp_path,
        {
            "m.py": """
            import urllib.request as ur

            @trusted(level='ASSURED')
            def test_ssrf(p):
                ur.urlopen(read_raw(p))
            """
        },
    )
    defects = [f for f in findings if f.kind is Kind.DEFECT]
    ssrf_findings = [f for f in defects if f.rule_id == "PY-WL-117"]
    assert len(ssrf_findings) == 1
    assert ssrf_findings[0].properties["sink"] == "urllib.request.urlopen"


# ── PY-WL-118: SQL Injection ───────────────────────────────────────────────


def test_sql_injection_fires_on_execute(tmp_path: Path) -> None:
    findings = _analyze_files(
        tmp_path,
        {
            "m.py": """
            @trusted(level='ASSURED')
            def test_sql(p, cursor):
                cursor.execute(read_raw(p))
            """
        },
    )
    defects = [f for f in findings if f.kind is Kind.DEFECT]
    sqli_findings = [f for f in defects if f.rule_id == "PY-WL-118"]
    assert len(sqli_findings) == 1
    assert sqli_findings[0].qualname == "m.test_sql"


def test_sql_injection_parameterized_query_does_not_fire(tmp_path: Path) -> None:
    # Bound-parameter query: the SQL string is a constant literal, the untrusted value is
    # passed ONLY as a bound parameter (the OWASP-canonical mitigation), so it cannot alter
    # SQL structure — there is no CWE-89 finding (wardline-e0e44852e7).
    findings = _analyze_files(
        tmp_path,
        {
            "m.py": """
            @trusted(level='ASSURED')
            def q(p, cursor):
                cursor.execute("SELECT * FROM users WHERE id = ?", (read_raw(p),))
            """
        },
    )
    sqli = [f for f in findings if f.kind is Kind.DEFECT and f.rule_id == "PY-WL-118"]
    assert sqli == []


def test_sql_injection_executemany_parameterized_does_not_fire(tmp_path: Path) -> None:
    # executemany's seq_of_params is also a bound-parameter position.
    findings = _analyze_files(
        tmp_path,
        {
            "m.py": """
            @trusted(level='ASSURED')
            def q(p, cursor):
                cursor.executemany("INSERT INTO t VALUES (?)", read_raw(p))
            """
        },
    )
    sqli = [f for f in findings if f.kind is Kind.DEFECT and f.rule_id == "PY-WL-118"]
    assert sqli == []


def test_sql_injection_tainted_sql_string_with_clean_params_still_fires(tmp_path: Path) -> None:
    # The no-FN guard for the FP fix: narrowing to the operation position must NOT silence a
    # genuinely tainted SQL STRING. Untrusted data interpolated into the query text — with a
    # clean bound parameter — is still SQLi.
    findings = _analyze_files(
        tmp_path,
        {
            "m.py": """
            @trusted(level='ASSURED')
            def q(p, uid, cursor):
                cursor.execute(f"SELECT * FROM {read_raw(p)} WHERE id = ?", (uid,))
            """
        },
    )
    sqli = [f for f in findings if f.kind is Kind.DEFECT and f.rule_id == "PY-WL-118"]
    assert len(sqli) == 1
    assert sqli[0].qualname == "m.q"


# ── PY-WL-119: Degenerate Boundary ─────────────────────────────────────────


def test_degenerate_boundary_fires(tmp_path: Path) -> None:
    findings = _analyze_files(
        tmp_path,
        {
            "m.py": """
            @trust_boundary(to_level='ASSURED')
            def degenerate(x):
                return x
            """
        },
    )
    defects = [f for f in findings if f.kind is Kind.DEFECT]
    db_findings = [f for f in defects if f.rule_id == "PY-WL-119"]
    assert len(db_findings) == 1
    assert db_findings[0].qualname == "m.degenerate"


def test_clean_boundary_does_not_fire(tmp_path: Path) -> None:
    findings = _analyze_files(
        tmp_path,
        {
            "m.py": """
            @trust_boundary(to_level='ASSURED')
            def safe(x):
                if not x:
                    raise ValueError
                return x
            """
        },
    )
    defects = [f for f in findings if f.kind is Kind.DEFECT]
    db_findings = [f for f in defects if f.rule_id == "PY-WL-119"]
    assert len(db_findings) == 0


# ── PY-WL-120: Stored Taint ────────────────────────────────────────────────


def test_stored_taint_reaches_return_fires(tmp_path: Path) -> None:
    findings = _analyze_files(
        tmp_path,
        {
            "m.py": """
            @trusted(level='ASSURED')
            def get_data():
                f = open('data.txt')
                content = f.read()
                return content
            """
        },
    )
    defects = [f for f in findings if f.kind is Kind.DEFECT]
    st_findings = [f for f in defects if f.rule_id == "PY-WL-120"]
    assert len(st_findings) == 1
    assert st_findings[0].qualname == "m.get_data"


def test_stored_taint_reaches_callee_fires(tmp_path: Path) -> None:
    findings = _analyze_files(
        tmp_path,
        {
            "m.py": """
            @trusted(level='ASSURED')
            def store(val):
                return 1

            @trusted(level='ASSURED')
            def run():
                path = pathlib.Path('config.txt')
                data = path.read_text()
                store(data)
            """
        },
    )
    defects = [f for f in findings if f.kind is Kind.DEFECT]
    st_findings = [f for f in defects if f.rule_id == "PY-WL-120"]
    assert len(st_findings) == 1
    assert st_findings[0].qualname == "m.run"


def test_sql_injection_nested_def_inherits_trusted_tier(tmp_path: Path) -> None:
    # A nested def inside a @trusted parent inherits the parent's trusted tier via the
    # family-wide ``.<locals>.`` strip (commit bdccca1). PY-WL-118 originally lacked the
    # strip, so a tainted execute() wrapped in a nested function silently evaded the
    # highest-severity sink (wardline-9b88ec5419). This test previously asserted the BUG
    # (118 stays silent here); it now asserts the parity it always should have had —
    # 118 fires exactly as its siblings 108/115/116/117 do in this shape.
    findings = _analyze_files(
        tmp_path,
        {
            "m.py": """
            @trusted(level='ASSURED')
            def safe_parent(p):
                def nested_untrusted():
                    import sqlite3
                    conn = sqlite3.connect(':memory:')
                    cursor = conn.cursor()
                    cursor.execute(read_raw(p))
                return "ok"
            """
        },
    )
    defects = [f for f in findings if f.kind is Kind.DEFECT]
    sqli_findings = [f for f in defects if f.rule_id == "PY-WL-118"]
    assert len(sqli_findings) == 1
    assert sqli_findings[0].qualname == "m.safe_parent.<locals>.nested_untrusted"


def test_stored_taint_nested_scope_isolation(tmp_path: Path) -> None:
    findings = _analyze_files(
        tmp_path,
        {
            "m.py": """
            @trusted(level='ASSURED')
            def safe_parent(p):
                def nested_untrusted():
                    data = open('data.txt').read()
                    return data
                return read_raw(p)
            """
        },
    )
    defects = [f for f in findings if f.kind is Kind.DEFECT]
    st_findings = [f for f in defects if f.rule_id == "PY-WL-120"]
    assert len(st_findings) == 0
