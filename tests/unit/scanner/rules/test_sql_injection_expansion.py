"""PY-WL-118 precision + coverage expansion (wardline-1751b0fac6 + 2026-06-10 eval FPs).

Three behaviour groups:

1. Text-clause constant exemption — ``conn.execute(text("... :id"), {"id": uid})``
   is THE canonical safe SQLAlchemy parameterized pattern: the operation string is a
   compile-time constant wrapped in a recognized text-clause constructor, so it cannot
   carry attacker bytes. ``text(tainted)`` must still fire (the exemption keys on the
   constructor FQN AND all-constant arguments, never on the wrapper alone).

2. Receiver heuristic — ``.execute``/``.executemany`` matching was receiver-blind, so
   ``pool.execute(task)`` on a thread-pool object fired a CWE-89 ERROR. Clearly-non-DB
   receivers (pool/executor/worker names, or instances constructed from executor
   modules) stop firing; DB-ish and UNKNOWN receivers keep firing (fail-closed — an FN
   here is worse than an FP).

3. Sink coverage — ``executescript`` (sqlite3 cursor/connection; non-parameterizable,
   strictly more dangerous than ``execute``) joins the sink set, plus the previously
   untested ``executemany`` positive direction.
"""

from __future__ import annotations

import textwrap
from collections.abc import Sequence
from pathlib import Path

from wardline.core.config import WardlineConfig
from wardline.core.finding import Finding, Kind, Severity
from wardline.scanner.analyzer import WardlineAnalyzer


def _analyze_files(tmp_path: Path, files: dict[str, str]) -> Sequence[Finding]:
    for name, content in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        header = (
            "from wardline.decorators import external_boundary, trust_boundary, trusted\n"
            "@external_boundary\ndef read_raw(p):\n    return p\n"
        )
        p.write_text(header + textwrap.dedent(content), encoding="utf-8")

    analyzer = WardlineAnalyzer()
    file_paths = [tmp_path / name for name in files]
    return analyzer.analyze(file_paths, WardlineConfig(), root=tmp_path)


def _sqli(findings: Sequence[Finding]) -> list[Finding]:
    return [f for f in findings if f.kind is Kind.DEFECT and f.rule_id == "PY-WL-118"]


# ── 1. text-clause constant exemption (canonical SQLAlchemy parameterized query) ──


def test_sqlalchemy_text_constant_operation_does_not_fire(tmp_path: Path) -> None:
    # The canonical safe pattern: constant SQL wrapped in text(), untrusted value bound.
    findings = _analyze_files(
        tmp_path,
        {
            "m.py": """
            from sqlalchemy import text

            @trusted(level='ASSURED')
            def f(p, conn):
                uid = read_raw(p)
                conn.execute(text("SELECT * FROM t WHERE id = :id"), {"id": uid})
            """
        },
    )
    assert _sqli(findings) == []


def test_sqlalchemy_module_alias_text_constant_does_not_fire(tmp_path: Path) -> None:
    # Import-alias awareness: ``import sqlalchemy as sa; sa.text(...)`` and the
    # ``sqlalchemy.sql.text`` spelling both resolve to a recognized text-clause FQN.
    findings = _analyze_files(
        tmp_path,
        {
            "m.py": """
            import sqlalchemy as sa
            from sqlalchemy.sql import text as mktext

            @trusted(level='ASSURED')
            def f(p, conn):
                uid = read_raw(p)
                conn.execute(sa.text("SELECT * FROM t WHERE id = :id"), {"id": uid})
                conn.execute(mktext("SELECT * FROM u WHERE id = :id"), {"id": uid})
            """
        },
    )
    assert _sqli(findings) == []


def test_sqlalchemy_text_constant_via_operation_keyword_does_not_fire(tmp_path: Path) -> None:
    findings = _analyze_files(
        tmp_path,
        {
            "m.py": """
            from sqlalchemy import text

            @trusted(level='ASSURED')
            def f(p, conn):
                conn.execute(statement=text("SELECT 1"), parameters={"id": read_raw(p)})
            """
        },
    )
    assert _sqli(findings) == []


def test_sqlalchemy_text_with_tainted_argument_still_fires(tmp_path: Path) -> None:
    # text() is NOT a sanitiser: a tainted string inside the wrapper is still SQLi.
    findings = _analyze_files(
        tmp_path,
        {
            "m.py": """
            from sqlalchemy import text

            @trusted(level='ASSURED')
            def f(p, conn):
                conn.execute(text(read_raw(p)))
            """
        },
    )
    assert len(_sqli(findings)) == 1


def test_sqlalchemy_text_with_fstring_argument_still_fires(tmp_path: Path) -> None:
    # A JoinedStr is not a Constant — interpolated taint inside text() keeps firing.
    findings = _analyze_files(
        tmp_path,
        {
            "m.py": """
            from sqlalchemy import text

            @trusted(level='ASSURED')
            def f(p, conn):
                conn.execute(text(f"SELECT * FROM {read_raw(p)}"))
            """
        },
    )
    assert len(_sqli(findings)) == 1


def test_unrecognized_constant_arg_wrapper_still_fires(tmp_path: Path) -> None:
    # The exemption is scoped to RECOGNIZED text-clause constructors — an arbitrary
    # third-party wrapper around a constant stays fail-closed (UNKNOWN_RAW fires).
    findings = _analyze_files(
        tmp_path,
        {
            "m.py": """
            import mylib

            @trusted(level='ASSURED')
            def f(p, conn):
                conn.execute(mylib.textish("SELECT 1"))
            """
        },
    )
    assert len(_sqli(findings)) == 1


def test_sqlalchemy_text_zero_args_stays_fail_closed(tmp_path: Path) -> None:
    # text() with no argument proves nothing constant; the slot keeps its engine taint.
    findings = _analyze_files(
        tmp_path,
        {
            "m.py": """
            from sqlalchemy import text

            @trusted(level='ASSURED')
            def f(p, conn):
                conn.execute(text())
            """
        },
    )
    assert len(_sqli(findings)) == 1


# ── 2. receiver heuristic ──────────────────────────────────────────────────


def test_non_db_receiver_pool_does_not_fire(tmp_path: Path) -> None:
    # The eval FP repro: a thread-pool/command object is not a SQL sink.
    findings = _analyze_files(
        tmp_path,
        {
            "m.py": """
            @trusted(level='ASSURED')
            def f(p, pool):
                task = read_raw(p)
                pool.execute(task)
            """
        },
    )
    assert _sqli(findings) == []


def test_non_db_receiver_thread_pool_attribute_does_not_fire(tmp_path: Path) -> None:
    # Non-DB token match on the LAST attribute segment (self.thread_pool → "thread_pool").
    findings = _analyze_files(
        tmp_path,
        {
            "m.py": """
            @trusted(level='ASSURED')
            def f(self, p):
                self.thread_pool.execute(read_raw(p))
            """
        },
    )
    assert _sqli(findings) == []


def test_non_db_constructed_executor_does_not_fire(tmp_path: Path) -> None:
    # Construct-then-method resolution: an instance provably built from an executor
    # module is non-DB even when its NAME looks DB-ish.
    findings = _analyze_files(
        tmp_path,
        {
            "m.py": """
            import concurrent.futures

            @trusted(level='ASSURED')
            def f(p):
                runner = concurrent.futures.ThreadPoolExecutor()
                runner.execute(read_raw(p))
            """
        },
    )
    assert _sqli(findings) == []


def test_db_constructed_instance_overrides_non_db_name(tmp_path: Path) -> None:
    # Binding evidence beats the name heuristic: a var NAMED "pool" that is provably a
    # sqlite3 connection is a real SQL sink and must fire.
    findings = _analyze_files(
        tmp_path,
        {
            "m.py": """
            import sqlite3

            @trusted(level='ASSURED')
            def f(p):
                pool = sqlite3.connect(":memory:")
                pool.execute(read_raw(p))
            """
        },
    )
    assert len(_sqli(findings)) == 1


def test_unknown_receiver_fails_closed_and_fires(tmp_path: Path) -> None:
    # An opaque single-letter receiver gives no evidence either way — fail closed, fire
    # (FN is worse than FP; covers the SQLAlchemy ``s.execute`` / DB-API ``c.execute`` style).
    findings = _analyze_files(
        tmp_path,
        {
            "m.py": """
            @trusted(level='ASSURED')
            def f(p, c):
                c.execute(read_raw(p))
            """
        },
    )
    assert len(_sqli(findings)) == 1


def test_db_token_receiver_keeps_firing(tmp_path: Path) -> None:
    findings = _analyze_files(
        tmp_path,
        {
            "m.py": """
            @trusted(level='ASSURED')
            def f(p, db_session):
                db_session.execute(read_raw(p))
            """
        },
    )
    assert len(_sqli(findings)) == 1


def test_db_token_wins_over_non_db_token(tmp_path: Path) -> None:
    # Mixed evidence ("db_pool") resolves toward firing — conservative by design.
    findings = _analyze_files(
        tmp_path,
        {
            "m.py": """
            @trusted(level='ASSURED')
            def f(p, db_pool):
                db_pool.execute(read_raw(p))
            """
        },
    )
    assert len(_sqli(findings)) == 1


# ── 3. sink coverage: executescript + executemany ──────────────────────────


def test_executescript_tainted_fires_at_base_severity(tmp_path: Path) -> None:
    findings = _analyze_files(
        tmp_path,
        {
            "m.py": """
            @trusted(level='ASSURED')
            def f(p, cursor):
                cursor.executescript(read_raw(p))
            """
        },
    )
    sqli = _sqli(findings)
    assert len(sqli) == 1
    assert sqli[0].severity is Severity.ERROR
    assert sqli[0].properties["sink"] == "executescript"


def test_executescript_on_connection_fires(tmp_path: Path) -> None:
    # sqlite3 exposes executescript on the CONNECTION as well as the cursor.
    findings = _analyze_files(
        tmp_path,
        {
            "m.py": """
            import sqlite3

            @trusted(level='ASSURED')
            def f(p):
                conn = sqlite3.connect(":memory:")
                conn.executescript(read_raw(p))
            """
        },
    )
    assert len(_sqli(findings)) == 1


def test_executescript_sql_script_keyword_fires(tmp_path: Path) -> None:
    # The sqlite3 parameter name spelling of the script slot.
    findings = _analyze_files(
        tmp_path,
        {
            "m.py": """
            @trusted(level='ASSURED')
            def f(p, cursor):
                cursor.executescript(sql_script=read_raw(p))
            """
        },
    )
    assert len(_sqli(findings)) == 1


def test_executescript_constant_script_does_not_fire(tmp_path: Path) -> None:
    findings = _analyze_files(
        tmp_path,
        {
            "m.py": """
            @trusted(level='ASSURED')
            def f(cursor):
                cursor.executescript("CREATE TABLE t (id INTEGER); CREATE INDEX i ON t (id);")
            """
        },
    )
    assert _sqli(findings) == []


def test_executemany_tainted_operation_fires(tmp_path: Path) -> None:
    # executemany is in _SINKS but had no positive test (wardline-1751b0fac6).
    findings = _analyze_files(
        tmp_path,
        {
            "m.py": """
            @trusted(level='ASSURED')
            def f(p, cursor):
                cursor.executemany(read_raw(p), [])
            """
        },
    )
    sqli = _sqli(findings)
    assert len(sqli) == 1
    assert sqli[0].properties["sink"] == "executemany"
    assert sqli[0].severity is Severity.ERROR


def test_118_undecorated_is_suppressed(tmp_path: Path) -> None:
    # Matrix slot (wardline-e159060db7): SQLInjection overrides check(), so its
    # tier-gate branch needs its own undecorated (UNKNOWN_RAW freedom-zone)
    # negative — raw data at the execute sink must stay silent without a trust claim.
    findings = _analyze_files(
        tmp_path,
        {
            "m.py": """
            def f(p, cursor):
                cursor.execute(read_raw(p))
            """
        },
    )
    assert _sqli(findings) == []
