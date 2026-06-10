"""PY-WL-120 precision + stored-source coverage (wardline-66b2c91470 / stored.json FP).

Three behaviors under test:

1. **Receiver-aware storage matching.** ``io.StringIO`` / ``io.BytesIO`` are
   in-memory buffers — a ``.read()`` on one returns data the process itself put
   there, never *persistent storage* — so they are exempt from PY-WL-120's
   storage-read matcher (the old matcher accepted ANY ``.read()`` receiver-blind
   and mislabeled an in-memory constant as "stored/persisted data").

2. **101 delegation on unsubstantiated provenance.** When a matched return's
   taint is ``UNKNOWN_RAW``/``MIXED_RAW`` the engine could not resolve where the
   value came from, so the "stored/persisted" label rests solely on the AST name
   match — unsubstantiated. PY-WL-120 suppresses its return finding and delegates
   to PY-WL-101 (which polices the same trust-claim violation, gate-eligibly).
   A substantiated ``EXTERNAL_RAW`` storage return keeps the documented
   complementary 120+101 pair (both pinned by the frozen identity corpus).

3. **DB-cursor seeding is real.** ``cursor.fetchone/fetchall/fetchmany()`` seed
   ``EXTERNAL_RAW`` (wardline-e7c7cda31a), so PY-WL-120's advertised DB-cursor
   coverage fires on both the trusted-callee arm and the return arm.
"""

from __future__ import annotations

import textwrap
from collections.abc import Sequence
from pathlib import Path

from wardline.core.config import WardlineConfig
from wardline.core.finding import Finding, Kind
from wardline.core.taints import TaintState
from wardline.scanner.analyzer import WardlineAnalyzer


def _analyze(tmp_path: Path, source: str) -> Sequence[Finding]:
    header = (
        "from wardline.decorators import external_boundary, trust_boundary, trusted\n"
        "import io\n"
        "@trust_boundary(to_level='ASSURED')\n"
        "def validate(x):\n"
        "    if not x:\n        raise ValueError\n    return x\n"
    )
    p = tmp_path / "m.py"
    p.write_text(header + textwrap.dedent(source), encoding="utf-8")
    analyzer = WardlineAnalyzer()
    return analyzer.analyze([p], WardlineConfig(), root=tmp_path)


def _rule(findings: Sequence[Finding], rule_id: str) -> list[Finding]:
    return [f for f in findings if f.kind is Kind.DEFECT and f.rule_id == rule_id]


# ── 1. In-memory buffer receivers are exempt (the verified FP) ───────────────


def test_stringio_constant_read_is_not_stored_data(tmp_path: Path) -> None:
    # stored.json FP: an io.StringIO of an internal constant involves zero
    # persistent storage — the receiver-blind ``.read()`` match mislabeled it.
    findings = _analyze(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f():
            buf = io.StringIO("internal constant")
            data = buf.read()
            return data
        """,
    )
    assert _rule(findings, "PY-WL-120") == []


def test_chained_stringio_read_is_not_stored_data(tmp_path: Path) -> None:
    # Chained constructor→method form: io.StringIO("x").read().
    findings = _analyze(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f():
            return io.StringIO("x").read()
        """,
    )
    assert _rule(findings, "PY-WL-120") == []


def test_from_import_stringio_read_is_not_stored_data(tmp_path: Path) -> None:
    # The exemption resolves through the module import alias map.
    findings = _analyze(
        tmp_path,
        """
        from io import StringIO

        @trusted(level='ASSURED')
        def f():
            buf = StringIO("x")
            data = buf.read()
            return data
        """,
    )
    assert _rule(findings, "PY-WL-120") == []


def test_bytesio_with_block_read_is_not_stored_data(tmp_path: Path) -> None:
    # ``with io.BytesIO(...) as buf`` binds via the context-manager target form.
    findings = _analyze(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f():
            with io.BytesIO(b"x") as buf:
                data = buf.read()
            return data
        """,
    )
    assert _rule(findings, "PY-WL-120") == []


def test_open_file_read_still_fires(tmp_path: Path) -> None:
    # CONTROL: a genuine file read (open() receiver, EXTERNAL_RAW provenance)
    # keeps firing — the exemption is buffer-class-specific, not a .read() FN.
    findings = _analyze(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def get_data():
            f = open('data.txt')
            content = f.read()
            return content
        """,
    )
    st = _rule(findings, "PY-WL-120")
    assert [f.qualname for f in st] == ["m.get_data"]


def test_stringio_rebound_to_open_file_still_fires(tmp_path: Path) -> None:
    # Last-binding-wins: a name rebound from a buffer to a real file is NOT exempt.
    findings = _analyze(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f():
            h = io.StringIO("x")
            h = open('data.txt')
            data = h.read()
            return data
        """,
    )
    st = _rule(findings, "PY-WL-120")
    assert [f.qualname for f in st] == ["m.f"]


# ── 2. Return-arm delegation to PY-WL-101 on unsubstantiated provenance ──────


def test_unresolved_receiver_read_return_delegates_to_101(tmp_path: Path) -> None:
    # ``legacy.store.read()``: an imported-but-unmodeled dotted call resolves to
    # UNKNOWN_RAW — provenance unresolved, so the "stored/persisted" label rests
    # solely on the AST ``.read`` name match. 120 suppresses and delegates to 101,
    # which polices the same trust-claim violation (ONE finding on the return,
    # not two). (A bare PARAM receiver like ``handle.read()`` propagates the
    # trusted seed instead — neither rule fires there; documented
    # over-approximation, see variable_level.py.)
    findings = _analyze(
        tmp_path,
        """
        import legacy

        @trusted(level='ASSURED')
        def f():
            data = legacy.store.read()
            return data
        """,
    )
    assert _rule(findings, "PY-WL-120") == []
    p101 = _rule(findings, "PY-WL-101")
    assert [f.qualname for f in p101] == ["m.f"]
    assert p101[0].properties["actual_return"] == TaintState.UNKNOWN_RAW.value


def test_external_raw_storage_return_keeps_the_documented_pair(tmp_path: Path) -> None:
    # A SUBSTANTIATED storage return (EXTERNAL_RAW from the open() seed) keeps the
    # deliberate complementary pair: 101 = trust-claim violation (gate-eligible),
    # 120 = storage-provenance annotation (PREVIEW). Pinned by the frozen identity
    # corpus (sinks fixture: open_catalog_file / lookup_member).
    findings = _analyze(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def get_data():
            content = open('data.txt').read()
            return content
        """,
    )
    assert len(_rule(findings, "PY-WL-120")) == 1
    p101 = _rule(findings, "PY-WL-101")
    assert len(p101) == 1
    assert p101[0].properties["actual_return"] == TaintState.EXTERNAL_RAW.value


# ── 3. DB-cursor fetch coverage (advertised → real; wardline-e7c7cda31a) ─────


def test_cursor_fetchone_return_fires_with_external_raw_seed(tmp_path: Path) -> None:
    # Acceptance: cursor.fetchone() flowing to a return in a @trusted fn produces
    # the documented finding — the fetch* EXTERNAL_RAW seed substantiates the
    # storage provenance, so the 120 return arm fires (alongside 101's claim check).
    findings = _analyze(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def load_record(cursor):
            row = cursor.fetchone()
            return row
        """,
    )
    st = _rule(findings, "PY-WL-120")
    assert [f.qualname for f in st] == ["m.load_record"]
    assert st[0].properties["return_taint"] == TaintState.EXTERNAL_RAW.value
    p101 = _rule(findings, "PY-WL-101")
    assert len(p101) == 1
    assert p101[0].properties["actual_return"] == TaintState.EXTERNAL_RAW.value


def test_cursor_fetchone_to_trusted_callee_fires(tmp_path: Path) -> None:
    # Acceptance: cursor.fetchone() flowing to a trusted-callee sink fires the
    # 120 call arm (the arm PY-WL-101 does not cover).
    findings = _analyze(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def store(val):
            return 1

        @trusted(level='ASSURED')
        def load_record(cursor):
            row = cursor.fetchone()
            store(row)
        """,
    )
    st = _rule(findings, "PY-WL-120")
    assert [f.qualname for f in st] == ["m.load_record"]
    assert st[0].properties["callee"] == "m.store"
    assert st[0].properties["arg_taint"] == TaintState.EXTERNAL_RAW.value


def test_cursor_fetchmany_return_fires(tmp_path: Path) -> None:
    # fetchmany completes the advertised fetch{one,all,many} trio (fetchall is
    # pinned in test_wave3_deferred_rules.py).
    findings = _analyze(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def load_records(cursor):
            rows = cursor.fetchmany(5)
            return rows
        """,
    )
    st = _rule(findings, "PY-WL-120")
    assert [f.qualname for f in st] == ["m.load_records"]
    assert st[0].properties["return_taint"] == TaintState.EXTERNAL_RAW.value


def test_cursor_fetch_validated_stays_silent(tmp_path: Path) -> None:
    # CONTROL: laundering through a @trust_boundary clears both arms.
    findings = _analyze(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def load_record(cursor):
            row = cursor.fetchone()
            return validate(row)
        """,
    )
    assert _rule(findings, "PY-WL-120") == []
