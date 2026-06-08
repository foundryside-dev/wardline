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
from wardline.core.finding import Finding, Kind, Severity
from wardline.core.taints import TaintState
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


# ── PY-WL-118 regression: **kwargs dict-unpacking gate (wardline-8c31463f9f) ──


def test_sql_injection_fires_on_kwargs_operation(tmp_path: Path) -> None:
    # A tainted SQL operation passed via ``**{"operation": ...}`` collapses to the engine's
    # ``None`` (``**kwargs``) arg-key. The narrowed _SQL_STRING_KEYS gate ignored ``None``, so
    # this FN slipped past the FP fix (wardline-8c31463f9f). The literal-dict key ("operation")
    # is in the SQL-string slot, so 118 must fire.
    findings = _analyze_files(
        tmp_path,
        {
            "m.py": """
            @trusted(level='ASSURED')
            def q(p, cursor):
                cursor.execute(**{"operation": read_raw(p)})
            """
        },
    )
    sqli = [f for f in findings if f.kind is Kind.DEFECT and f.rule_id == "PY-WL-118"]
    assert len(sqli) == 1
    assert sqli[0].qualname == "m.q"


def test_sql_injection_fires_on_kwargs_sql(tmp_path: Path) -> None:
    findings = _analyze_files(
        tmp_path,
        {
            "m.py": """
            @trusted(level='ASSURED')
            def q(p, cursor):
                cursor.execute(**{"sql": read_raw(p)})
            """
        },
    )
    sqli = [f for f in findings if f.kind is Kind.DEFECT and f.rule_id == "PY-WL-118"]
    assert len(sqli) == 1


def test_sql_injection_kwargs_parameters_only_does_not_fire(tmp_path: Path) -> None:
    # Preserves the parameterized-query FP fix (wardline-e0e44852e7) for the ``**kwargs`` shape:
    # a literal dict that provably targets only the bound-parameter slot ("parameters") — never
    # the SQL string — is not SQLi and must stay silent.
    findings = _analyze_files(
        tmp_path,
        {
            "m.py": """
            @trusted(level='ASSURED')
            def q(p, cursor):
                cursor.execute(**{"parameters": read_raw(p)})
            """
        },
    )
    sqli = [f for f in findings if f.kind is Kind.DEFECT and f.rule_id == "PY-WL-118"]
    assert sqli == []


def test_sql_injection_opaque_kwargs_fails_closed(tmp_path: Path) -> None:
    # An opaque ``**`` unpack (not a static literal dict) cannot be split into operation-vs-params,
    # so a raw-tier value reaching it is treated as potentially the SQL string — fail closed, fire.
    findings = _analyze_files(
        tmp_path,
        {
            "m.py": """
            @trusted(level='ASSURED')
            def q(p, cursor):
                cursor.execute(**read_raw(p))
            """
        },
    )
    sqli = [f for f in findings if f.kind is Kind.DEFECT and f.rule_id == "PY-WL-118"]
    assert len(sqli) == 1


def test_sql_injection_fires_on_execute_inside_lambda(tmp_path: Path) -> None:
    # PY-WL-118 must inspect sink calls inside LAMBDA bodies, matching its sink-family siblings
    # (PY-WL-106/107/108 descend into lambdas via _own_calls). It previously walked own_nodes,
    # which treats ast.Lambda as a scope boundary, so a tainted execute() in a lambda silently
    # escaped — a real SQLi FN. Attribution is to the enclosing entity (as the siblings do).
    findings = _analyze_files(
        tmp_path,
        {
            "m.py": """
            @trusted(level='ASSURED')
            def f(p, cursor):
                run = lambda: cursor.execute(read_raw(p))
                return run
            """
        },
    )
    sqli = [f for f in findings if f.kind is Kind.DEFECT and f.rule_id == "PY-WL-118"]
    assert len(sqli) == 1
    assert sqli[0].qualname == "m.f"
    assert sqli[0].severity is Severity.ERROR


def test_sql_injection_fires_on_kwargs_operation_inside_lambda(tmp_path: Path) -> None:
    # The bug-1 **kwargs gate and the lambda-descent fix compose: a tainted ** operation inside
    # a lambda body must fire.
    findings = _analyze_files(
        tmp_path,
        {
            "m.py": """
            @trusted(level='ASSURED')
            def f(p, cursor):
                run = lambda: cursor.execute(**{"operation": read_raw(p)})
                return run
            """
        },
    )
    sqli = [f for f in findings if f.kind is Kind.DEFECT and f.rule_id == "PY-WL-118"]
    assert len(sqli) == 1


def test_sql_injection_lambda_bound_parameter_stays_silent(tmp_path: Path) -> None:
    # Descending into lambdas must not break the bound-parameter FP fix (wardline-e0e44852e7):
    # a clean SQL string with the untrusted value only in the parameter position stays silent
    # even inside a lambda.
    findings = _analyze_files(
        tmp_path,
        {
            "m.py": """
            @trusted(level='ASSURED')
            def f(p, cursor):
                run = lambda: cursor.execute("SELECT * FROM t WHERE id = ?", (read_raw(p),))
                return run
            """
        },
    )
    sqli = [f for f in findings if f.kind is Kind.DEFECT and f.rule_id == "PY-WL-118"]
    assert sqli == []


def test_sql_injection_kwargs_mixed_literal_overfires_failclosed(tmp_path: Path) -> None:
    # KNOWN, INTENDED fail-closed over-approximation: the engine collapses every ``**``-dict
    # value into ONE worst-taint under the ``None`` key, so a literal dict that puts a clean
    # value in the SQL-string slot ("operation") and the tainted value in the bound-parameter
    # slot ("parameters") cannot be attributed per-key. Because an SQL-string key IS present and
    # the ``**`` region carries raw taint, the gate fires (over-approximation, never an FN). The
    # precise per-key attribution is engine-level work tracked as expansion backlog.
    findings = _analyze_files(
        tmp_path,
        {
            "m.py": """
            @trusted(level='ASSURED')
            def q(p, cursor):
                cursor.execute(**{"operation": "SELECT 1", "parameters": read_raw(p)})
            """
        },
    )
    sqli = [f for f in findings if f.kind is Kind.DEFECT and f.rule_id == "PY-WL-118"]
    assert len(sqli) == 1


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


def test_sql_injection_nested_own_trusted_decorator_under_undecorated_parent_fires(tmp_path: Path) -> None:
    # Regression wardline-bb8396f96e: the unconditional ``.<locals>.`` strip made a nested def
    # inherit its parent's tier even when the nested def carries its OWN trust decorator. Here
    # the parent is undecorated (UNKNOWN_RAW); the nested ``inner`` is @trusted in its own right,
    # so its tier — not the parent's — governs, and the real SQLi must fire.
    findings = _analyze_files(
        tmp_path,
        {
            "m.py": """
            def outer(p, cursor):
                @trusted(level='ASSURED')
                def inner(q, cursor):
                    cursor.execute(read_raw(q))
                return inner
            """
        },
    )
    defects = [f for f in findings if f.kind is Kind.DEFECT]
    sqli = [f for f in defects if f.rule_id == "PY-WL-118"]
    assert len(sqli) == 1
    assert sqli[0].qualname == "m.outer.<locals>.inner"
    assert sqli[0].severity is Severity.ERROR


def test_sql_injection_nested_own_trusted_under_external_boundary_parent_fires(tmp_path: Path) -> None:
    # Regression wardline-bb8396f96e, case B: parent is @external_boundary (EXTERNAL_RAW, which
    # modulates to NONE). The nested @trusted ``inner`` must use its OWN tier and fire at ERROR
    # rather than inheriting the suppressed parent tier.
    findings = _analyze_files(
        tmp_path,
        {
            "m.py": """
            @external_boundary
            def outer(p, cursor):
                @trusted(level='ASSURED')
                def inner(q, cursor):
                    cursor.execute(read_raw(q))
                return inner
            """
        },
    )
    defects = [f for f in findings if f.kind is Kind.DEFECT]
    sqli = [f for f in defects if f.rule_id == "PY-WL-118"]
    assert len(sqli) == 1
    assert sqli[0].qualname == "m.outer.<locals>.inner"
    assert sqli[0].severity is Severity.ERROR


def test_sql_injection_double_nested_undecorated_inherits_trusted_tier(tmp_path: Path) -> None:
    # Preserves wardline-9b88ec5419 at depth: two levels of UNDECORATED nesting inside a @trusted
    # outer must still inherit the outer's tier (walk-outward to the nearest DECLARED scope), so
    # the leaf sink fires.
    findings = _analyze_files(
        tmp_path,
        {
            "m.py": """
            @trusted(level='ASSURED')
            def deep(p, cursor):
                def mid(q):
                    def leaf(r):
                        cursor.execute(read_raw(r))
                    return leaf
                return mid
            """
        },
    )
    defects = [f for f in findings if f.kind is Kind.DEFECT]
    sqli = [f for f in defects if f.rule_id == "PY-WL-118"]
    assert len(sqli) == 1
    assert sqli[0].qualname == "m.deep.<locals>.mid.<locals>.leaf"


def test_exec_sink_nested_own_trusted_under_undecorated_parent_fires(tmp_path: Path) -> None:
    # Family-wide coverage: the same nested-own-decorator fix lives in the shared TaintedSinkRule
    # base (_sink_helpers), so a non-118 sink rule (PY-WL-107, eval) must also honor a nested
    # def's own @trusted decorator under an undecorated parent.
    findings = _analyze_files(
        tmp_path,
        {
            "m.py": """
            def outer(p):
                @trusted(level='ASSURED')
                def inner(q):
                    eval(read_raw(q))
                return inner
            """
        },
    )
    defects = [f for f in findings if f.kind is Kind.DEFECT]
    exec_findings = [f for f in defects if f.rule_id == "PY-WL-107"]
    assert len(exec_findings) == 1
    assert exec_findings[0].qualname == "m.outer.<locals>.inner"


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


def test_stored_taint_cursor_fetch_reaches_return_fires(tmp_path: Path) -> None:
    # wardline-e7c7cda31a: PY-WL-120 was a dead branch for DB-cursor fetches — the matcher
    # matched fetchall() but the result was never seeded raw. Seeding fetch{one,all,many}
    # EXTERNAL_RAW makes a @trusted fn that returns unvalidated rows fire PY-WL-120.
    findings = _analyze_files(
        tmp_path,
        {
            "m.py": """
            @trusted(level='ASSURED')
            def get_rows(cursor):
                rows = cursor.fetchall()
                return rows
            """
        },
    )
    st = [f for f in findings if f.kind is Kind.DEFECT and f.rule_id == "PY-WL-120"]
    assert [f.qualname for f in st] == ["m.get_rows"]
    # wardline-obs-638a5d9fd1: pin the resolved tier for a DB-cursor read. The PY-WL-101
    # finding on the same producer must classify actual_return as EXTERNAL_RAW (DB read is
    # external/stored data, like open()/read_text()), DETERMINISTICALLY — not the old
    # fail-closed UNKNOWN_RAW the dead-branch fallback produced. This locks the storage-read
    # seed's end-to-end return tier so the "tier drift" observation cannot recur.
    p101 = [f for f in findings if f.rule_id == "PY-WL-101" and f.qualname == "m.get_rows"]
    assert len(p101) == 1, p101
    assert p101[0].properties["actual_return"] == TaintState.EXTERNAL_RAW.value


def test_stored_taint_cursor_fetch_validated_stays_silent(tmp_path: Path) -> None:
    # FP guard: fetch then VALIDATE through a @trust_boundary before returning launders the
    # return to ASSURED (outside RAW_ZONE) — must not fire PY-WL-120.
    findings = _analyze_files(
        tmp_path,
        {
            "m.py": """
            @trusted(level='ASSURED')
            def get_rows(cursor):
                rows = cursor.fetchall()
                return validate(rows)
            """
        },
    )
    st = [f for f in findings if f.kind is Kind.DEFECT and f.rule_id == "PY-WL-120" and f.qualname == "m.get_rows"]
    assert st == []


def test_stored_taint_cursor_fetch_constant_return_stays_silent(tmp_path: Path) -> None:
    # FP guard: fetching then returning a constant (rows don't flow out) stays silent.
    findings = _analyze_files(
        tmp_path,
        {
            "m.py": """
            @trusted(level='ASSURED')
            def get_rows(cursor):
                rows = cursor.fetchall()
                return 42
            """
        },
    )
    st = [f for f in findings if f.kind is Kind.DEFECT and f.rule_id == "PY-WL-120" and f.qualname == "m.get_rows"]
    assert st == []


def test_stored_taint_branch_conditional_trusted_callee_fires_regardless_of_ast_order(tmp_path: Path) -> None:
    # wardline-499c22bbdd (PY-WL-120 candidate-set consumer): stored rows passed to a
    # branch-conditional receiver whose trusted-sink candidate is the AST-FIRST arm must
    # still fire — the candidate set is consulted, not just the AST-last single callee.
    src_tmpl = """
        class Plain:
            def take(self, x):
                return 1
        class TrustedSink:
            @trusted(level='ASSURED')
            def take(self, x):
                return 1
        @trusted(level='ASSURED')
        def f(cursor, flag):
            rows = cursor.fetchall()
            if flag:
                o = {first}
            else:
                o = {second}
            o.take(rows)
        """
    for first, second in (("TrustedSink()", "Plain()"), ("Plain()", "TrustedSink()")):
        findings = _analyze_files(tmp_path, {"m.py": src_tmpl.format(first=first, second=second)})
        st = [f for f in findings if f.kind is Kind.DEFECT and f.rule_id == "PY-WL-120" and f.qualname == "m.f"]
        assert len(st) == 1, (first, second, st)


def test_stored_taint_branch_conditional_neither_trusted_stays_silent(tmp_path: Path) -> None:
    # CONTROL: two candidate receivers, neither a trusted sink — must stay silent.
    findings = _analyze_files(
        tmp_path,
        {
            "m.py": """
            class Plain:
                def take(self, x):
                    return 1
            class Plain2:
                def take(self, x):
                    return 1
            @trusted(level='ASSURED')
            def f(cursor, flag):
                rows = cursor.fetchall()
                if flag:
                    o = Plain()
                else:
                    o = Plain2()
                o.take(rows)
            """
        },
    )
    st = [f for f in findings if f.kind is Kind.DEFECT and f.rule_id == "PY-WL-120" and f.qualname == "m.f"]
    assert st == []


def test_stored_taint_two_trusted_candidates_emits_one_finding(tmp_path: Path) -> None:
    # panel-2 (wardline-499c22bbdd): PY-WL-120 carries its own one-finding-per-call-site
    # collapse. When BOTH branch arms are trusted sinks, stored rows reaching the dispatch
    # is ONE defect — assert exactly one finding with the "also reaches" annotation.
    findings = _analyze_files(
        tmp_path,
        {
            "m.py": """
            class A:
                @trusted(level='ASSURED')
                def take(self, x):
                    return 1
            class B:
                @trusted(level='ASSURED')
                def take(self, x):
                    return 1
            @trusted(level='ASSURED')
            def f(cursor, flag):
                rows = cursor.fetchall()
                if flag:
                    o = A()
                else:
                    o = B()
                o.take(rows)
            """
        },
    )
    st = [f for f in findings if f.kind is Kind.DEFECT and f.rule_id == "PY-WL-120" and f.qualname == "m.f"]
    assert len(st) == 1, st
    assert "also reaches" in st[0].message
