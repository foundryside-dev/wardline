"""PY-WL-116 expansion (wardline-04b65cf0be + Zip Slip eval item) — empirical coverage.

Three sink families joining the path-traversal rule:

1. Filesystem-MUTATION sinks (``os.remove``/``shutil.rmtree``/...) — direct dotted
   calls with a tainted path argument (destructive traversal: delete/move/copy
   outside the intended directory).
2. Path-METHOD sinks — ``read_text``/``write_bytes``/... on a ``pathlib.Path``
   CONSTRUCTED from tainted input, both bound (``p = Path(raw); p.read_text()``)
   and chained (``pathlib.Path(raw).read_text()``), via the shared sink-binding
   machinery. The taint is read from the CONSTRUCTOR call's arguments.
3. Archive extraction (Zip Slip / tarbomb, CWE-22) — ``extractall``/``extract`` on
   a ``tarfile.open``/``tarfile.TarFile``/``zipfile.ZipFile`` instance whose
   ARCHIVE SOURCE is tainted; exempt when the call passes the tarfile safe filter
   ``filter="data"``.

Precision pins: constant paths (``os.remove('/var/log/x')``,
``Path('static.txt').read_text()``) stay silent; the freedom zone stays silent.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from wardline.core.config import WardlineConfig
from wardline.core.finding import Severity
from wardline.scanner.analyzer import WardlineAnalyzer

_HEADER = (
    "import os, os.path, shutil, pathlib, tarfile, zipfile\n"
    "from pathlib import Path\n"
    "from wardline.decorators import external_boundary, trusted\n"
    "@external_boundary\n"
    "def read_raw(p):\n"
    "    return p\n"
)


def _pt_findings(tmp_path: Path, src: str):
    p = tmp_path / "m.py"
    p.write_text(_HEADER + textwrap.dedent(src), encoding="utf-8")
    analyzer = WardlineAnalyzer()
    findings = analyzer.analyze([p], WardlineConfig(), root=tmp_path)
    return [f for f in findings if f.rule_id == "PY-WL-116"]


def _sinks(findings) -> set[str]:
    return {f.properties["sink"] for f in findings if f.properties}


# ── 1. Filesystem-mutation sinks (direct dotted calls) ─────────────────────


@pytest.mark.parametrize(
    "call",
    [
        "os.remove(read_raw(p))",
        "os.unlink(read_raw(p))",
        "os.rmdir(read_raw(p))",
        "os.makedirs(read_raw(p))",
        "os.mkdir(read_raw(p))",
        "os.rename(read_raw(p), '/dst')",
        "os.renames(read_raw(p), '/dst')",
        "os.replace(read_raw(p), '/dst')",
        "shutil.rmtree(read_raw(p))",
        "shutil.copy(read_raw(p), '/dst')",
        "shutil.copy2(read_raw(p), '/dst')",
        "shutil.copyfile(read_raw(p), '/dst')",
        "shutil.copytree(read_raw(p), '/dst')",
        "shutil.move(read_raw(p), '/dst')",
    ],
)
def test_fs_mutation_sink_fires_on_tainted_path(tmp_path: Path, call: str) -> None:
    findings = _pt_findings(
        tmp_path,
        f"""
        @trusted(level='ASSURED')
        def f(p):
            {call}
        """,
    )
    assert len(findings) == 1
    assert findings[0].qualname == "m.f"
    assert findings[0].severity == Severity.WARN


def test_fs_mutation_tainted_destination_also_fires(tmp_path: Path) -> None:
    # Worst-of-all-args: a tainted DESTINATION is traversal too (write outside the dir).
    findings = _pt_findings(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p):
            shutil.copy('/etc/app.conf', read_raw(p))
        """,
    )
    assert _sinks(findings) == {"shutil.copy"}


def test_fs_mutation_constant_path_is_silent(tmp_path: Path) -> None:
    findings = _pt_findings(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f():
            os.remove('/var/log/app.log')
            shutil.rmtree('/tmp/scratch')
        """,
    )
    assert findings == []


def test_fs_mutation_freedom_zone_is_silent(tmp_path: Path) -> None:
    findings = _pt_findings(
        tmp_path,
        """
        def f(p):
            os.remove(read_raw(p))
        """,
    )
    assert findings == []


def test_os_open_tainted_path_fires(tmp_path: Path) -> None:
    # os.open is a declared _SINKS member with no dedicated positive
    # (wardline-e159060db7) — a silent drop from the table would go undetected.
    findings = _pt_findings(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p):
            os.open(read_raw(p), os.O_RDONLY)
        """,
    )
    assert [(x.rule_id, x.qualname, x.severity) for x in findings] == [("PY-WL-116", "m.f", Severity.WARN)]


def test_pathlib_path_constructor_tainted_fires(tmp_path: Path) -> None:
    # The bare pathlib.Path(...) CONSTRUCTOR is itself a declared sink (distinct
    # from the construct-then-method shapes below) — pin it individually.
    findings = _pt_findings(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p):
            pathlib.Path(read_raw(p))
        """,
    )
    assert [(x.rule_id, x.qualname, x.severity) for x in findings] == [("PY-WL-116", "m.f", Severity.WARN)]


# ── 2. Path-method sinks (construct-then-method via the binding machinery) ──


def test_bound_path_read_text_fires(tmp_path: Path) -> None:
    findings = _pt_findings(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p):
            q = pathlib.Path(read_raw(p))
            return q.read_text()
        """,
    )
    # The tainted CONSTRUCTOR still fires (existing sink) and the method adds its own.
    assert _sinks(findings) == {"pathlib.Path", "pathlib.Path.read_text"}
    method = next(f for f in findings if f.properties["sink"] == "pathlib.Path.read_text")
    assert method.severity == Severity.WARN
    assert method.qualname == "m.f"


def test_chained_path_read_bytes_fires(tmp_path: Path) -> None:
    findings = _pt_findings(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p):
            return pathlib.Path(read_raw(p)).read_bytes()
        """,
    )
    assert "pathlib.Path.read_bytes" in _sinks(findings)


def test_from_import_alias_path_write_text_fires(tmp_path: Path) -> None:
    findings = _pt_findings(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p):
            q = Path(read_raw(p))
            q.write_text('payload')
        """,
    )
    assert "pathlib.Path.write_text" in _sinks(findings)


@pytest.mark.parametrize("method", ["write_bytes", "open", "unlink", "rmdir", "mkdir"])
def test_bound_path_method_family_fires(tmp_path: Path, method: str) -> None:
    findings = _pt_findings(
        tmp_path,
        f"""
        @trusted(level='ASSURED')
        def f(p):
            q = Path(read_raw(p))
            q.{method}()
        """,
    )
    assert f"pathlib.Path.{method}" in _sinks(findings)


def test_static_path_methods_are_silent(tmp_path: Path) -> None:
    findings = _pt_findings(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f():
            q = Path('static.txt')
            q.read_text()
            Path('static.txt').read_bytes()
        """,
    )
    assert findings == []


def test_method_on_non_path_instance_is_silent(tmp_path: Path) -> None:
    # A var bound to some other constructor must not match the Path method sinks.
    findings = _pt_findings(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p):
            c = compute(read_raw(p))
            return c.read_text()
        """,
    )
    assert findings == []


def test_rebound_path_resolves_at_final_binding(tmp_path: Path) -> None:
    # Last-binding-wins (machinery contract): tainted Path rebound to a constant
    # Path before the method call — the method must not fire on the stale ctor.
    findings = _pt_findings(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p):
            q = Path(read_raw(p))
            q = Path('static.txt')
            return q.read_text()
        """,
    )
    assert _sinks(findings) == {"pathlib.Path"}  # only the tainted ctor itself


# ── 3. Archive extraction (Zip Slip / tarbomb) ──────────────────────────────


def test_tarfile_bound_extractall_fires_and_names_archive_extraction(tmp_path: Path) -> None:
    findings = _pt_findings(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p):
            tf = tarfile.open(read_raw(p))
            tf.extractall('/dst')
        """,
    )
    assert _sinks(findings) == {"tarfile.open.extractall"}
    assert "archive extraction" in findings[0].message
    assert findings[0].severity == Severity.WARN


def test_tarfile_with_binding_extract_fires(tmp_path: Path) -> None:
    findings = _pt_findings(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p, member):
            with tarfile.open(read_raw(p)) as tf:
                tf.extract(member, '/dst')
        """,
    )
    assert "tarfile.open.extract" in _sinks(findings)


def test_zipfile_chained_extractall_fires(tmp_path: Path) -> None:
    findings = _pt_findings(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p):
            zipfile.ZipFile(read_raw(p)).extractall()
        """,
    )
    assert _sinks(findings) == {"zipfile.ZipFile.extractall"}


def test_zipfile_bound_extract_fires(tmp_path: Path) -> None:
    findings = _pt_findings(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p):
            zf = zipfile.ZipFile(read_raw(p))
            zf.extract('member.txt')
        """,
    )
    assert "zipfile.ZipFile.extract" in _sinks(findings)


def test_tarfile_class_constructor_extractall_fires(tmp_path: Path) -> None:
    findings = _pt_findings(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p):
            tf = tarfile.TarFile(read_raw(p))
            tf.extractall('/dst')
        """,
    )
    assert "tarfile.TarFile.extractall" in _sinks(findings)


def test_data_filter_exempts_extraction(tmp_path: Path) -> None:
    # filter="data" is tarfile's safe extraction filter (blocks absolute paths,
    # ../ traversal, devices) — the documented mitigation, so no finding.
    findings = _pt_findings(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p):
            tf = tarfile.open(read_raw(p))
            tf.extractall('/dst', filter='data')
        """,
    )
    assert findings == []


def test_non_data_filter_still_fires(tmp_path: Path) -> None:
    # Only the "data" filter is the documented exemption; "fully_trusted" is unsafe.
    findings = _pt_findings(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p):
            tf = tarfile.open(read_raw(p))
            tf.extractall('/dst', filter='fully_trusted')
        """,
    )
    assert _sinks(findings) == {"tarfile.open.extractall"}


def test_constant_archive_source_is_silent(tmp_path: Path) -> None:
    # v1 scope decision: the rule keys on the ARCHIVE SOURCE; a tainted
    # destination with a trusted archive does not fire this family.
    findings = _pt_findings(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p):
            tf = tarfile.open('bundled.tar')
            tf.extractall('/dst')
        """,
    )
    assert findings == []


# ── Fingerprint discipline (multi_emit discriminator) ───────────────────────


def test_co_located_method_and_ctor_findings_have_distinct_fingerprints(tmp_path: Path) -> None:
    # The chained form emits both the ctor and the method finding on ONE line —
    # the taint_path discriminator (span + sink name) must separate them.
    findings = _pt_findings(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p):
            return pathlib.Path(read_raw(p)).read_text()
        """,
    )
    assert _sinks(findings) == {"pathlib.Path", "pathlib.Path.read_text"}
    fps = [f.fingerprint for f in findings]
    assert len(fps) == len(set(fps))
