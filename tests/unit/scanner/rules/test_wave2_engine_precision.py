"""Wave 2 — Engine Precision tests (WP7, WP8, WP8b).

Tests for:
- WP7 (Flow-Sensitive Call-Site Taint): ensures sinks evaluate arguments
  at their call-site taint, not their final flow-insensitive taint.
- WP8 (Cross-Module Call-Argument Taint): ensures call-site argument taints
  propagate cross-module to callee parameters, and PY-WL-105 catches
  cross-module violations.
- WP8b (Write-Site / Assignment Taint Tracking): captures external
  attribute writes (obj.attr = val) and associates them with class summaries.
"""

from __future__ import annotations

import textwrap
from collections.abc import Sequence
from pathlib import Path

from wardline.core.config import WardlineConfig
from wardline.core.finding import Finding, Kind
from wardline.scanner.analyzer import WardlineAnalyzer

# Shared file preamble. Line-number assertions below are expressed relative to
# _HEADER_LINES (wardline-e159060db7): adding a line here used to silently shift
# four absolute line-number assertions with no engine change.
_HEADER = (
    "from wardline.decorators import external_boundary, trust_boundary, trusted\n"
    "@external_boundary\ndef read_raw(p):\n    return p\n"
    "@trust_boundary(to_level='ASSURED')\n"
    "def validate(x):\n"
    "    if not x:\n        raise ValueError\n    return x\n"
)
_HEADER_LINES = _HEADER.count("\n")


def _analyze_files(tmp_path: Path, files: dict[str, str]) -> Sequence[Finding]:
    for name, content in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(_HEADER + textwrap.dedent(content), encoding="utf-8")

    analyzer = WardlineAnalyzer()
    file_paths = [tmp_path / name for name in files]
    findings = analyzer.analyze(file_paths, WardlineConfig(), root=tmp_path)
    return findings


# ── WP7: Flow-Sensitive Call-Site Taint ─────────────────────────────────────


def test_flow_sensitive_args_resolves_sinks_correctly(tmp_path: Path) -> None:
    # A single variable `x` is assigned to a raw value, passed to a sink (eval),
    # and then reassigned to a safe string and passed to a sink (eval).
    # The first eval should fire PY-WL-107, but the second should NOT.
    findings = _analyze_files(
        tmp_path,
        {
            "m.py": """
            @trusted(level='ASSURED')
            def test_flow(p):
                x = read_raw(p)
                eval(x)       # Should FIRE (line 14)
                x = 'safe_str'
                eval(x)       # Should NOT fire (line 16)
            """
        },
    )
    defects = [f for f in findings if f.kind is Kind.DEFECT]
    # Check that PY-WL-107 is raised, but only for the first eval.
    py_wl_107_findings = [f for f in defects if f.rule_id == "PY-WL-107"]
    assert len(py_wl_107_findings) == 1
    # Snippet line 5 (leading blank, @trusted, def, x=, eval) after the header.
    assert py_wl_107_findings[0].location.line_start == _HEADER_LINES + 5


def test_starred_args_and_kwargs_resolution_flow_sensitive(tmp_path: Path) -> None:
    # Test that `*args` and `**kwargs` are resolved without contaminating
    # parameters that Python's call binding already filled explicitly.
    findings = _analyze_files(
        tmp_path,
        {
            "m.py": """
            @trusted(level='ASSURED')
            def target(a, b, c=None):
                eval(a)  # Should FIRE (line 13)
                eval(b)  # Should NOT fire; *args is clean and cannot rebind a
                if c:
                    eval(c)  # Should NOT fire; c is explicitly keyword-filled
                return 1

            def test_starred(p):
                args = ('safe_b',)
                target(read_raw(p), *args, c='safe_c')
            """
        },
    )
    defects = [f for f in findings if f.kind is Kind.DEFECT]
    py_wl_107_findings = [f for f in defects if f.rule_id == "PY-WL-107"]
    assert len(py_wl_107_findings) == 1
    assert all(f.qualname == "m.target" for f in py_wl_107_findings)
    lines = sorted((f.location.line_start or 0) for f in py_wl_107_findings)
    # eval(a) is snippet line 4 (leading blank, @trusted, def, eval) after the header.
    assert lines == [_HEADER_LINES + 4]


def test_kwargs_unpack_only_taints_unfilled_keyword_capable_parameters(tmp_path: Path) -> None:
    findings = _analyze_files(
        tmp_path,
        {
            "m.py": """
            @trusted(level='ASSURED')
            def target(a, b, *rest, c=None, **extra):
                eval(a)  # Should NOT fire; explicitly safe positional
                eval(b)  # Should NOT fire; explicitly safe keyword
                if rest:
                    eval(rest)  # Should NOT fire; **kwargs cannot populate *rest
                if c:
                    eval(c)  # Should FIRE; **kwargs may populate c
                if extra:
                    eval(extra)  # Should FIRE; leftover **kwargs may populate extra
                return 1

            def test_kwargs(p):
                kwargs = {'c': read_raw(p)}
                target('safe_a', b='safe_b', **kwargs)
            """
        },
    )
    defects = [f for f in findings if f.kind is Kind.DEFECT]
    py_wl_107_findings = [f for f in defects if f.rule_id == "PY-WL-107" and f.qualname == "m.target"]
    lines = sorted((f.location.line_start or 0) for f in py_wl_107_findings)
    # eval(c) / eval(extra) are snippet lines 9 and 11 after the header.
    assert lines == [_HEADER_LINES + 9, _HEADER_LINES + 11]


# ── WP8: Cross-Module Call-Argument Taint ──────────────────────────────────


def test_cross_module_py_wl_105_fires(tmp_path: Path) -> None:
    # A trusted producer in one module is called with untrusted data from another module.
    # This should trigger PY-WL-105.
    findings = _analyze_files(
        tmp_path,
        {
            "producer.py": """
            @trusted(level='ASSURED')
            def store(data):
                return 1
            """,
            "caller.py": """
            from producer import store
            def run(p):
                store(read_raw(p))
            """,
        },
    )
    defects = [f for f in findings if f.kind is Kind.DEFECT]
    py_wl_105_findings = [f for f in defects if f.rule_id == "PY-WL-105"]
    assert len(py_wl_105_findings) == 1
    assert py_wl_105_findings[0].qualname == "caller.run"
    assert py_wl_105_findings[0].properties["callee"] == "producer.store"


def test_cross_module_parameter_seeding_propagates(tmp_path: Path) -> None:
    # A trusted helper function in one module accepts an argument and eval's it.
    # Another module calls this helper with raw untrusted data.
    # The helper's parameter should be seeded with the meet of all call sites (raw),
    # causing the eval inside the helper to trigger PY-WL-107.
    findings = _analyze_files(
        tmp_path,
        {
            "helper.py": """
            @trusted(level='ASSURED')
            def eval_helper(cmd):
                eval(cmd)
            """,
            "caller.py": """
            from helper import eval_helper
            def run(p):
                eval_helper(read_raw(p))
            """,
        },
    )
    defects = [f for f in findings if f.kind is Kind.DEFECT]
    py_wl_107_findings = [f for f in defects if f.rule_id == "PY-WL-107"]
    assert len(py_wl_107_findings) == 1
    assert py_wl_107_findings[0].qualname == "helper.eval_helper"


# ── WP8b: Write-Site / Assignment Taint Tracking ───────────────────────────


def test_external_attribute_write_propagates_to_class_attr_taint(tmp_path: Path) -> None:
    # obj = C()
    # obj.x = read_raw(p)
    # Inside class C, a trusted getter returns self.x.
    # This should trigger PY-WL-101.
    findings = _analyze_files(
        tmp_path,
        {
            "m.py": """
            class MyClass:
                def __init__(self):
                    self.x = 'safe_default'

                @trusted(level='ASSURED')
                def get_x(self):
                    return self.x

            def run_external_write(p):
                obj = MyClass()
                obj.x = read_raw(p)
            """
        },
    )
    defects = [f for f in findings if f.kind is Kind.DEFECT]
    py_wl_101_findings = [f for f in defects if f.rule_id == "PY-WL-101"]
    assert len(py_wl_101_findings) == 1
    assert py_wl_101_findings[0].qualname == "m.MyClass.get_x"


def test_external_attribute_write_copied_variable_type(tmp_path: Path) -> None:
    # Track constructor when assigned to a variable that is then copied:
    # obj = MyClass()
    # obj_alias = obj
    # obj_alias.x = read_raw(p)
    # Inside MyClass, get_x returns self.x (should fire PY-WL-101).
    findings = _analyze_files(
        tmp_path,
        {
            "m.py": """
            class MyClass:
                @trusted(level='ASSURED')
                def get_x(self):
                    return self.x

            def run_external_write(p):
                obj = MyClass()
                obj_alias = obj
                obj_alias.x = read_raw(p)
            """
        },
    )
    defects = [f for f in findings if f.kind is Kind.DEFECT]
    py_wl_101_findings = [f for f in defects if f.rule_id == "PY-WL-101"]
    assert len(py_wl_101_findings) == 1
    assert py_wl_101_findings[0].qualname == "m.MyClass.get_x"


def test_parameter_type_annotation_method_resolution(tmp_path: Path) -> None:
    # Test that parameter type annotations are parsed and used to resolve method calls.
    findings = _analyze_files(
        tmp_path,
        {
            "m.py": """
            class MyClass:
                def get_raw(self, p):
                    return read_raw(p)

            @trusted(level='ASSURED')
            def run(obj: MyClass, p):
                eval(obj.get_raw(p))
            """
        },
    )
    defects = [f for f in findings if f.kind is Kind.DEFECT]
    py_wl_107_findings = [f for f in defects if f.rule_id == "PY-WL-107"]
    assert len(py_wl_107_findings) == 1
    assert py_wl_107_findings[0].qualname == "m.run"
