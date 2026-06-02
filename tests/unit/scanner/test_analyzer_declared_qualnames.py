# tests/unit/scanner/test_analyzer_declared_qualnames.py
"""TDD: AnalysisContext.declared_qualnames surfaces the trust surface (anchored entities).

The field collects qualnames whose L1 seed came from a trust DECLARATION (a
decorator, ``FunctionSeed.source == "provider"``); plain unannotated functions
are excluded.  This is the coverage-denominator consumed by ``core/assure.py``.
"""

from wardline.core.run import run_scan


def test_declared_qualnames_lists_only_anchored(tmp_path):
    (tmp_path / "m.py").write_text(
        "from wardline.decorators.trust import trusted, external_boundary\n"
        "@trusted(level='INTEGRAL')\n"
        "def good():\n    return 1\n"
        "@external_boundary\n"
        "def src():\n    return input()\n"
        "def plain():\n    return 2\n"
    )
    result = run_scan(tmp_path)
    assert result.context is not None
    assert result.context.declared_qualnames == frozenset({"m.good", "m.src"})
