"""PY-WL-125 — untrusted data as a log MESSAGE (log injection, CWE-117)."""

from __future__ import annotations

import textwrap
from pathlib import Path

from wardline.core.config import WardlineConfig
from wardline.core.finding import Kind, Severity
from wardline.scanner.analyzer import WardlineAnalyzer
from wardline.scanner.rules.untrusted_to_log import UntrustedToLog

_HEADER = (
    "import logging\n"
    "from wardline.decorators import external_boundary, trusted\n"
    "@external_boundary\n"
    "def read_raw(p):\n"
    "    return p\n"
)


def _analyze(tmp_path: Path, src: str):
    p = tmp_path / "m.py"
    p.write_text(_HEADER + textwrap.dedent(src), encoding="utf-8")
    analyzer = WardlineAnalyzer()
    findings = analyzer.analyze([p], WardlineConfig(), root=tmp_path)
    assert analyzer.last_context is not None
    return analyzer.last_context, list(findings)


def test_125_module_level_logging_tainted_message_fires_info(tmp_path) -> None:
    ctx, _ = _analyze(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p):
            logging.info(read_raw(p))
            return 1
        """,
    )
    findings = UntrustedToLog().check(ctx)
    assert [(x.rule_id, x.qualname) for x in findings] == [("PY-WL-125", "m.f")]
    assert findings[0].kind == Kind.DEFECT
    # Calibrated INFO: log forging is real but noisy by nature — advisory, never gate-tripping.
    assert findings[0].severity == Severity.INFO


def test_125_all_module_level_methods_fire(tmp_path) -> None:
    ctx, _ = _analyze(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p):
            logging.debug(read_raw(p))
            logging.warning(read_raw(p))
            logging.error(read_raw(p))
            logging.critical(read_raw(p))
            logging.exception(read_raw(p))
            return 1
        """,
    )
    assert len(UntrustedToLog().check(ctx)) == 5


def test_125_logger_instance_method_fires(tmp_path) -> None:
    # construct-then-method: the getLogger(...) binding resolves logger.warning.
    ctx, _ = _analyze(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p):
            logger = logging.getLogger('app')
            logger.warning(read_raw(p))
            return 1
        """,
    )
    assert [x.properties["sink"] for x in UntrustedToLog().check(ctx)] == ["logging.getLogger.warning"]


def test_125_parameterized_logging_is_the_clean_idiom(tmp_path) -> None:
    # Tainted data in the lazy %-args position is logging's SAFE parameterization —
    # firing on it would be an FP factory. Only the message FORMAT string counts.
    ctx, _ = _analyze(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p):
            logging.info('user input = %s', read_raw(p))
            return 1
        """,
    )
    assert UntrustedToLog().check(ctx) == []


def test_125_literal_message_is_clean(tmp_path) -> None:
    ctx, _ = _analyze(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f():
            logging.error('fixed message')
            return 1
        """,
    )
    assert UntrustedToLog().check(ctx) == []


def test_125_undecorated_is_suppressed(tmp_path) -> None:
    ctx, _ = _analyze(
        tmp_path,
        """
        def f(p):
            logging.info(read_raw(p))
            return 1
        """,
    )
    assert UntrustedToLog().check(ctx) == []


def test_125_registered_end_to_end(tmp_path) -> None:
    _, findings = _analyze(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p):
            logging.info(read_raw(p))
            return 1
        """,
    )
    assert "PY-WL-125" in {f.rule_id for f in findings}
