"""PY-WL-126 — untrusted recipient/message reaches SMTP.sendmail (mail injection, CWE-93)."""

from __future__ import annotations

import textwrap
from pathlib import Path

from wardline.core.config import WardlineConfig
from wardline.core.finding import Kind, Severity
from wardline.scanner.analyzer import WardlineAnalyzer
from wardline.scanner.rules.untrusted_to_mail import UntrustedToMail

_HEADER = (
    "import smtplib\n"
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


def test_126_tainted_message_construct_then_method_fires_warn(tmp_path) -> None:
    ctx, _ = _analyze(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p):
            s = smtplib.SMTP('localhost')
            s.sendmail('from@example.com', 'to@example.com', read_raw(p))
            return 1
        """,
    )
    findings = UntrustedToMail().check(ctx)
    assert [(x.rule_id, x.qualname) for x in findings] == [("PY-WL-126", "m.f")]
    assert findings[0].kind == Kind.DEFECT
    assert findings[0].severity == Severity.WARN
    assert findings[0].properties["sink"] == "smtplib.SMTP.sendmail"


def test_126_tainted_recipient_fires(tmp_path) -> None:
    ctx, _ = _analyze(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p):
            s = smtplib.SMTP('localhost')
            s.sendmail('from@example.com', read_raw(p), 'body')
            return 1
        """,
    )
    assert [x.rule_id for x in UntrustedToMail().check(ctx)] == ["PY-WL-126"]


def test_126_with_statement_binding_fires(tmp_path) -> None:
    ctx, _ = _analyze(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p):
            with smtplib.SMTP('localhost') as s:
                s.sendmail('from@example.com', 'to@example.com', read_raw(p))
            return 1
        """,
    )
    assert [x.rule_id for x in UntrustedToMail().check(ctx)] == ["PY-WL-126"]


def test_126_smtp_ssl_fires(tmp_path) -> None:
    ctx, _ = _analyze(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p):
            s = smtplib.SMTP_SSL('localhost')
            s.sendmail('from@example.com', 'to@example.com', read_raw(p))
            return 1
        """,
    )
    assert [x.properties["sink"] for x in UntrustedToMail().check(ctx)] == ["smtplib.SMTP_SSL.sendmail"]


def test_126_literal_recipient_and_message_are_clean(tmp_path) -> None:
    ctx, _ = _analyze(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f():
            s = smtplib.SMTP('localhost')
            s.sendmail('from@example.com', 'to@example.com', 'body')
            return 1
        """,
    )
    assert UntrustedToMail().check(ctx) == []


def test_126_tainted_from_addr_only_is_clean(tmp_path) -> None:
    # Charter: recipient (to_addrs) + message are the CWE-93 injection slots;
    # from_addr alone is out of scope (documented calibration).
    ctx, _ = _analyze(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p):
            s = smtplib.SMTP('localhost')
            s.sendmail(read_raw(p), 'to@example.com', 'body')
            return 1
        """,
    )
    assert UntrustedToMail().check(ctx) == []


def test_126_undecorated_is_suppressed(tmp_path) -> None:
    ctx, _ = _analyze(
        tmp_path,
        """
        def f(p):
            s = smtplib.SMTP('localhost')
            s.sendmail('from@example.com', 'to@example.com', read_raw(p))
            return 1
        """,
    )
    assert UntrustedToMail().check(ctx) == []


def test_126_registered_end_to_end(tmp_path) -> None:
    _, findings = _analyze(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p):
            s = smtplib.SMTP('localhost')
            s.sendmail('from@example.com', 'to@example.com', read_raw(p))
            return 1
        """,
    )
    assert "PY-WL-126" in {f.rule_id for f in findings}
