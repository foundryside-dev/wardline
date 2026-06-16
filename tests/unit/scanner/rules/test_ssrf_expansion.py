# tests/unit/scanner/rules/test_ssrf_expansion.py
"""PY-WL-117 SSRF expansion — wardline-3002f63969 / wardline-66b2c91470.

Pins three directions:
  1. Construct-then-method sinks (the dominant real-world shape): methods on a
     constructed ``httpx.Client``/``AsyncClient`` (incl. ``async with``),
     ``requests.Session()``, and ``aiohttp.ClientSession``.
  2. Module-level gaps: ``requests.head``/``requests.options`` and
     ``urllib.request.Request`` (the constructor carries the tainted URL).
  3. Arg-position precision: only the URL slot (and ``base_url=`` on client
     constructors) drives the verdict — a tainted ``timeout=``/``headers=``/
     ``verify=`` with a clean literal URL is NOT an SSRF vector.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

from wardline.core.config import WardlineConfig
from wardline.core.finding import Finding, Kind, Severity
from wardline.scanner.analyzer import WardlineAnalyzer

_HEADER = (
    "import requests\n"
    "import httpx\n"
    "import aiohttp\n"
    "import urllib.request\n"
    "from wardline.decorators import external_boundary, trusted\n"
    "@external_boundary\n"
    "def read_raw(p):\n"
    "    return p\n"
)


def _ssrf(tmp_path: Path, src: str) -> list[Finding]:
    p = tmp_path / "m.py"
    p.write_text(_HEADER + textwrap.dedent(src), encoding="utf-8")
    findings = WardlineAnalyzer().analyze([p], WardlineConfig(), root=tmp_path)
    return [f for f in findings if f.rule_id == "PY-WL-117" and f.kind is Kind.DEFECT]


# ── 1. construct-then-method ───────────────────────────────────────────────


def test_117_httpx_client_construct_then_get_fires(tmp_path: Path) -> None:
    findings = _ssrf(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p):
            client = httpx.Client()
            client.get(read_raw(p))
        """,
    )
    assert [(f.qualname, f.properties["sink"]) for f in findings] == [("m.f", "httpx.Client.get")]
    assert findings[0].severity is Severity.WARN


def test_117_httpx_async_with_client_fires(tmp_path: Path) -> None:
    findings = _ssrf(
        tmp_path,
        """
        @trusted(level='ASSURED')
        async def fetch(p):
            async with httpx.AsyncClient() as client:
                await client.get(read_raw(p))
        """,
    )
    assert [f.properties["sink"] for f in findings] == ["httpx.AsyncClient.get"]


def test_117_requests_session_chained_fires(tmp_path: Path) -> None:
    findings = _ssrf(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p):
            requests.Session().get(read_raw(p))
        """,
    )
    assert [f.properties["sink"] for f in findings] == ["requests.Session.get"]


def test_117_requests_session_var_post_fires(tmp_path: Path) -> None:
    findings = _ssrf(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p):
            s = requests.Session()
            s.post(read_raw(p))
        """,
    )
    assert [f.properties["sink"] for f in findings] == ["requests.Session.post"]


def test_117_aiohttp_session_method_fires(tmp_path: Path) -> None:
    findings = _ssrf(
        tmp_path,
        """
        @trusted(level='ASSURED')
        async def fetch(p):
            async with aiohttp.ClientSession() as session:
                await session.get(read_raw(p))
        """,
    )
    assert [f.properties["sink"] for f in findings] == ["aiohttp.ClientSession.get"]


def test_117_client_request_tainted_url_position_fires(tmp_path: Path) -> None:
    # client.request(method, url): the URL is the SECOND slot.
    findings = _ssrf(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p):
            client = httpx.Client()
            client.request("GET", read_raw(p))
        """,
    )
    assert [f.properties["sink"] for f in findings] == ["httpx.Client.request"]


def test_117_client_request_tainted_method_verb_does_not_fire(tmp_path: Path) -> None:
    # A tainted method VERB with a clean literal URL cannot redirect the request target.
    findings = _ssrf(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p):
            client = httpx.Client()
            client.request(read_raw(p), "https://safe.example")
        """,
    )
    assert findings == []


def test_117_client_stream_fires(tmp_path: Path) -> None:
    findings = _ssrf(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p):
            with httpx.Client() as client:
                client.stream("GET", read_raw(p))
        """,
    )
    assert [f.properties["sink"] for f in findings] == ["httpx.Client.stream"]


# ── 2. module-level gaps ───────────────────────────────────────────────────


def test_117_requests_head_and_options_fire(tmp_path: Path) -> None:
    findings = _ssrf(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p):
            requests.head(read_raw(p))
            requests.options(read_raw(p))
        """,
    )
    assert [f.properties["sink"] for f in findings] == ["requests.head", "requests.options"]


def test_117_urllib_request_request_constructor_fires(tmp_path: Path) -> None:
    findings = _ssrf(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p):
            req = urllib.request.Request(read_raw(p))
            return req
        """,
    )
    assert [f.properties["sink"] for f in findings] == ["urllib.request.Request"]


def test_117_module_level_requests_get_stays_green(tmp_path: Path) -> None:
    findings = _ssrf(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p):
            requests.get(read_raw(p))
        """,
    )
    assert [f.properties["sink"] for f in findings] == ["requests.get"]


# ── 3. arg-position precision ──────────────────────────────────────────────


def test_117_tainted_non_url_kwargs_clean_url_do_not_fire(tmp_path: Path) -> None:
    findings = _ssrf(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p):
            requests.get('https://safe.example', timeout=read_raw(p))
            requests.get('https://safe.example', verify=read_raw(p))
            requests.get('https://safe.example', headers=read_raw(p))
        """,
    )
    assert findings == []


def test_117_tainted_url_keyword_fires(tmp_path: Path) -> None:
    findings = _ssrf(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p):
            requests.get(url=read_raw(p), timeout=5)
        """,
    )
    assert [f.properties["sink"] for f in findings] == ["requests.get"]


def test_117_httpx_client_ctor_tainted_timeout_does_not_fire(tmp_path: Path) -> None:
    findings = _ssrf(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p):
            httpx.Client(timeout=read_raw(p))
        """,
    )
    assert findings == []


def test_117_httpx_client_ctor_tainted_first_positional_does_not_fire(tmp_path: Path) -> None:
    # httpx.Client()'s first positional is not a URL; base_url is keyword-only.
    findings = _ssrf(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p):
            httpx.Client(read_raw(p))
        """,
    )
    assert findings == []


def test_117_httpx_client_ctor_tainted_base_url_fires(tmp_path: Path) -> None:
    findings = _ssrf(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p):
            httpx.Client(base_url=read_raw(p))
        """,
    )
    assert [f.properties["sink"] for f in findings] == ["httpx.Client"]


def test_117_instance_method_tainted_headers_clean_url_does_not_fire(tmp_path: Path) -> None:
    findings = _ssrf(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p):
            client = httpx.Client()
            client.get('https://safe.example', headers=read_raw(p))
        """,
    )
    assert findings == []


def test_117_star_args_widening_fires(tmp_path: Path) -> None:
    # *args makes positional slots unmappable: fail-closed widening keeps the verdict.
    findings = _ssrf(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p):
            parts = read_raw(p)
            requests.get(*parts)
        """,
    )
    assert [f.properties["sink"] for f in findings] == ["requests.get"]


def test_117_undecorated_construct_then_method_is_suppressed(tmp_path: Path) -> None:
    # Freedom zone: the tier gate applies to the new shapes exactly as to the old ones.
    findings = _ssrf(
        tmp_path,
        """
        def f(p):
            client = httpx.Client()
            client.get(read_raw(p))
        """,
    )
    assert findings == []
