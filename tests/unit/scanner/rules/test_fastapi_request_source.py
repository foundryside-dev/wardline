"""Part C of wardline-bd9d1e65cb: FastAPI/starlette request-type taint source seeding.

wardline ships Flask request coverage but no FastAPI/starlette coverage, so a
FastAPI+pydantic app's request entry points are invisible. This adds annotation-based
source seeding: a parameter annotated with a recognized request type
(``fastapi.Request`` / ``starlette.requests.Request``) is an external-data boundary, and
curated DATA members read off it (``.query_params``/``.path_params``/``.headers``/
``.cookies`` properties; ``.json()``/``.body()``/``.form()``/``.stream()`` methods) yield
EXTERNAL_RAW. Match is on the RESOLVED TYPE (via the alias map), NEVER the parameter name.

Design: the typed-receiver + curated-member approach (not whole-param tainting), so the
framework objects (``req.app``/``req.state``/``req.url``/``req.scope``/``req.client``)
stay clean. Like every wardline taint rule this is annotation-driven — the firing GATE
still requires the enclosing handler be declared-trusted; this feature only makes the
SOURCE visible (an undecorated handler fires nothing, by design).
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from wardline.core.config import WardlineConfig
from wardline.core.finding import Kind
from wardline.scanner.analyzer import WardlineAnalyzer


def _defect_rules(tmp_path: Path, src: str) -> set[str]:
    p = tmp_path / "m.py"
    p.write_text(textwrap.dedent(src), encoding="utf-8")
    findings = list(WardlineAnalyzer().analyze([p], WardlineConfig(), root=tmp_path))
    return {f.rule_id for f in findings if f.kind is Kind.DEFECT}


# --- MUST FIRE: curated request-data members reaching a command sink (PY-WL-108) -------

_MUST_FIRE = {
    "query_params_get": """
        import os
        from wardline.decorators import trusted
        from fastapi import Request

        @trusted(level='ASSURED')
        def h(req: Request):
            os.system(req.query_params.get('x'))
    """,
    "path_params_subscript": """
        import os
        from wardline.decorators import trusted
        from fastapi import Request

        @trusted(level='ASSURED')
        def h(req: Request):
            os.system(req.path_params['id'])
    """,
    "headers_get": """
        import os
        from wardline.decorators import trusted
        from fastapi import Request

        @trusted(level='ASSURED')
        def h(req: Request):
            os.system(req.headers.get('x'))
    """,
    "cookies_subscript": """
        import os
        from wardline.decorators import trusted
        from fastapi import Request

        @trusted(level='ASSURED')
        def h(req: Request):
            os.system(req.cookies['c'])
    """,
    "await_json": """
        import os
        from wardline.decorators import trusted
        from fastapi import Request

        @trusted(level='ASSURED')
        async def h(req: Request):
            os.system(await req.json())
    """,
    "await_body_bare": """
        import os
        from wardline.decorators import trusted
        from fastapi import Request

        @trusted(level='ASSURED')
        async def h(req: Request):
            os.system(await req.body())
    """,
    "await_form_get": """
        import os
        from wardline.decorators import trusted
        from fastapi import Request

        @trusted(level='ASSURED')
        async def h(req: Request):
            os.system((await req.form()).get('f'))
    """,
    "await_stream": """
        import os
        from wardline.decorators import trusted
        from fastapi import Request

        @trusted(level='ASSURED')
        async def h(req: Request):
            os.system(await req.stream())
    """,
    "query_params_items": """
        import os
        from wardline.decorators import trusted
        from fastapi import Request

        @trusted(level='ASSURED')
        def h(req: Request):
            os.system(str(req.query_params.items()))
    """,
    "starlette_request": """
        import os
        from wardline.decorators import trusted
        from starlette.requests import Request

        @trusted(level='ASSURED')
        def h(req: Request):
            os.system(req.query_params.get('x'))
    """,
    "renamed_param_name_independent": """
        import os
        from wardline.decorators import trusted
        from fastapi import Request

        @trusted(level='ASSURED')
        def h(r: Request):
            os.system(r.query_params.get('x'))
    """,
}


# --- RETURN-POSITION boundary leak: a @trusted boundary RETURNING a request source -----
#
# A function declared a trust boundary (@trusted producing ASSURED) that returns raw
# request data is a contract violation caught AT the boundary by PY-WL-101 (untrusted data
# reaches a trusted producer) — exactly how every other source (DB-fetch, @external_boundary
# producers) is treated. The request source must be visible in the RETURN pass for this to
# fire. The DIRECT-return forms were a false negative until the receiver-type map was
# re-established for compute_return_taint (the local-var form already worked via var_taints);
# pinning all three keeps the direct/local forms consistent and prevents regression.

_RETURN_BOUNDARY_LEAK = {
    "direct_return_query_params_get": """
        from wardline.decorators import trusted
        from fastapi import Request

        @trusted(level='ASSURED')
        def extract(req: Request):
            return req.query_params.get('x')
    """,
    "direct_return_await_json": """
        from wardline.decorators import trusted
        from fastapi import Request

        @trusted(level='ASSURED')
        async def extract(req: Request):
            return await req.json()
    """,
    "local_var_then_return": """
        from wardline.decorators import trusted
        from fastapi import Request

        @trusted(level='ASSURED')
        def extract(req: Request):
            q = req.query_params.get('x')
            return q
    """,
}


@pytest.mark.parametrize("name", sorted(_RETURN_BOUNDARY_LEAK))
def test_request_source_returned_from_trusted_boundary_fires_101(tmp_path: Path, name: str) -> None:
    assert "PY-WL-101" in _defect_rules(tmp_path, _RETURN_BOUNDARY_LEAK[name]), name


def test_undecorated_handler_returning_request_source_is_quiet(tmp_path: Path) -> None:
    # No @trusted -> not an anchored boundary -> PY-WL-101 cannot fire (freedom zone),
    # mirroring the direct-sink freedom-zone case. The source is seeded; the gate governs.
    src = """
        from fastapi import Request

        def extract(req: Request):
            return req.query_params.get('x')
    """
    assert "PY-WL-101" not in _defect_rules(tmp_path, src)


@pytest.mark.parametrize("name", sorted(_MUST_FIRE))
def test_fastapi_request_source_fires(tmp_path: Path, name: str) -> None:
    assert "PY-WL-108" in _defect_rules(tmp_path, _MUST_FIRE[name]), name


# --- MUST NOT FIRE: framework objects, name-only, whole-param, freedom zone ------------

_MUST_NOT_FIRE = {
    # Framework / control objects on the request — not attacker wire input.
    "app_state_db": """
        import os
        from wardline.decorators import trusted
        from fastapi import Request

        @trusted(level='ASSURED')
        def h(req: Request):
            os.system(req.app.state.db)
    """,
    "app_bare": """
        import os
        from wardline.decorators import trusted
        from fastapi import Request

        @trusted(level='ASSURED')
        def h(req: Request):
            os.system(req.app)
    """,
    "url_path": """
        import os
        from wardline.decorators import trusted
        from fastapi import Request

        @trusted(level='ASSURED')
        def h(req: Request):
            os.system(req.url.path)
    """,
    "client_host": """
        import os
        from wardline.decorators import trusted
        from fastapi import Request

        @trusted(level='ASSURED')
        def h(req: Request):
            os.system(req.client.host)
    """,
    "scope_subscript": """
        import os
        from wardline.decorators import trusted
        from fastapi import Request

        @trusted(level='ASSURED')
        def h(req: Request):
            os.system(req.scope['path'])
    """,
    "state_attr": """
        import os
        from wardline.decorators import trusted
        from fastapi import Request

        @trusted(level='ASSURED')
        def h(req: Request):
            os.system(req.state.user_id)
    """,
    "base_url": """
        import os
        from wardline.decorators import trusted
        from fastapi import Request

        @trusted(level='ASSURED')
        def h(req: Request):
            os.system(req.base_url.hostname)
    """,
    # Property/method split: a bare uncalled `req.json` is a bound coroutine-method, not data.
    "uncalled_json_attribute": """
        import os
        from wardline.decorators import trusted
        from fastapi import Request

        @trusted(level='ASSURED')
        def h(req: Request):
            os.system(req.json)
    """,
    # Resolved-type discriminator: a same-named local class is not the request type.
    "param_named_request_other_type": """
        import os
        from wardline.decorators import trusted

        class Request: ...

        @trusted(level='ASSURED')
        def h(request: Request):
            os.system(request.query_params.get('x'))
    """,
    # No annotation -> no type slot -> never seeds (the name 'request' is not special-cased).
    "param_named_request_unannotated": """
        import os
        from wardline.decorators import trusted

        @trusted(level='ASSURED')
        def h(request):
            os.system(request.query_params.get('x'))
    """,
    # Typed-receiver, not whole-param tainting: passing the request whole is clean.
    "request_passed_to_unseen_helper": """
        import os
        from wardline.decorators import trusted
        from fastapi import Request

        def helper(x):
            os.system(x)

        @trusted(level='ASSURED')
        def h(req: Request):
            helper(req)
    """,
    # The GATE, not the seed, governs an undecorated handler: no @trusted -> nothing fires.
    "undecorated_handler_freedom_zone": """
        import os
        from fastapi import Request

        def h(req: Request):
            os.system(req.query_params.get('x'))
    """,
}


@pytest.mark.parametrize("name", sorted(_MUST_NOT_FIRE))
def test_fastapi_request_source_does_not_fire(tmp_path: Path, name: str) -> None:
    assert "PY-WL-108" not in _defect_rules(tmp_path, _MUST_NOT_FIRE[name]), name
