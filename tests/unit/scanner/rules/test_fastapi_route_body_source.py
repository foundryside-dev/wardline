"""Route-aware FastAPI Pydantic body parameter source seeding."""

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


@pytest.mark.parametrize(
    ("name", "src"),
    [
        (
            "direct_model",
            """
            import os
            from fastapi import FastAPI
            from pydantic import BaseModel
            from wardline.decorators import trusted
            app = FastAPI()
            class Payload(BaseModel):
                command: str
            @app.post('/run')
            @trusted(level='ASSURED')
            def run(body: Payload):
                os.system(body.command)
            """,
        ),
        (
            "aliased_import",
            """
            import os
            import fastapi as fa
            from pydantic import BaseModel as Model
            from wardline.decorators import trusted
            api = fa.FastAPI()
            class Payload(Model):
                nested: dict[str, str]
            @api.put('/run')
            @trusted(level='ASSURED')
            def run(body: Payload):
                os.system(body.nested['command'])
            """,
        ),
        (
            "router_and_model_alias",
            """
            import os
            from fastapi import APIRouter as Router
            from pydantic import BaseModel as Model
            from wardline.decorators import trusted
            router = Router()
            class Payload(Model):
                command: str
            @router.patch('/run')
            @trusted(level='ASSURED')
            def run(body: Payload):
                os.system(body.command)
            """,
        ),
    ],
)
def test_fastapi_route_model_body_fires(tmp_path: Path, name: str, src: str) -> None:
    assert "PY-WL-108" in _defect_rules(tmp_path, src), name


@pytest.mark.parametrize(
    ("name", "src"),
    [
        (
            "ordinary_function",
            """
            import os
            from pydantic import BaseModel
            from wardline.decorators import trusted
            class Payload(BaseModel):
                command: str
            @trusted(level='ASSURED')
            def helper(body: Payload):
                os.system(body.command)
            """,
        ),
        (
            "depends_provider",
            """
            import os
            from fastapi import Depends, FastAPI
            from pydantic import BaseModel
            from wardline.decorators import trusted
            app = FastAPI()
            class Payload(BaseModel):
                command: str
            def validated() -> Payload:
                return Payload(command='fixed')
            @app.post('/run')
            @trusted(level='ASSURED')
            def run(body: Payload = Depends(validated)):
                os.system(body.command)
            """,
        ),
        (
            "aliased_depends_provider",
            """
            import os
            import fastapi as fa
            from pydantic import BaseModel
            from wardline.decorators import trusted
            api = fa.FastAPI()
            class Payload(BaseModel):
                command: str
            def validated() -> Payload:
                return Payload(command='fixed')
            @api.post('/run')
            @trusted(level='ASSURED')
            def run(body: Payload = fa.Depends(validated)):
                os.system(body.command)
            """,
        ),
        (
            "coincidental_get_decorator",
            """
            import os
            from pydantic import BaseModel
            from wardline.decorators import trusted
            class Local:
                def get(self, _path): return lambda f: f
            app = Local()
            class Payload(BaseModel):
                command: str
            @app.get('/run')
            @trusted(level='ASSURED')
            def run(body: Payload):
                os.system(body.command)
            """,
        ),
    ],
)
def test_non_body_model_parameters_stay_clean(tmp_path: Path, name: str, src: str) -> None:
    assert "PY-WL-108" not in _defect_rules(tmp_path, src), name


@pytest.mark.parametrize(
    ("name", "src"),
    [
        (
            "non_route_depends",
            """
            import os
            from fastapi import Depends
            from pydantic import BaseModel
            from wardline.decorators import trusted
            class Payload(BaseModel):
                command: str
            def validated() -> Payload:
                return Payload(command='fixed')
            @trusted(level='ASSURED')
            def helper(body: Payload = Depends(validated)):
                os.system(body.command)
            """,
        ),
        (
            "arbitrary_route_default",
            """
            import os
            from fastapi import FastAPI
            from pydantic import BaseModel
            from wardline.decorators import trusted
            app = FastAPI()
            class Payload(BaseModel):
                command: str
            def factory() -> Payload:
                return Payload(command='fixed')
            @app.post('/run')
            @trusted(level='ASSURED')
            def run(body: Payload = factory()):
                os.system(body.command)
            """,
        ),
    ],
)
def test_depends_quieting_is_precisely_route_scoped(tmp_path: Path, name: str, src: str) -> None:
    assert "PY-WL-108" in _defect_rules(tmp_path, src), name
