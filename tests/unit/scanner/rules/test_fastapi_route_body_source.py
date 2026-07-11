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
            @trusted(level='ASSURED')
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
            @trusted(level='ASSURED')
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


@pytest.mark.parametrize(
    "provider",
    [
        "@external_boundary\ndef supplied():\n    return 'raw'",
        "def supplied():\n    return input()",
    ],
)
def test_route_depends_uses_actual_untrusted_provider_taint(tmp_path: Path, provider: str) -> None:
    provider = textwrap.indent(provider, "        ")
    src = f"""
        import os
        from fastapi import Depends, FastAPI
        from wardline.decorators import external_boundary, trusted
        app = FastAPI()
{provider}
        @app.post('/run')
        @trusted(level='ASSURED')
        def run(value: str = Depends(supplied)):
            os.system(value)
    """
    assert "PY-WL-108" in _defect_rules(tmp_path, src)


@pytest.mark.parametrize(
    ("provider_decorator", "fires"),
    [("@external_boundary", True), ("@trusted(level='ASSURED')", False)],
)
def test_annotated_depends_uses_provider_taint(tmp_path: Path, provider_decorator: str, fires: bool) -> None:
    src = f"""
        import os
        from typing import Annotated
        from fastapi import Depends, FastAPI
        from wardline.decorators import external_boundary, trusted
        app = FastAPI()
        {provider_decorator}
        def supplied():
            return 'value'
        @app.post('/run')
        @trusted(level='ASSURED')
        def run(value: Annotated[str, Depends(supplied)]):
            os.system(value)
    """
    assert ("PY-WL-108" in _defect_rules(tmp_path, src)) is fires


@pytest.mark.parametrize(
    "binding",
    [
        "app = FastAPI()\napp = Local()",
        "FastAPI = Local\napp = FastAPI()",
    ],
)
def test_shadowed_fastapi_bindings_do_not_classify_routes(tmp_path: Path, binding: str) -> None:
    binding = textwrap.indent(binding, "        ")
    src = f"""
        import os
        from fastapi import FastAPI
        from pydantic import BaseModel
        from wardline.decorators import trusted
        class Local: pass
{binding}
        class Payload(BaseModel):
            command: str
        @app.post('/run')
        @trusted(level='ASSURED')
        def run(body: Payload):
            os.system(body.command)
    """
    assert "PY-WL-108" not in _defect_rules(tmp_path, src)


def test_shadowed_pydantic_base_alias_does_not_classify_model(tmp_path: Path) -> None:
    src = """
        import os
        from fastapi import FastAPI
        from pydantic import BaseModel as Model
        from wardline.decorators import trusted
        class Local: pass
        app = FastAPI()
        Model = Local
        class Payload(Model):
            command: str
        @app.post('/run')
        @trusted(level='ASSURED')
        def run(body: Payload):
            os.system(body.command)
    """
    assert "PY-WL-108" not in _defect_rules(tmp_path, src)


@pytest.mark.parametrize(
    "annotation",
    ["Annotated[Payload, Body()]", "Optional[Payload]", "Payload | None", "Payload[str]"],
)
def test_common_route_body_annotation_forms_are_sources(tmp_path: Path, annotation: str) -> None:
    src = f"""
        import os
        from typing import Annotated, Generic, Optional, TypeVar
        from fastapi import Body, FastAPI
        from pydantic import BaseModel
        from wardline.decorators import trusted
        T = TypeVar('T')
        app = FastAPI()
        class Payload(BaseModel, Generic[T]):
            command: str
        @app.post('/run')
        @trusted(level='ASSURED')
        def run(body: {annotation}):
            os.system(body.command)
    """
    assert "PY-WL-108" in _defect_rules(tmp_path, src)
