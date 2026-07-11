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


def _defect_rules_files(tmp_path: Path, files: dict[str, str]) -> set[str]:
    paths = []
    for name, src in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(src), encoding="utf-8")
        paths.append(path)
    findings = WardlineAnalyzer().analyze(paths, WardlineConfig(), root=tmp_path)
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


def test_route_uses_receiver_binding_at_definition_before_later_reassignment(tmp_path: Path) -> None:
    src = """
        import os
        from fastapi import FastAPI
        from pydantic import BaseModel
        from wardline.decorators import trusted
        class Local: pass
        app = FastAPI()
        class Payload(BaseModel): command: str
        @app.post('/')
        @trusted(level='ASSURED')
        def run(body: Payload): os.system(body.command)
        app = Local()
    """
    assert "PY-WL-108" in _defect_rules(tmp_path, src)


def test_class_body_route_inherits_module_binding_snapshot(tmp_path: Path) -> None:
    src = """
        import os
        from fastapi import FastAPI
        from pydantic import BaseModel
        from wardline.decorators import trusted
        app = FastAPI()
        class Payload(BaseModel): command: str
        class Routes:
            @app.post('/')
            @trusted(level='ASSURED')
            def run(body: Payload): os.system(body.command)
    """
    assert "PY-WL-108" in _defect_rules(tmp_path, src)


def test_nested_route_inherits_enclosing_module_binding_snapshot(tmp_path: Path) -> None:
    src = """
        import os
        from fastapi import FastAPI
        from pydantic import BaseModel
        from wardline.decorators import trusted
        app = FastAPI()
        class Payload(BaseModel): command: str
        def register():
            @app.post('/')
            @trusted(level='ASSURED')
            def run(body: Payload): os.system(body.command)
            return run
    """
    assert "PY-WL-108" in _defect_rules(tmp_path, src)


def test_reimport_restores_shadowed_fastapi_constructor(tmp_path: Path) -> None:
    src = """
        import os
        from fastapi import FastAPI
        from pydantic import BaseModel
        from wardline.decorators import trusted
        class Local: pass
        FastAPI = Local
        from fastapi import FastAPI
        app = FastAPI()
        class Payload(BaseModel): command: str
        @app.post('/')
        @trusted(level='ASSURED')
        def run(body: Payload): os.system(body.command)
    """
    assert "PY-WL-108" in _defect_rules(tmp_path, src)


@pytest.mark.parametrize("style", ["default", "annotated"])
def test_shadowed_depends_is_not_treated_as_fastapi_injection(tmp_path: Path, style: str) -> None:
    parameter = "value: str = Depends(safe)" if style == "default" else "value: Annotated[str, Depends(safe)] = raw()"
    src = f"""
        import os
        from typing import Annotated
        from fastapi import Depends, FastAPI
        from wardline.decorators import external_boundary, trusted
        app = FastAPI()
        @external_boundary
        def raw(): return 'raw'
        @trusted(level='ASSURED')
        def safe(): return 'fixed'
        Depends = lambda provider: input()
        @app.post('/')
        @trusted(level='ASSURED')
        def run({parameter}): os.system(value)
    """
    assert "PY-WL-108" in _defect_rules(tmp_path, src)


def test_imported_pydantic_model_rebound_before_route_is_not_body_source(tmp_path: Path) -> None:
    rules = _defect_rules_files(
        tmp_path,
        {
            "models.py": "from pydantic import BaseModel\nclass Payload(BaseModel):\n    command: str\n",
            "api.py": """
                import os
                from fastapi import FastAPI
                from models import Payload
                from wardline.decorators import trusted
                class Local: pass
                app = FastAPI()
                Payload = Local
                @app.post('/')
                @trusted(level='ASSURED')
                def run(body: Payload): os.system(body.command)
            """,
        },
    )
    assert "PY-WL-108" not in rules


def test_reassigned_local_pydantic_model_discovery_terminates_and_invalidates(tmp_path: Path) -> None:
    src = """
        import os
        from fastapi import FastAPI
        from pydantic import BaseModel
        from wardline.decorators import trusted
        class Local: pass
        app = FastAPI()
        class Payload(BaseModel): command: str
        Payload = Local
        @app.post('/')
        @trusted(level='ASSURED')
        def run(body: Payload): os.system(body.command)
    """
    assert "PY-WL-108" not in _defect_rules(tmp_path, src)


def test_route_keeps_model_binding_from_definition_before_later_reassignment(tmp_path: Path) -> None:
    src = """
        import os
        from fastapi import FastAPI
        from pydantic import BaseModel
        from wardline.decorators import trusted
        class Local: pass
        app = FastAPI()
        class Payload(BaseModel): command: str
        @app.post('/')
        @trusted(level='ASSURED')
        def run(body: Payload): os.system(body.command)
        Payload = Local
    """
    assert "PY-WL-108" in _defect_rules(tmp_path, src)


def test_reimport_restores_shadowed_pydantic_base(tmp_path: Path) -> None:
    src = """
        import os
        from fastapi import FastAPI
        from pydantic import BaseModel as Model
        from wardline.decorators import trusted
        class Local: pass
        Model = Local
        from pydantic import BaseModel as Model
        app = FastAPI()
        class Payload(Model): command: str
        @app.post('/')
        @trusted(level='ASSURED')
        def run(body: Payload): os.system(body.command)
    """
    assert "PY-WL-108" in _defect_rules(tmp_path, src)


def test_restored_pydantic_model_is_exported_to_importing_route(tmp_path: Path) -> None:
    rules = _defect_rules_files(
        tmp_path,
        {
            "models.py": """
                from pydantic import BaseModel
                class Local: pass
                BaseModel = Local
                from pydantic import BaseModel
                class Payload(BaseModel): command: str
            """,
            "api.py": """
                import os
                from fastapi import FastAPI
                from models import Payload
                from wardline.decorators import trusted
                app = FastAPI()
                @app.post('/')
                @trusted(level='ASSURED')
                def run(body: Payload): os.system(body.command)
            """,
        },
    )
    assert "PY-WL-108" in rules


def test_later_non_model_class_replaces_model_binding(tmp_path: Path) -> None:
    src = """
        import os
        from fastapi import FastAPI
        from pydantic import BaseModel
        from wardline.decorators import trusted
        class Local: pass
        app = FastAPI()
        class Payload(BaseModel): command: str
        class Payload(Local): pass
        @app.post('/')
        @trusted(level='ASSURED')
        def run(body: Payload): os.system(body.command)
    """
    assert "PY-WL-108" not in _defect_rules(tmp_path, src)


def test_replaced_model_is_not_exported_to_importing_route(tmp_path: Path) -> None:
    rules = _defect_rules_files(
        tmp_path,
        {
            "models.py": """
                from pydantic import BaseModel
                class Local: pass
                class Payload(BaseModel): command: str
                class Payload(Local): pass
            """,
            "api.py": """
                import os
                from fastapi import FastAPI
                from models import Payload
                from wardline.decorators import trusted
                app = FastAPI()
                @app.post('/')
                @trusted(level='ASSURED')
                def run(body: Payload): os.system(body.command)
            """,
        },
    )
    assert "PY-WL-108" not in rules


@pytest.mark.parametrize(
    "annotation",
    ["list[Payload]", "Sequence[Payload]", "dict[str, Payload]", "Union[Payload, None]"],
)
def test_recursive_collection_body_annotations_are_sources(tmp_path: Path, annotation: str) -> None:
    src = f"""
        import os
        from typing import Sequence, Union
        from fastapi import FastAPI
        from pydantic import BaseModel
        from wardline.decorators import trusted
        app = FastAPI()
        class Payload(BaseModel): command: str
        @app.post('/')
        @trusted(level='ASSURED')
        def run(body: {annotation}): os.system(str(body))
    """
    assert "PY-WL-108" in _defect_rules(tmp_path, src)


def test_deeply_nested_body_annotation_terminates_and_fails_closed(tmp_path: Path) -> None:
    annotation = "list[" * 150 + "Payload" + "]" * 150
    src = f"""
        import os
        from fastapi import FastAPI
        from pydantic import BaseModel
        from wardline.decorators import trusted
        app = FastAPI()
        class Payload(BaseModel): command: str
        @app.post('/')
        @trusted(level='ASSURED')
        def run(body: {annotation}): os.system(str(body))
    """
    assert "PY-WL-108" in _defect_rules(tmp_path, src)


def test_deep_attribute_annotation_terminates_and_fails_closed(tmp_path: Path) -> None:
    annotation = "root" + ".item" * 150
    src = f"""
        import os
        from fastapi import FastAPI
        from wardline.decorators import trusted
        app = FastAPI()
        @app.post('/')
        @trusted(level='ASSURED')
        def run(body: {annotation}): os.system(str(body))
    """
    assert "PY-WL-108" in _defect_rules(tmp_path, src)


def test_rebound_imported_dependency_provider_fails_closed(tmp_path: Path) -> None:
    rules = _defect_rules_files(
        tmp_path,
        {
            "dep.py": """
                from wardline.decorators import trusted
                @trusted(level='ASSURED')
                def supplied(): return 'fixed'
            """,
            "api.py": """
                import os
                from fastapi import Depends, FastAPI
                from dep import supplied
                from wardline.decorators import external_boundary, trusted
                app = FastAPI()
                @external_boundary
                def raw(): return 'raw'
                supplied = raw
                @app.post('/')
                @trusted(level='ASSURED')
                def run(value: str = Depends(supplied)): os.system(value)
            """,
        },
    )
    assert "PY-WL-108" in rules


def test_unproven_provider_reassignment_does_not_resolve_stale_function(tmp_path: Path) -> None:
    src = """
        import os
        from fastapi import Depends, FastAPI
        from wardline.decorators import trusted
        app = FastAPI()
        @trusted(level='ASSURED')
        def supplied(): return 'fixed'
        def factory(): return lambda: input()
        supplied = factory()
        @app.post('/')
        @trusted(level='ASSURED')
        def run(value: str = Depends(supplied)): os.system(value)
    """
    assert "PY-WL-108" in _defect_rules(tmp_path, src)


def test_local_model_alias_is_resolved_at_route_definition(tmp_path: Path) -> None:
    src = """
        import os
        from fastapi import FastAPI
        from pydantic import BaseModel
        from wardline.decorators import trusted
        app = FastAPI()
        class Payload(BaseModel): command: str
        PayloadAlias = Payload
        @app.post('/')
        @trusted(level='ASSURED')
        def run(body: PayloadAlias): os.system(body.command)
    """
    assert "PY-WL-108" in _defect_rules(tmp_path, src)


def test_local_dependency_provider_alias_preserves_trusted_return(tmp_path: Path) -> None:
    src = """
        import os
        from fastapi import Depends, FastAPI
        from wardline.decorators import trusted
        app = FastAPI()
        @trusted(level='ASSURED')
        def supplied(): return 'fixed'
        supplied_alias = supplied
        @app.post('/')
        @trusted(level='ASSURED')
        def run(value: str = Depends(supplied_alias)): os.system(value)
    """
    assert "PY-WL-108" not in _defect_rules(tmp_path, src)


def test_reimport_restores_shadowed_depends_binding(tmp_path: Path) -> None:
    src = """
        import os
        from fastapi import Depends, FastAPI
        from wardline.decorators import trusted
        app = FastAPI()
        @trusted(level='ASSURED')
        def supplied(): return 'fixed'
        Depends = lambda provider: input()
        from fastapi import Depends
        @app.post('/')
        @trusted(level='ASSURED')
        def run(value: str = Depends(supplied)): os.system(value)
    """
    assert "PY-WL-108" not in _defect_rules(tmp_path, src)


def test_package_module_model_discovery_terminates(tmp_path: Path) -> None:
    rules = _defect_rules_files(
        tmp_path,
        {
            "pkg/__init__.py": "",
            "pkg/sub.py": "from pydantic import BaseModel\nclass Payload(BaseModel):\n    command: str\n",
        },
    )
    assert "WLN-ENGINE-FILE-FAILED" not in rules


def test_relative_model_import_is_resolved_in_package_route(tmp_path: Path) -> None:
    rules = _defect_rules_files(
        tmp_path,
        {
            "pkg/__init__.py": "",
            "pkg/models.py": "from pydantic import BaseModel\nclass Payload(BaseModel):\n    command: str\n",
            "pkg/api.py": """
                import os
                import fastapi.routing
                from .models import Payload
                from wardline.decorators import trusted
                app = fastapi.routing.APIRouter()
                @app.post('/')
                @trusted(level='ASSURED')
                def run(body: Payload): os.system(body.command)
            """,
        },
    )
    assert "PY-WL-108" in rules
