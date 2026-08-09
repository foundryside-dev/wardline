"""Route-aware FastAPI Pydantic body parameter source seeding."""

from __future__ import annotations

import ast
import textwrap
from pathlib import Path

import pytest

from wardline.core.config import WardlineConfig
from wardline.core.finding import Kind, Severity
from wardline.core.run import run_scan
from wardline.scanner import analyzer as analyzer_module
from wardline.scanner.analyzer import WardlineAnalyzer
from wardline.scanner.taint.fastapi_sources import _annotation_candidates, discover_fastapi_route_receivers
from wardline.scanner.taint.pydantic_discovery import (
    PydanticDiscoveryBudget,
    PydanticDiscoveryReason,
    PydanticDiscoveryResult,
)


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
    ("annotated_import", "annotated_name"),
    [
        pytest.param("from typing import Annotated", "Annotated", id="typing"),
        pytest.param(
            "from typing_extensions import Annotated",
            "Annotated",
            id="typing-extensions-direct",
        ),
        pytest.param(
            "from typing_extensions import Annotated as DependencyAnnotated",
            "DependencyAnnotated",
            id="typing-extensions-symbol-alias",
        ),
        pytest.param(
            "import typing_extensions as te",
            "te.Annotated",
            id="typing-extensions-module-alias",
        ),
    ],
)
@pytest.mark.parametrize(
    ("provider_decorator", "fires"),
    [("@external_boundary", True), ("@trusted(level='ASSURED')", False)],
)
def test_annotated_depends_uses_provider_taint(
    tmp_path: Path,
    annotated_import: str,
    annotated_name: str,
    provider_decorator: str,
    fires: bool,
) -> None:
    src = f"""
        import os
        {annotated_import}
        from fastapi import Depends, FastAPI
        from wardline.decorators import external_boundary, trusted
        app = FastAPI()
        {provider_decorator}
        def supplied():
            return 'value'
        @app.post('/run')
        @trusted(level='ASSURED')
        def run(value: {annotated_name}[str, Depends(supplied)]):
            os.system(value)
    """
    assert ("PY-WL-108" in _defect_rules(tmp_path, src)) is fires


@pytest.mark.parametrize(
    ("binding", "annotated_name"),
    [
        pytest.param("import local_typing", "local_typing.Annotated", id="lookalike-module"),
        pytest.param(
            "from typing_extensions import Annotated\nclass Annotated:\n    pass",
            "Annotated",
            id="shadowed-symbol",
        ),
        pytest.param(
            "import typing_extensions as te\nclass LocalTyping:\n    class Annotated:\n        pass\nte = LocalTyping",
            "te.Annotated",
            id="shadowed-module-alias",
        ),
    ],
)
def test_annotated_depends_requires_exact_supported_fqn(tmp_path: Path, binding: str, annotated_name: str) -> None:
    binding = textwrap.indent(binding, "        ")
    src = f"""
        import os
        from fastapi import Depends, FastAPI
        from wardline.decorators import external_boundary, trusted
{binding}
        app = FastAPI()
        @external_boundary
        def supplied():
            return 'value'
        @app.post('/run')
        @trusted(level='ASSURED')
        def run(value: {annotated_name}[str, Depends(supplied)]):
            os.system(value)
    """
    assert "PY-WL-108" not in _defect_rules(tmp_path, src)


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


def test_typing_extensions_annotated_route_body_unwraps_payload_type(tmp_path: Path) -> None:
    src = """
        import os
        from typing_extensions import Annotated
        from fastapi import Body, FastAPI
        from pydantic import BaseModel
        from wardline.decorators import trusted
        app = FastAPI()
        class Payload(BaseModel):
            command: str
        @app.post('/run')
        @trusted(level='ASSURED')
        def run(body: Annotated[Payload, Body()]):
            os.system(body.command)
    """
    tree = ast.parse(textwrap.dedent(src))
    route = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "run")
    annotation = route.args.args[0].annotation
    assert annotation is not None
    assert _annotation_candidates(
        annotation,
        {
            "Annotated": "typing_extensions.Annotated",
            "Body": "fastapi.Body",
            "Payload": "m.Payload",
        },
    ) == {"m.Payload"}
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


@pytest.mark.parametrize("assignment", ["Payload = Payload", "Alias = Payload; Payload = Alias"])
def test_model_identity_preserving_assignment_keeps_body_source(tmp_path: Path, assignment: str) -> None:
    src = f"""
        import os
        from fastapi import FastAPI
        from pydantic import BaseModel
        from wardline.decorators import trusted
        app = FastAPI()
        class Payload(BaseModel): command: str
        {assignment}
        @app.post('/')
        @trusted(level='ASSURED')
        def run(body: Payload): os.system(body.command)
    """
    assert "PY-WL-108" in _defect_rules(tmp_path, src)


def test_nested_scope_local_fastapi_receiver_is_recognized(tmp_path: Path) -> None:
    src = """
        import os
        from fastapi import FastAPI
        from pydantic import BaseModel
        from wardline.decorators import trusted
        class Payload(BaseModel): command: str
        def register():
            app = FastAPI()
            @app.post('/')
            @trusted(level='ASSURED')
            def run(body: Payload): os.system(body.command)
            return run
    """
    assert "PY-WL-108" in _defect_rules(tmp_path, src)


def test_nested_scope_provider_uses_locals_qualified_identity(tmp_path: Path) -> None:
    src = """
        import os
        from fastapi import Depends, FastAPI
        from wardline.decorators import trusted
        def register():
            app = FastAPI()
            @trusted(level='ASSURED')
            def supplied(): return 'fixed'
            @app.post('/')
            @trusted(level='ASSURED')
            def run(value: str = Depends(supplied)): os.system(value)
            return run
    """
    assert "PY-WL-108" not in _defect_rules(tmp_path, src)


def test_nested_scope_local_shadow_hides_inherited_receiver(tmp_path: Path) -> None:
    src = """
        import os
        from fastapi import FastAPI
        from pydantic import BaseModel
        from wardline.decorators import trusted
        class Local: pass
        app = FastAPI()
        class Payload(BaseModel): command: str
        def register():
            app = Local()
            @app.post('/')
            @trusted(level='ASSURED')
            def run(body: Payload): os.system(body.command)
            return run
    """
    assert "PY-WL-108" not in _defect_rules(tmp_path, src)


def test_class_scope_local_fastapi_receiver_is_recognized(tmp_path: Path) -> None:
    src = """
        import os
        from fastapi import FastAPI
        from pydantic import BaseModel
        from wardline.decorators import trusted
        class Payload(BaseModel): command: str
        class Routes:
            app = FastAPI()
            @app.post('/')
            @trusted(level='ASSURED')
            def run(body: Payload): os.system(body.command)
    """
    assert "PY-WL-108" in _defect_rules(tmp_path, src)


def test_class_scope_local_shadow_hides_inherited_receiver(tmp_path: Path) -> None:
    src = """
        import os
        from fastapi import FastAPI
        from pydantic import BaseModel
        from wardline.decorators import trusted
        class Local: pass
        app = FastAPI()
        class Payload(BaseModel): command: str
        class Routes:
            app = Local()
            @app.post('/')
            @trusted(level='ASSURED')
            def run(body: Payload): os.system(body.command)
    """
    assert "PY-WL-108" not in _defect_rules(tmp_path, src)


def test_exported_model_alias_is_recognized_cross_module(tmp_path: Path) -> None:
    rules = _defect_rules_files(
        tmp_path,
        {
            "models.py": """
                from pydantic import BaseModel
                class Payload(BaseModel): command: str
                PublicPayload = Payload
            """,
            "api.py": """
                import os
                from fastapi import FastAPI
                from models import PublicPayload
                from wardline.decorators import trusted
                app = FastAPI()
                @app.post('/')
                @trusted(level='ASSURED')
                def run(body: PublicPayload): os.system(body.command)
            """,
        },
    )
    assert "PY-WL-108" in rules


def test_exported_trusted_provider_alias_is_quiet_cross_module(tmp_path: Path) -> None:
    rules = _defect_rules_files(
        tmp_path,
        {
            "providers.py": """
                from wardline.decorators import trusted
                @trusted(level='ASSURED')
                def supplied(): return 'fixed'
                public = supplied
            """,
            "api.py": """
                import os
                from fastapi import Depends, FastAPI
                from providers import public
                from wardline.decorators import trusted
                app = FastAPI()
                @app.post('/')
                @trusted(level='ASSURED')
                def run(value: str = Depends(public)): os.system(value)
            """,
        },
    )
    assert "PY-WL-108" not in rules


def test_unproven_model_alias_annotation_fails_closed(tmp_path: Path) -> None:
    src = """
        import os
        from fastapi import FastAPI
        from pydantic import BaseModel
        from wardline.decorators import trusted
        app = FastAPI()
        class Payload(BaseModel): command: str
        def identity(value): return value
        Alias = identity(Payload)
        @app.post('/')
        @trusted(level='ASSURED')
        def run(body: Alias): os.system(body.command)
    """
    assert "PY-WL-108" in _defect_rules(tmp_path, src)


@pytest.mark.parametrize("annotation", ['"Payload"', '"list[Payload]"'])
def test_forward_reference_body_annotations_are_sources(tmp_path: Path, annotation: str) -> None:
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


def test_pydantic_v1_model_body_is_source(tmp_path: Path) -> None:
    src = """
        import os
        from fastapi import FastAPI
        from pydantic.v1 import BaseModel
        from wardline.decorators import trusted
        app = FastAPI()
        class Payload(BaseModel): command: str
        @app.post('/')
        @trusted(level='ASSURED')
        def run(body: Payload): os.system(body.command)
    """
    assert "PY-WL-108" in _defect_rules(tmp_path, src)


def test_route_heavy_discovery_stores_only_derived_route_data() -> None:
    routes = "\n".join(f"@app.get('/{index}')\ndef route_{index}(value: str): pass" for index in range(1000))
    tree = ast.parse(f"from fastapi import FastAPI\napp = FastAPI()\n{routes}\n")
    snapshots = discover_fastapi_route_receivers(
        tree,
        {},
        module="m",
        known_models=frozenset(),
    )
    assert len(snapshots) == 1000
    assert all(not snapshot.body_parameters and not snapshot.dependency_bindings for snapshot in snapshots.values())


def test_large_model_chain_degrades_loudly_with_bounded_work(tmp_path: Path) -> None:
    files = {
        "m0.py": "from pydantic import BaseModel\nclass Model0(BaseModel): pass\n",
        **{
            f"m{index}.py": (f"from m{index - 1} import Model{index - 1}\nclass Model{index}(Model{index - 1}): pass\n")
            for index in range(1, 80)
        },
    }
    paths = []
    for name, src in files.items():
        path = tmp_path / name
        path.write_text(src, encoding="utf-8")
        paths.append(path)

    findings = WardlineAnalyzer().analyze(paths, WardlineConfig(), root=tmp_path)
    finding = next(finding for finding in findings if finding.rule_id == "WLN-ENGINE-PYDANTIC-DISCOVERY-LIMIT")

    assert finding.severity is Severity.ERROR
    assert finding.kind is Kind.DEFECT
    assert finding.properties == {
        "reason": "work_budget_exceeded",
        "round": 18,
        "work": 14_960,
        "budget": 15_360,
        "next_round_cost": 1_600,
        "required_total": 16_560,
        "file_count": 80,
        "statement_count": 160,
        "known_model_count": 17,
        "absolute_cap_applied": False,
    }
    assert "required=16560" in finding.message


@pytest.mark.parametrize("reason", ["repeated_state", "round_limit_exceeded"])
def test_pydantic_discovery_state_degradation_reports_structural_context(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    reason: PydanticDiscoveryReason,
) -> None:
    path = tmp_path / "m.py"
    path.write_text("class Model: pass\n", encoding="utf-8")
    budget = PydanticDiscoveryBudget.from_counts(file_count=1, statement_count=1)
    result = PydanticDiscoveryResult(
        models=frozenset({"m.Model"}),
        degraded_reason=reason,
        round_number=2,
        work_completed=2,
        budget=budget,
        next_round_cost=None,
        required_total=None,
        known_model_count=1,
        model_counts_by_round=(1, 1),
    )
    monkeypatch.setattr(analyzer_module, "discover_project_pydantic_models", lambda _files: result, raising=False)

    findings = WardlineAnalyzer().analyze([path], WardlineConfig(), root=tmp_path)
    finding = next(finding for finding in findings if finding.rule_id == "WLN-ENGINE-PYDANTIC-DISCOVERY-LIMIT")

    assert finding.properties == {
        "reason": reason,
        "round": 2,
        "work": 2,
        "budget": 4_096,
        "file_count": 1,
        "statement_count": 1,
        "known_model_count": 1,
        "absolute_cap_applied": False,
    }
    assert "next_round_cost" not in finding.properties
    assert "required_total" not in finding.properties


def test_pydantic_discovery_budget_cap_is_visible_in_diagnostic(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "m.py"
    path.write_text("class Model: pass\n", encoding="utf-8")
    budget = PydanticDiscoveryBudget.from_counts(file_count=100_000, statement_count=0)
    result = PydanticDiscoveryResult(
        models=frozenset({"m.Model"}),
        degraded_reason="work_budget_exceeded",
        round_number=2,
        work_completed=4_900_000,
        budget=budget,
        next_round_cost=200_000,
        required_total=5_100_000,
        known_model_count=1,
        model_counts_by_round=(1,),
    )
    monkeypatch.setattr(analyzer_module, "discover_project_pydantic_models", lambda _files: result, raising=False)

    findings = WardlineAnalyzer().analyze([path], WardlineConfig(), root=tmp_path)
    finding = next(finding for finding in findings if finding.rule_id == "WLN-ENGINE-PYDANTIC-DISCOVERY-LIMIT")

    assert finding.properties == {
        "reason": "work_budget_exceeded",
        "round": 2,
        "work": 4_900_000,
        "budget": 5_000_000,
        "next_round_cost": 200_000,
        "required_total": 5_100_000,
        "file_count": 100_000,
        "statement_count": 0,
        "known_model_count": 1,
        "absolute_cap_applied": True,
    }
    assert "required=5100000" in finding.message


@pytest.mark.parametrize(
    ("alias_target", "annotation_src"),
    [
        ("typing.Annotated", "Annotated[()]"),
        ("typing_extensions.Annotated", "Annotated[()]"),
        ("typing.Optional", "Optional[()]"),
    ],
)
def test_empty_subscript_annotation_is_unknown_not_absent(alias_target: str, annotation_src: str) -> None:
    """An empty `Annotated[()]` / `Optional[()]` must read as UNINTERPRETABLE, never as nothing.

    There is no inner type to unwrap, so the unwrap branch has no element to take. It
    must record `_UNKNOWN_ANNOTATION` rather than yielding an empty candidate set:
    route_body_parameters seeds a body parameter when the annotation is unknown OR names
    a project model, so an empty set would silently DECLINE to seed an annotation we
    could not read — fail-open on attacker-controlled input. (wardline-release-1.5.0)
    """
    alias = alias_target.rsplit(".", 1)[1]
    tree = ast.parse(f"x: {annotation_src}")
    annotation = tree.body[0].annotation  # type: ignore[attr-defined]

    assert _annotation_candidates(annotation, {alias: alias_target}) == {"<unknown-annotation>"}


def test_empty_subscript_annotation_seeds_the_body_fail_closed(tmp_path: Path) -> None:
    """The unreadable annotation still seeds the route body, so the sink defect fires."""
    src = """
        import os
        from typing import Annotated
        from fastapi import FastAPI
        from wardline.decorators import trusted
        app = FastAPI()
        @app.post('/run')
        @trusted(level='ASSURED')
        def run(body: Annotated[()]):
            os.system(body.command)
    """

    assert "PY-WL-108" in _defect_rules(tmp_path, src)


def test_empty_subscript_annotation_does_not_abort_the_whole_scan(tmp_path: Path) -> None:
    """One unreadable file must never take the scan down with it (per-file isolation).

    Regression pin for the release-1.5.0 review finding: `_annotation_candidates` took
    `elements[0]` unguarded, and the route-receiver discovery that reaches it runs in a
    comprehension OUTSIDE any per-file try, so a single `Annotated[()]` raised IndexError
    out of `run_scan` and the WHOLE project produced zero findings. The invariant under
    test is the one `WardlineAnalyzer` documents: a file that cannot be analyzed is
    recorded, and every other file is still analyzed.
    """
    (tmp_path / "bad.py").write_text(
        textwrap.dedent(
            """
            from typing import Annotated
            from fastapi import FastAPI
            app = FastAPI()
            @app.post('/x')
            def handler(body: Annotated[()]):
                return None
            """
        ),
        encoding="utf-8",
    )
    (tmp_path / "good.py").write_text(
        textwrap.dedent(
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
            """
        ),
        encoding="utf-8",
    )

    result = run_scan(tmp_path)

    assert result.files_scanned == 2
    assert "PY-WL-108" in {f.rule_id for f in result.findings if f.kind is Kind.DEFECT}
