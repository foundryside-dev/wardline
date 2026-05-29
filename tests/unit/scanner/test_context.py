from __future__ import annotations

import ast

from wardline.core.finding import Finding, Kind, Location, Severity
from wardline.core.taints import TaintState as T
from wardline.scanner.context import AnalysisContext, RuleRegistry
from wardline.scanner.index import Entity


def _entity(q: str) -> Entity:
    node = ast.parse("def f(): pass").body[0]
    assert isinstance(node, ast.FunctionDef)
    return Entity(qualname=q, kind="function", node=node, location=Location(path="m.py"))


def test_context_holds_engine_outputs() -> None:
    ctx = AnalysisContext(
        project_taints={"m.f": T.UNKNOWN_RAW},
        project_return_taints={"m.f": T.UNKNOWN_RAW},
        function_var_taints={"m.f": {"x": T.INTEGRAL}},
        function_return_taints={},
        entities={"m.f": _entity("m.f")},
        taint_provenance={},
    )
    assert ctx.project_taints["m.f"] == T.UNKNOWN_RAW
    assert ctx.function_var_taints["m.f"]["x"] == T.INTEGRAL
    assert ctx.entities["m.f"].qualname == "m.f"


def test_empty_registry_runs_no_rules() -> None:
    reg = RuleRegistry()
    assert reg.rules == ()
    ctx = AnalysisContext(
        project_taints={}, project_return_taints={}, function_var_taints={},
        function_return_taints={}, entities={}, taint_provenance={}
    )
    assert reg.run(ctx) == []


def test_registry_runs_registered_rule() -> None:
    finding = Finding(
        rule_id="X", message="m", severity=Severity.INFO, kind=Kind.FACT,
        location=Location(path="m.py"), fingerprint="fp",
    )

    class _Rule:
        rule_id = "X"

        def check(self, context: AnalysisContext):  # noqa: ANN201, ARG002
            return [finding]

    reg = RuleRegistry()
    reg.register(_Rule())
    ctx = AnalysisContext(
        project_taints={}, project_return_taints={}, function_var_taints={},
        function_return_taints={}, entities={}, taint_provenance={}
    )
    assert reg.run(ctx) == [finding]
    assert len(reg.rules) == 1
