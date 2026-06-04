from __future__ import annotations

import ast

import pytest

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
        function_return_callee={},
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
        project_taints={},
        project_return_taints={},
        function_var_taints={},
        function_return_taints={},
        function_return_callee={},
        entities={},
        taint_provenance={},
    )
    assert reg.run(ctx) == []


def test_registry_runs_registered_rule() -> None:
    finding = Finding(
        rule_id="X",
        message="m",
        severity=Severity.INFO,
        kind=Kind.FACT,
        location=Location(path="m.py"),
        fingerprint="fp",
    )

    class _Rule:
        rule_id = "X"

        def check(self, context: AnalysisContext):  # noqa: ANN201, ARG002
            return [finding]

    reg = RuleRegistry()
    reg.register(_Rule())
    ctx = AnalysisContext(
        project_taints={},
        project_return_taints={},
        function_var_taints={},
        function_return_taints={},
        function_return_callee={},
        entities={},
        taint_provenance={},
    )
    assert reg.run(ctx) == [finding]
    assert len(reg.rules) == 1


def test_context_deep_freezes_nested_mappings_and_source_dicts() -> None:
    source_vars = {"x": T.INTEGRAL}
    source_call_sites = {123: {"x": T.INTEGRAL}}
    ctx = AnalysisContext(
        project_taints={},
        project_return_taints={},
        function_var_taints={"m.f": source_vars},
        function_return_taints={},
        function_return_callee={},
        entities={},
        taint_provenance={},
        function_call_site_taints={"m.f": source_call_sites},
        class_attr_taints={"m.C": {"attr": T.INTEGRAL}},
    )

    with pytest.raises(TypeError):
        ctx.function_var_taints["m.f"]["x"] = T.EXTERNAL_RAW  # type: ignore[index]
    with pytest.raises(TypeError):
        ctx.function_call_site_taints["m.f"][123]["x"] = T.EXTERNAL_RAW  # type: ignore[index]
    with pytest.raises(TypeError):
        ctx.class_attr_taints["m.C"]["attr"] = T.EXTERNAL_RAW  # type: ignore[index]

    source_vars["x"] = T.EXTERNAL_RAW
    source_call_sites[123]["x"] = T.EXTERNAL_RAW

    assert ctx.function_var_taints["m.f"]["x"] == T.INTEGRAL
    assert ctx.function_call_site_taints["m.f"][123]["x"] == T.INTEGRAL


def test_registry_rule_cannot_mutate_nested_context_for_later_rules() -> None:
    finding = Finding(
        rule_id="X",
        message="m",
        severity=Severity.INFO,
        kind=Kind.FACT,
        location=Location(path="m.py"),
        fingerprint="fp",
    )
    ctx = AnalysisContext(
        project_taints={},
        project_return_taints={},
        function_var_taints={"m.f": {"x": T.INTEGRAL}},
        function_return_taints={},
        function_return_callee={},
        entities={},
        taint_provenance={},
    )

    class _MutatingRule:
        rule_id = "MUT"

        def check(self, context: AnalysisContext) -> list[Finding]:
            with pytest.raises(TypeError):
                context.function_var_taints["m.f"]["x"] = T.EXTERNAL_RAW  # type: ignore[index]
            return []

    class _ObservingRule:
        rule_id = "X"

        def check(self, context: AnalysisContext) -> list[Finding]:
            assert context.function_var_taints["m.f"]["x"] == T.INTEGRAL
            return [finding]

    reg = RuleRegistry()
    reg.register(_MutatingRule())
    reg.register(_ObservingRule())

    assert reg.run(ctx) == [finding]
