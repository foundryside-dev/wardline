from __future__ import annotations

import ast

from wardline.core.config import WardlineConfig
from wardline.core.run import run_scan
from wardline.core.taints import TaintState
from wardline.scanner.pipeline import L2FunctionInput, ParseProjectInput, run_l2_function_stage, run_parse_project_stage
from wardline.scanner.taint.decorator_provider import DecoratorTaintSourceProvider, vocabulary_star_exports
from wardline.scanner.taint.provider import SeedContext, SeedResult

T = TaintState


def test_l2_function_stage_returns_explicit_typed_output() -> None:
    tree = ast.parse("def f(p):\n    x = read_raw(p)\n    sink(x)\n    return x\n")
    node = tree.body[0]
    assert isinstance(node, ast.FunctionDef)
    sink_call = next(
        call
        for call in ast.walk(node)
        if isinstance(call, ast.Call) and isinstance(call.func, ast.Name) and call.func.id == "sink"
    )

    result = run_l2_function_stage(
        L2FunctionInput(
            node=node,
            function_taint=T.INTEGRAL,
            taint_map={"read_raw": T.EXTERNAL_RAW},
            alias_map={},
            module_prefix="svc",
        )
    )

    assert result.variable_taints["x"] == T.EXTERNAL_RAW
    assert result.return_taint == T.EXTERNAL_RAW
    assert result.return_callee == "read_raw"
    assert result.call_site_arg_taints[id(sink_call)][0] == T.EXTERNAL_RAW


def test_parse_project_stage_returns_typed_modules_and_dirty_scope(tmp_path) -> None:
    path = tmp_path / "m.py"
    path.write_text(
        "from wardline.decorators import external_boundary\n@external_boundary\ndef read_raw(p):\n    return p\n",
        encoding="utf-8",
    )

    result = run_parse_project_stage(
        ParseProjectInput(
            files=(path,),
            root=tmp_path,
            provider=DecoratorTaintSourceProvider(),
            config=WardlineConfig(),
            star_exports=vocabulary_star_exports(),
        )
    )

    assert result.parse_findings == []
    assert result.dirty_modules == frozenset({"m"})
    assert result.modules[0].module_path == "m"
    assert result.files[0].relpath == "m.py"
    assert result.files[0].module == "m"
    assert result.files[0].entities[0].qualname == "m.read_raw"


def _shadow_project(tmp_path, root: str):  # noqa: ANN001, ANN202
    """Write an app that spoofs ``@trusted`` from a project-local shadow of *root*."""
    app = tmp_path / "app.py"
    app.write_text(
        f"from {root} import trusted\n@trusted\ndef unsafe(p):\n    return p\n",
        encoding="utf-8",
    )
    shadow_pkg = tmp_path / root / "decorators" if root == "wardline" else tmp_path / root
    shadow_pkg.mkdir(parents=True)
    if root == "wardline":
        (tmp_path / "wardline" / "__init__.py").write_text("", encoding="utf-8")
        files = (app, tmp_path / "wardline" / "__init__.py", shadow_pkg / "__init__.py")
    else:
        files = (app, shadow_pkg / "__init__.py")
    (shadow_pkg / "__init__.py").write_text("def trusted(fn):\n    return fn\n", encoding="utf-8")
    return app, files


def test_parse_project_stage_fails_closed_for_shadowed_wardline_decorators(tmp_path) -> None:
    _app, files = _shadow_project(tmp_path, "wardline")
    result = run_parse_project_stage(
        ParseProjectInput(
            files=files,
            root=tmp_path,
            provider=DecoratorTaintSourceProvider(),
            config=WardlineConfig(),
            star_exports=vocabulary_star_exports(),
        )
    )
    app_module = next(m for m in result.modules if m.module_path == "app")
    seed = app_module.seeds["app.unsafe"]
    assert seed.source == "default"
    assert seed.body_taint == T.UNKNOWN_RAW
    assert "shadowed-roots=" in result.provider_fingerprint
    assert "wardline" in result.provider_fingerprint


def test_parse_project_stage_fails_closed_for_shadowed_weft_markers(tmp_path) -> None:
    # The generalization the codex PR left open: shadowing ``weft_markers`` must also
    # fail closed and the shadow bit must reach the provider fingerprint.
    _app, files = _shadow_project(tmp_path, "weft_markers")
    result = run_parse_project_stage(
        ParseProjectInput(
            files=files,
            root=tmp_path,
            provider=DecoratorTaintSourceProvider(),
            config=WardlineConfig(),
            star_exports=vocabulary_star_exports(),
        )
    )
    app_module = next(m for m in result.modules if m.module_path == "app")
    seed = app_module.seeds["app.unsafe"]
    assert seed.source == "default"
    assert seed.body_taint == T.UNKNOWN_RAW
    assert "weft_markers" in result.provider_fingerprint


def test_parse_project_stage_unshadowed_fingerprint_is_bare(tmp_path) -> None:
    # No shadow → today's exact (cache/baseline-stable) fingerprint, no suffix.
    path = tmp_path / "m.py"
    path.write_text(
        "from wardline.decorators import trusted\n@trusted\ndef f(p):\n    return p\n",
        encoding="utf-8",
    )
    result = run_parse_project_stage(
        ParseProjectInput(
            files=(path,),
            root=tmp_path,
            provider=DecoratorTaintSourceProvider(),
            config=WardlineConfig(),
            star_exports=vocabulary_star_exports(),
        )
    )
    assert "shadowed-roots=" not in result.provider_fingerprint
    assert result.provider_fingerprint == DecoratorTaintSourceProvider().fingerprint()
    seed = result.modules[0].seeds["m.f"]
    assert seed.body_taint == T.INTEGRAL


def test_parse_project_stage_records_entity_qualname_config_source_match(tmp_path) -> None:
    # An untrusted_sources entry naming a project entity qualname is APPLIED here
    # (the seed override below) — the match must be reported back to the analyzer
    # so the directive is never misreported as WLN-CONFIG-UNUSED-SOURCE.
    path = tmp_path / "m.py"
    path.write_text("def get_input():\n    return 'x'\n", encoding="utf-8")
    result = run_parse_project_stage(
        ParseProjectInput(
            files=(path,),
            root=tmp_path,
            provider=DecoratorTaintSourceProvider(),
            config=WardlineConfig(untrusted_sources=("m.get_input", "elsewhere.unmatched")),
            star_exports=vocabulary_star_exports(),
        )
    )
    seed = result.modules[0].seeds["m.get_input"]
    assert seed.body_taint == T.EXTERNAL_RAW  # the directive took effect...
    assert result.matched_config_sources == frozenset({"m.get_input"})  # ...and is recorded
    # The unmatched entry is NOT recorded — the unused-source diagnostic stays live.


def test_parse_project_stage_parse_failure_is_gating_error_defect(tmp_path) -> None:
    # A discovered-but-unparseable file is a gate-eligible ERROR DEFECT (fail-closed:
    # unscanned code must not pass the default --fail-on ERROR loop), never a NONE
    # FACT. line_start is ALWAYS set (fallback 1) so the lineless-DEFECT downgrade
    # in suppression.py cannot demote a no-line encoding failure out of the gate.
    from wardline.core.finding import Kind, Severity

    (tmp_path / "syntax.py").write_text("def f(:\n", encoding="utf-8")
    (tmp_path / "enc.py").write_bytes(b'# -*- coding: latin-1 -*-\nx = "\xe9"\n')
    result = run_parse_project_stage(
        ParseProjectInput(
            files=(tmp_path / "syntax.py", tmp_path / "enc.py"),
            root=tmp_path,
            provider=DecoratorTaintSourceProvider(),
            config=WardlineConfig(),
            star_exports=vocabulary_star_exports(),
        )
    )
    by_path = {f.location.path: f for f in result.parse_findings}
    assert set(by_path) == {"syntax.py", "enc.py"}
    for finding in by_path.values():
        assert finding.rule_id == "WLN-ENGINE-PARSE-ERROR"
        assert finding.kind is Kind.DEFECT
        assert finding.severity is Severity.ERROR
        assert finding.location.line_start is not None
    # The syntax error keeps its real line; the encoding error falls back to 1.
    assert by_path["syntax.py"].location.line_start == 1
    assert by_path["enc.py"].location.line_start == 1


def test_parse_project_stage_recursion_skip_is_gate_eligible(tmp_path) -> None:
    # A recursion-limit file skip means policy rules never ran for the file. It
    # must be a gate-eligible under-scan defect, not a green severity result.
    from wardline.core.finding import Kind, Severity

    expr = "p" + " + p" * 3000
    (tmp_path / "deep.py").write_text(f"def deep(p):\n    x = {expr}\n    return x\n", encoding="utf-8")
    result = run_parse_project_stage(
        ParseProjectInput(
            files=(tmp_path / "deep.py",),
            root=tmp_path,
            provider=DecoratorTaintSourceProvider(),
            config=WardlineConfig(),
            star_exports=vocabulary_star_exports(),
        )
    )
    skips = [f for f in result.parse_findings if f.rule_id == "WLN-ENGINE-FILE-SKIPPED"]
    assert len(skips) == 1
    assert skips[0].kind is Kind.DEFECT
    assert skips[0].severity is Severity.ERROR
    assert skips[0].location.line_start == 1


class _CensusRecordingProvider:
    """Records the ``SeedContext`` census the parse loop handed the provider."""

    def __init__(self) -> None:
        self.seen: list[SeedContext] = []

    def taint_for(self, entity, ctx: SeedContext) -> SeedResult:  # noqa: ANN001, ARG002
        self.seen.append(ctx)
        return SeedResult(taint=None)

    def fingerprint(self) -> str:
        return "census-recording-v1"


def test_parse_loop_builds_one_census_per_module(tmp_path) -> None:
    # THE SINGLE BUILD. ``SeedContext`` and ``ParsedFile`` must receive the SAME
    # object, not two censuses that happen to compare equal — hence ``is``. A frozen
    # dataclass equality check would pass over two independent builds and the test
    # would not discriminate, which is exactly the drift this pins out.
    path = tmp_path / "svc.py"
    path.write_text(
        "from wardline.decorators import trusted\n"
        "_LEVEL = 'ASSURED'\n"
        "@trusted(level=_LEVEL)\n"
        "def f(p):\n"
        "    return p\n",
        encoding="utf-8",
    )
    provider = _CensusRecordingProvider()
    result = run_parse_project_stage(
        ParseProjectInput(
            files=(path,),
            root=tmp_path,
            provider=provider,
            config=WardlineConfig(),
            star_exports=vocabulary_star_exports(),
        )
    )

    assert provider.seen, "the provider was never called — the fixture seeds nothing"
    census = provider.seen[0].census
    # One census per MODULE, not one per entity — compared by identity because
    # ``ModuleCensus`` holds a mappingproxy and is therefore unhashable.
    assert all(ctx.census is census for ctx in provider.seen)
    assert census is not None
    assert result.files[0].census is census  # identity, not equality
    # ...and it is a REAL census, so the assertion above cannot be satisfied by two
    # matching empties.
    assert census.values["_LEVEL"].token == "ASSURED"


def test_seed_context_and_parsed_file_censuses_are_per_module(tmp_path) -> None:
    (tmp_path / "a.py").write_text("A = 'ASSURED'\ndef f(p):\n    return p\n", encoding="utf-8")
    (tmp_path / "b.py").write_text("B = 'INTEGRAL'\ndef g(p):\n    return p\n", encoding="utf-8")
    provider = _CensusRecordingProvider()
    result = run_parse_project_stage(
        ParseProjectInput(
            files=(tmp_path / "a.py", tmp_path / "b.py"),
            root=tmp_path,
            provider=provider,
            config=WardlineConfig(),
            star_exports=vocabulary_star_exports(),
        )
    )
    by_module = {parsed.module: parsed.census for parsed in result.files}
    assert set(by_module["a"].values) == {"A", "f"}
    assert set(by_module["b"].values) == {"B", "g"}
    assert by_module["a"] is not by_module["b"]


def test_census_reaches_a_rule_on_the_analysers_real_construction_path(tmp_path) -> None:
    # END-TO-END: the object the parse loop built IS the object a rule receives, and
    # the reference-site set holds the entity's OWN node — the identity relation form
    # 5 depends on. Driven through ``run_scan``, never a hand-built context.
    (tmp_path / "svc.py").write_text("def f(p):\n    return p\n", encoding="utf-8")
    result = run_scan(tmp_path)
    assert result.context is not None
    assert result.context.entities["svc.f"].node in result.context.module_censuses["svc"].reference_sites


def test_config_source_override_preserves_unknown_markers(tmp_path) -> None:
    # The configured-source override (the FunctionSeed reconstruction below the
    # seeding call) must PRESERVE the observability channels, not void them.
    path = tmp_path / "m.py"
    path.write_text(
        "import weft_markers\n@weft_markers.audit_record\ndef feed(e):\n    return e\n",
        encoding="utf-8",
    )
    result = run_parse_project_stage(
        ParseProjectInput(
            files=(path,),
            root=tmp_path,
            provider=DecoratorTaintSourceProvider(),
            config=WardlineConfig(untrusted_sources=("m.feed",)),
            star_exports=vocabulary_star_exports(),
        )
    )
    seed = result.modules[0].seeds["m.feed"]
    assert seed.body_taint == T.EXTERNAL_RAW  # the directive took effect...
    assert seed.unknown_markers == ((0, "weft_markers.audit_record"),)  # ...channel intact


def test_config_source_override_preserves_unprovable_boundaries(tmp_path) -> None:
    # Pre-existing bug closed by the same edit: the reconstruction hardcoded
    # unprovable_boundaries=() — a config-declared source that ALSO carried an
    # unprovable CUSTOM boundary lost its WLN-ENGINE-UNPROVABLE-BOUNDARY FACT.
    from wardline.scanner.boundary_types import BUILTIN_BOUNDARY_TYPES, BoundaryType, LevelArg
    from wardline.scanner.taint.provider import FunctionTaint

    custom = BoundaryType(
        "sanitized",
        "myproj.trust",
        1,
        (LevelArg("to_level", frozenset({T.GUARDED, T.ASSURED}), None),),
        lambda lv: FunctionTaint(T.EXTERNAL_RAW, lv["to_level"]),
    )
    path = tmp_path / "m.py"
    path.write_text(
        "import myproj.trust\n@myproj.trust.sanitized(to_level=CFG)\ndef feed(e):\n    return e\n",
        encoding="utf-8",
    )
    result = run_parse_project_stage(
        ParseProjectInput(
            files=(path,),
            root=tmp_path,
            provider=DecoratorTaintSourceProvider(boundary_types=BUILTIN_BOUNDARY_TYPES + (custom,)),
            config=WardlineConfig(untrusted_sources=("m.feed",)),
            star_exports=vocabulary_star_exports(),
        )
    )
    seed = result.modules[0].seeds["m.feed"]
    assert seed.body_taint == T.EXTERNAL_RAW
    assert seed.unprovable_boundaries == ("sanitized",)


def test_config_source_override_preserves_unreadable_level_values(tmp_path) -> None:
    # Spec §4.2.1 soundness condition 1: the residual FACT must NOT be voided by
    # configuration. The override block is a wholesale FunctionSeed reconstruction,
    # so without this test the third channel can be dropped from it and nothing reds.
    # DYN has a CALL right-hand side, which form 5 explicitly refuses, so the value
    # stays unreadable; the recorded value text is ast.unparse of the LEVEL slot's
    # own node ('DYN'), never the binding's right-hand side.
    path = tmp_path / "m.py"
    path.write_text(
        "from wardline.decorators import trusted\n"
        "def get_level():\n    return 'ASSURED'\n"
        "DYN = get_level()\n"
        "@trusted(level=DYN)\ndef feed(e):\n    return e\n",
        encoding="utf-8",
    )
    result = run_parse_project_stage(
        ParseProjectInput(
            files=(path,),
            root=tmp_path,
            provider=DecoratorTaintSourceProvider(),
            config=WardlineConfig(untrusted_sources=("m.feed",)),
            star_exports=vocabulary_star_exports(),
        )
    )
    seed = result.modules[0].seeds["m.feed"]
    assert seed.body_taint == T.EXTERNAL_RAW  # the directive took effect...
    assert seed.unreadable_level_values == ((0, "level", "DYN"),)  # ...channel intact


def test_provable_sibling_marker_still_carries_the_unreadable_level_value(tmp_path) -> None:
    # NOT the config-override path: this pins the OTHER FunctionSeed constructor. When a
    # provable marker co-occurs with a builtin whose LEVEL value is unreadable, the seed
    # takes the source="provider" branch of seed_function_taints — and the residual pair
    # must survive that branch too. Without this the pair is only ever observed on the
    # taint-is-None branch, and dropping the field from the provider branch reds nothing.
    path = tmp_path / "m.py"
    path.write_text(
        "from wardline.decorators import external_boundary, trusted\n"
        "def get_level():\n    return 'ASSURED'\n"
        "DYN = get_level()\n"
        "@external_boundary\n@trusted(level=DYN)\ndef feed(e):\n    return e\n",
        encoding="utf-8",
    )
    result = run_parse_project_stage(
        ParseProjectInput(
            files=(path,),
            root=tmp_path,
            provider=DecoratorTaintSourceProvider(),
            config=WardlineConfig(),
            star_exports=vocabulary_star_exports(),
        )
    )
    seed = result.modules[0].seeds["m.feed"]
    assert seed.source == "provider"  # the provable sibling minted a seed...
    assert seed.body_taint == T.EXTERNAL_RAW
    assert seed.unreadable_level_values == ((1, "level", "DYN"),)  # ...and the value rode along


def test_two_unreadable_builtin_markers_yield_two_residual_pairs(tmp_path) -> None:
    # ARITY. ``_match``'s OWN return is capped at one pair (its levels loop breaks on the
    # first non-RESOLVED verdict), but ``taint_for`` EXTENDS across the decorator list, so
    # the public ``SeedResult`` / ``FunctionSeed`` field is UNBOUNDED. Task 8's emission
    # loop iterates it and its fingerprint preimage includes the argument name, so two
    # pairs are two distinct FACTs. A consumer that read ``values[0]`` would silently drop
    # the second — a fail-open on this channel — and nothing else in the suite would red.
    path = tmp_path / "m.py"
    path.write_text(
        "from wardline.decorators import trusted, trust_boundary\n"
        "def get_level():\n    return 'ASSURED'\n"
        "DYN = get_level()\n"
        "@trusted(level=DYN)\n@trust_boundary(to_level=DYN)\ndef feed(e):\n    return e\n",
        encoding="utf-8",
    )
    result = run_parse_project_stage(
        ParseProjectInput(
            files=(path,),
            root=tmp_path,
            provider=DecoratorTaintSourceProvider(),
            config=WardlineConfig(),
            star_exports=vocabulary_star_exports(),
        )
    )
    seed = result.modules[0].seeds["m.feed"]
    assert seed.unreadable_level_values == ((0, "level", "DYN"), (1, "to_level", "DYN"))
    assert len(seed.unreadable_level_values) == 2  # NOT capped at one — do not assume it is
