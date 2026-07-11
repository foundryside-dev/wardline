# FastAPI Input Coverage Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the precise FastAPI request-member false negatives and add route-aware Pydantic body seeding without tainting ordinary `BaseModel` parameters or dependency-provider results.

**Architecture:** Implement the two existing children of parent `wardline-7b4c550e21` as two commits: `wardline-4b728106c8` for precise request members and `wardline-fff71be81a` for route bodies. Track A extends the existing typed-request source model with exact nested-member matching and regression pins; Track B adds a small FastAPI route classifier that supplies an explicit set of body parameter names to L2 parameter seeding. The classifier recognizes Pydantic models and FastAPI route decorators from alias-resolved syntax, while `Depends(...)` parameters and non-route functions remain negative controls.

**Tech Stack:** Python 3.12+, stdlib `ast`, Wardline L2 taint analysis, pytest, Filigree CLI, Ruff, mypy

---

## File map

- Modify: `src/wardline/scanner/taint/variable_level.py:163-186, 416-451, 656-794, 895-946, 1174-1245` — add the FastAPI re-export, exact nested request sources, and explicit route-body parameter seeds.
- Create: `src/wardline/scanner/taint/fastapi_sources.py` — pure alias-aware discovery of FastAPI route receivers, route decorators, Pydantic model classes, `Depends` defaults, and route-body parameter names.
- Modify: `src/wardline/scanner/analyzer.py:573-736, 800-900` — precompute project Pydantic model identities and pass per-entity route-body parameters into every initial and fixed-point L2 run.
- Modify: `tests/unit/scanner/rules/test_fastapi_request_source.py:1-326` — exact positive and negative request-member controls, including already-working stream/multidict behaviors.
- Create: `tests/unit/scanner/rules/test_fastapi_route_body_source.py` — route-body positive cases and precision controls.

## Task 1: Verify the two existing atomic work tickets

**Files:**
- No repository files.
- Tracker: parent `wardline-7b4c550e21`, child `wardline-4b728106c8`, and child `wardline-fff71be81a`.

- [ ] **Step 1: Verify both approved children and their transitions**

```bash
filigree show wardline-4b728106c8 --json
filigree transitions wardline-4b728106c8 --json
filigree show wardline-fff71be81a --json
filigree transitions wardline-fff71be81a --json
```

Expected: both are open tasks with `parent_issue_id=wardline-7b4c550e21` and a startable `in_progress` transition.

- [ ] **Step 2: Record the approved split on the parent**

```bash
filigree add-comment wardline-7b4c550e21 \
  "Approved split confirmed: wardline-4b728106c8 owns precise request-member additions; wardline-fff71be81a owns route-aware Pydantic body parameters. Each child receives its own red/green proof, commit, and closeout; the parent closes only after both children close." \
  --actor john
```

Expected: the parent remains `open`; comment names both children.

## Task 2: Track A — add exact request-member sources

**Files:**
- Modify: `tests/unit/scanner/rules/test_fastapi_request_source.py:30-326`
- Modify: `src/wardline/scanner/taint/variable_level.py:163-186, 895-946`

- [ ] **Step 1: Start the request-member child atomically**

```bash
filigree start-work wardline-4b728106c8 --assignee codex --actor john --advance --commit "release/consolidation-2026-06-26@388f3841d4d0"
filigree add-comment wardline-4b728106c8 \
  "Root cause: request-source recognition has only two Request FQNs and only one-level property/method matching; generic Attribute/Subscript propagation therefore keeps url.query and scope['query_string'] at the clean request-object taint." \
  --actor john
```

Expected: child status is `in_progress` and assignee is `codex`.

- [ ] **Step 2: Add failing exact-member cases and the FastAPI re-export**

Extend `_MUST_FIRE` in `tests/unit/scanner/rules/test_fastapi_request_source.py` with:

```python
"fastapi_requests_reexport": """
    import os
    from wardline.decorators import trusted
    from fastapi.requests import Request

    @trusted(level='ASSURED')
    def h(req: Request):
        os.system(req.query_params.get('x'))
""",
"url_query": """
    import os
    from wardline.decorators import trusted
    from fastapi import Request

    @trusted(level='ASSURED')
    def h(req: Request):
        os.system(req.url.query)
""",
"scope_query_string": """
    import os
    from wardline.decorators import trusted
    from fastapi import Request

    @trusted(level='ASSURED')
    def h(req: Request):
        os.system(req.scope['query_string'])
""",
```

Retain the existing `url_path`, `scope_subscript`, `app_bare`, `app_state_db`, `state_attr`, and `client_host` entries in `_MUST_NOT_FIRE`; do not weaken or rename them.

- [ ] **Step 3: Pin already-working async stream, multidict, and Depends behavior**

Add these explicit regression cases:

```python
_EXISTING_BEHAVIOR_MUST_FIRE = {
    "async_stream_iteration": """
        import os
        from wardline.decorators import trusted
        from fastapi import Request

        @trusted(level='ASSURED')
        async def h(req: Request):
            async for chunk in req.stream():
                os.system(chunk)
    """,
    "multi_items": """
        import os
        from wardline.decorators import trusted
        from fastapi import Request

        @trusted(level='ASSURED')
        def h(req: Request):
            os.system(str(req.query_params.multi_items()))
    """,
    "getlist": """
        import os
        from wardline.decorators import trusted
        from fastapi import Request

        @trusted(level='ASSURED')
        def h(req: Request):
            os.system(str(req.query_params.getlist('x')))
    """,
}

@pytest.mark.parametrize("name", sorted(_EXISTING_BEHAVIOR_MUST_FIRE))
def test_existing_request_container_and_stream_flows_stay_visible(tmp_path: Path, name: str) -> None:
    assert "PY-WL-108" in _defect_rules(tmp_path, _EXISTING_BEHAVIOR_MUST_FIRE[name]), name

def test_depends_parameter_is_not_seeded_by_request_member_logic(tmp_path: Path) -> None:
    src = """
        import os
        from fastapi import Depends
        from wardline.decorators import trusted

        def validated_value() -> str:
            return 'fixed'

        @trusted(level='ASSURED')
        def h(value: str = Depends(validated_value)):
            os.system(value)
    """
    assert "PY-WL-108" not in _defect_rules(tmp_path, src)
```

- [ ] **Step 4: Run the focused test to prove the new cases fail**

Run: `uv run pytest tests/unit/scanner/rules/test_fastapi_request_source.py -q`

Expected: FAIL for `fastapi_requests_reexport`, `url_query`, and `scope_query_string`; the existing-behavior controls pass.

- [ ] **Step 5: Implement exact nested-member matching**

In `src/wardline/scanner/taint/variable_level.py`, keep whole `url` and `scope` clean and add only these identities:

```python
_REQUEST_SOURCE_TYPES: dict[str, _RequestMembers] = {
    "fastapi.Request": _STARLETTE_REQUEST_MEMBERS,
    "fastapi.requests.Request": _STARLETTE_REQUEST_MEMBERS,
    "starlette.requests.Request": _STARLETTE_REQUEST_MEMBERS,
}

_REQUEST_NESTED_ATTRIBUTE_SOURCES: frozenset[tuple[str, str]] = frozenset(
    {("url", "query")}
)
_REQUEST_NESTED_SUBSCRIPT_SOURCES: frozenset[tuple[str, str]] = frozenset(
    {("scope", "query_string")}
)

def _request_receiver_fqns(name: str) -> tuple[str, ...]:
    var_types = _CURRENT_VAR_TYPES.get()
    if var_types is None:
        return ()
    return tuple(fqn for fqn in var_types.get(name, ()) if fqn in _REQUEST_SOURCE_TYPES)

def _constant_string(node: ast.expr) -> str | None:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None

def _is_exact_nested_request_source(node: ast.expr) -> bool:
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Attribute):
        base = node.value
        return (
            isinstance(base.value, ast.Name)
            and bool(_request_receiver_fqns(base.value.id))
            and (base.attr, node.attr) in _REQUEST_NESTED_ATTRIBUTE_SOURCES
        )
    if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Attribute):
        base = node.value
        return (
            isinstance(base.value, ast.Name)
            and bool(_request_receiver_fqns(base.value.id))
            and (base.attr, _constant_string(node.slice)) in _REQUEST_NESTED_SUBSCRIPT_SOURCES
        )
    return False
```

At the start of the `ast.Subscript` and `ast.Attribute` branches in `_resolve_expr`, return `TaintState.EXTERNAL_RAW` when `_is_exact_nested_request_source(node)` is true. Preserve all existing generic propagation after that check.

- [ ] **Step 6: Run Track A tests and adjacent L2 tests**

Run:

```bash
uv run pytest tests/unit/scanner/rules/test_fastapi_request_source.py -q
uv run pytest tests/unit/scanner/taint/test_variable_level.py -q
```

Expected: PASS; specifically `url.path`, `scope['path']`, `app`, `state`, and `client` remain quiet.

- [ ] **Step 7: Commit and close only Track A**

```bash
git add src/wardline/scanner/taint/variable_level.py tests/unit/scanner/rules/test_fastapi_request_source.py
git commit -m "fix: cover precise FastAPI request members"
TRACK_A_SHA="$(git rev-parse HEAD)"
filigree add-comment wardline-4b728106c8 \
  "Verified exact FastAPI Request re-export and nested query sources; negative controls keep url.path, scope['path'], app, state, and client clean. Focused request-source and L2 suites pass. Commit ${TRACK_A_SHA}." \
  --actor john
filigree close wardline-4b728106c8 --reason "Implemented and verified" --commit "release/consolidation-2026-06-26@${TRACK_A_SHA}" --actor john
```

Expected: one commit containing only Track A files; child is `closed`.

## Task 3: Track B — classify Pydantic body parameters only on FastAPI routes

**Files:**
- Create: `tests/unit/scanner/rules/test_fastapi_route_body_source.py`
- Create: `src/wardline/scanner/taint/fastapi_sources.py`
- Modify: `src/wardline/scanner/taint/variable_level.py:416-451, 656-794`
- Modify: `src/wardline/scanner/analyzer.py:573-736, 800-900`

- [ ] **Step 1: Start Track B and record the root cause**

```bash
filigree start-work wardline-fff71be81a --assignee codex --actor john --advance --commit "release/consolidation-2026-06-26@$(git rev-parse HEAD)"
filigree add-comment wardline-fff71be81a \
  "Root cause: L2 parameter seeding knows annotations only as receiver types; it has no route context and therefore cannot distinguish attacker-supplied FastAPI body models from identical BaseModel parameters in ordinary trusted functions." \
  --actor john
```

Expected: Track B is `in_progress` under `codex`.

- [ ] **Step 2: Write the failing route-body test matrix**

Create `tests/unit/scanner/rules/test_fastapi_route_body_source.py` with the same `_defect_rules` helper as the request-source test and these required cases:

```python
@pytest.mark.parametrize(
    ("name", "src"),
    [
        ("direct_model", """
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
        """),
        ("aliased_import", """
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
        """),
    ],
)
def test_fastapi_route_model_body_fires(tmp_path: Path, name: str, src: str) -> None:
    assert "PY-WL-108" in _defect_rules(tmp_path, src), name

@pytest.mark.parametrize(
    ("name", "src"),
    [
        ("ordinary_function", """
            import os
            from pydantic import BaseModel
            from wardline.decorators import trusted
            class Payload(BaseModel):
                command: str
            @trusted(level='ASSURED')
            def helper(body: Payload):
                os.system(body.command)
        """),
        ("depends_provider", """
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
        """),
        ("coincidental_get_decorator", """
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
        """),
    ],
)
def test_non_body_model_parameters_stay_clean(tmp_path: Path, name: str, src: str) -> None:
    assert "PY-WL-108" not in _defect_rules(tmp_path, src), name
```

- [ ] **Step 3: Run the new test to verify red behavior**

Run: `uv run pytest tests/unit/scanner/rules/test_fastapi_route_body_source.py -q`

Expected: direct and aliased FastAPI route cases FAIL; all three negative controls PASS.

- [ ] **Step 4: Add a pure route/body classifier**

Create `src/wardline/scanner/taint/fastapi_sources.py` with these closed sets and interfaces:

```python
from __future__ import annotations

import ast
from collections.abc import Mapping

_FASTAPI_CONSTRUCTORS = frozenset({"fastapi.FastAPI", "fastapi.routing.APIRouter", "fastapi.APIRouter"})
_ROUTE_METHODS = frozenset({"get", "post", "put", "patch", "delete", "options", "head", "trace", "api_route", "websocket"})
_PYDANTIC_BASES = frozenset({"pydantic.BaseModel", "pydantic.main.BaseModel"})
_DEPENDS = frozenset({"fastapi.Depends", "fastapi.params.Depends"})

def resolve_dotted(node: ast.expr, aliases: Mapping[str, str]) -> str | None:
    if isinstance(node, ast.Name):
        return aliases.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        parent = resolve_dotted(node.value, aliases)
        return f"{parent}.{node.attr}" if parent else None
    return None

def discover_fastapi_route_receivers(tree: ast.Module, aliases: Mapping[str, str]) -> frozenset[str]:
    receivers: set[str] = set()
    for stmt in tree.body:
        if (
            isinstance(stmt, (ast.Assign, ast.AnnAssign))
            and isinstance(stmt.value, ast.Call)
            and resolve_dotted(stmt.value.func, aliases) in _FASTAPI_CONSTRUCTORS
        ):
            targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
            receivers.update(target.id for target in targets if isinstance(target, ast.Name))
    return frozenset(receivers)

def discover_pydantic_models(
    tree: ast.Module,
    *,
    module: str,
    aliases: Mapping[str, str],
    known_models: frozenset[str],
) -> frozenset[str]:
    found = set(known_models)
    pending = [stmt for stmt in tree.body if isinstance(stmt, ast.ClassDef)]
    changed = True
    while changed:
        changed = False
        for cls in pending:
            qualname = f"{module}.{cls.name}"
            bases = {resolve_dotted(base, aliases) for base in cls.bases}
            if qualname not in found and any(
                base in _PYDANTIC_BASES
                or base in found
                or (base is not None and any(model.endswith(f".{base}") for model in found))
                for base in bases
            ):
                found.add(qualname)
                changed = True
    return frozenset(found)

def route_body_parameters(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    *,
    aliases: Mapping[str, str],
    route_receivers: frozenset[str],
    pydantic_models: frozenset[str],
) -> frozenset[str]:
    is_route = any(
        isinstance(dec, ast.Call)
        and isinstance(dec.func, ast.Attribute)
        and isinstance(dec.func.value, ast.Name)
        and dec.func.value.id in route_receivers
        and dec.func.attr in _ROUTE_METHODS
        for dec in node.decorator_list
    )
    if not is_route:
        return frozenset()
    positional = [*node.args.posonlyargs, *node.args.args]
    defaults: dict[str, ast.expr] = {
        arg.arg: default
        for arg, default in zip(positional[-len(node.args.defaults) :], node.args.defaults, strict=True)
    } if node.args.defaults else {}
    defaults.update(
        {
            arg.arg: default
            for arg, default in zip(node.args.kwonlyargs, node.args.kw_defaults, strict=True)
            if default is not None
        }
    )
    body_params: set[str] = set()
    for arg in [*positional, *node.args.kwonlyargs]:
        annotation = resolve_dotted(arg.annotation, aliases) if arg.annotation else None
        is_model = annotation in pydantic_models or (
            annotation is not None and any(model.endswith(f".{annotation}") for model in pydantic_models)
        )
        default = defaults.get(arg.arg)
        is_dependency = (
            isinstance(default, ast.Call) and resolve_dotted(default.func, aliases) in _DEPENDS
        )
        if is_model and not is_dependency:
            body_params.add(arg.arg)
    return frozenset(body_params)
```

Do not import FastAPI or Pydantic at scan time. Preserve deterministic frozenset outputs.

- [ ] **Step 5: Thread only the classified names into L2 seeding**

Add `route_body_params: frozenset[str] = frozenset()` to `VariableTaintContext`. Thread it through `analyze_function_variables()` into `compute_variable_taints()` and `_seed_parameters()`.

Use this minimal seed in `_seed_parameters.handle_arg`:

```python
if arg.arg in route_body_params:
    seed_val = combine(seed_val, TaintState.EXTERNAL_RAW)
```

In `analyzer.py`, compute module route receivers and the project-wide Pydantic model set before the entity L2 loop, then call `route_body_parameters(...)` for each entity and store the result in the `_L2Record` so the identical value is passed during both the initial pass and every fixed-point rerun. Do not infer route status from function names or parameter names.

- [ ] **Step 6: Run the focused and neighboring regressions**

Run:

```bash
uv run pytest tests/unit/scanner/rules/test_fastapi_route_body_source.py -q
uv run pytest tests/unit/scanner/rules/test_fastapi_request_source.py -q
uv run pytest tests/unit/scanner/taint/test_variable_level.py tests/unit/scanner/test_analyzer_declared_qualnames.py -q
```

Expected: PASS; direct/aliased/nested body cases fire, ordinary functions, validated `Depends`, and coincidental decorators stay quiet.

- [ ] **Step 7: Commit and close Track B**

```bash
git add src/wardline/scanner/taint/fastapi_sources.py \
  src/wardline/scanner/taint/variable_level.py \
  src/wardline/scanner/analyzer.py \
  tests/unit/scanner/rules/test_fastapi_route_body_source.py
git commit -m "feat: classify FastAPI Pydantic route bodies"
TRACK_B_SHA="$(git rev-parse HEAD)"
filigree add-comment wardline-fff71be81a \
  "Verified route-aware Pydantic body seeding for direct models, aliases, and nested fields. Ordinary BaseModel parameters, Depends-provider returns, and coincidental decorators remain clean. Commit ${TRACK_B_SHA}." \
  --actor john
filigree close wardline-fff71be81a --reason "Implemented and verified" --commit "release/consolidation-2026-06-26@${TRACK_B_SHA}" --actor john
```

Expected: a second independent commit; Track B is `closed`.

## Task 4: Repository verification and parent closeout

**Files:**
- No additional production files.
- Tracker: `wardline-7b4c550e21`.

- [ ] **Step 1: Run the complete required verification stack**

```bash
uv run ruff check src tests
uv run ruff format --check src tests
uv run mypy
uv run pytest -q
uv run wardline scan . --fail-on ERROR
git diff --check
git status --short
```

Expected: all commands exit 0; Wardline reports no `ERROR` gate finding; status contains no generated scan artifact or unrelated file.

- [ ] **Step 2: Confirm both child issues are terminal before closing the umbrella**

```bash
filigree show wardline-4b728106c8 --json
filigree show wardline-fff71be81a --json
filigree add-comment wardline-7b4c550e21 \
  "Both split tracks are closed with separate commits. Full Ruff, format, mypy, pytest, Wardline gate, and diff checks pass; precision controls remain green." \
  --actor john
filigree close wardline-7b4c550e21 --reason "Both approved child tracks implemented and verified" --actor john
```

Expected: both children and parent are `closed`; no third code commit is created for tracker-only closeout.
