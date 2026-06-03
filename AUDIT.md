# Wardline Comprehensive Codebase Audit Report

This report compiles, synthesizes, and categorizes findings from a comprehensive read-only audit of the Wardline codebase. The audit was conducted using seven specialized subagents: Architecture Critic, Systems Thinker, Python Engineer, Quality Engineer, Security Architect, Static Tools Analyst, and MCP & CLI Specialist.

---

## 📋 Executive Summary of Findings

| Finding ID | Title | Severity | Location | Focus Area |
| :--- | :--- | :--- | :--- | :--- |
| **WLN-CRIT-01** | [Parameter Default Expressions Ignored](file:///home/john/wardline/src/wardline/scanner/taint/variable_level.py#L163-L185) | **Critical** | `src/wardline/scanner/taint/variable_level.py` | Systems / Taint Propagation |
| **WLN-HIGH-01** | [Python Standard Input Buffer blocking in MCP Server](file:///home/john/wardline/src/wardline/mcp/protocol.py#L107-L108) | **High** | `src/wardline/mcp/protocol.py` | CLI & MCP |
| **WLN-HIGH-02** | [Fragile Skip Invariant in File Discovery](file:///home/john/wardline/src/wardline/core/discovery.py#L32-L34) | **High** | `src/wardline/core/discovery.py` | Quality / Discovery |
| **WLN-HIGH-03** | [Lack of Import Alias Resolution in TaintedSinkRule](file:///home/john/wardline/src/wardline/scanner/rules/_sink_helpers.py#L76-L82) | **High** | `src/wardline/scanner/rules/_sink_helpers.py` | Static Analysis / Soundness |
| **WLN-HIGH-04** | [Soundness Gap for Generators Yielding Untrusted Data](file:///home/john/wardline/src/wardline/scanner/taint/variable_level.py#L1337-L1367) | **High** | `src/wardline/scanner/taint/variable_level.py` | Static Analysis / Soundness |
| **WLN-HIGH-05** | [Module-level import-time dependency on pyyaml in core modules](file:///home/john/wardline/src/wardline/core/baseline.py#L18) | **High** | `src/wardline/core/*` | Architecture / Layering |
| **WLN-HIGH-06** | [Static Analysis Bypass via Undecorated Nested Helper Functions](file:///home/john/wardline/src/wardline/scanner/rules/_sink_helpers.py#L215-L219) | **High** | `src/wardline/scanner/rules/*` | Python Engineering |
| **WLN-HIGH-07** | [Static Analysis Evasion via Lambda Expressions](file:///home/john/wardline/src/wardline/scanner/ast_primitives.py#L102-L103) | **High** | `src/wardline/scanner/ast_primitives.py` | Python Engineering |
| **WLN-MED-01** | [Transitive Import-Time Dependency on scanner from Base Core Modules](file:///home/john/wardline/src/wardline/core/assure.py#L40) | **Medium** | `src/wardline/core/*` | Architecture / Layering |
| **WLN-MED-02** | [Module-level Import of Optional Dependency (pyyaml) in Base Install](file:///home/john/wardline/src/wardline/install/pack.py#L8) | **Medium** | `src/wardline/install/pack.py` | Architecture / Layering |
| **WLN-MED-03** | [Import-Time Coupling in Dependency-Free MCP Server](file:///home/john/wardline/src/wardline/mcp/server.py#L24) | **Medium** | `src/wardline/mcp/*` | Architecture / Layering |
| **WLN-MED-04** | [Waiver Tool in MCP Server hardcodes configuration path](file:///home/john/wardline/src/wardline/mcp/server.py#L402) | **Medium** | `src/wardline/mcp/server.py` | CLI & MCP |
| **WLN-MED-05** | [Missing context_lines option in MCP judge tool](file:///home/john/wardline/src/wardline/mcp/server.py#L344-L356) | **Medium** | `src/wardline/mcp/server.py` | CLI & MCP |
| **WLN-MED-06** | [Absolute Path Match Failure in explain_finding](file:///home/john/wardline/src/wardline/core/explain.py#L77-L92) | **Medium** | `src/wardline/core/explain.py` | Quality / Explanations |
| **WLN-MED-07** | [Inconsistent Defaults for confine_to_root in Attestation](file:///home/john/wardline/src/wardline/core/attest.py#L270-L288) | **Medium** | `src/wardline/core/attest.py` | Quality / Integrity |
| **WLN-MED-08** | [Under-Tainting with **kwargs Unpacking](file:///home/john/wardline/src/wardline/scanner/analyzer.py#L317-L318) | **Medium** | `src/wardline/scanner/analyzer.py` | Static Analysis / Taint |
| **WLN-MED-09** | [Under-Tainting via Loop-Carried Dependencies](file:///home/john/wardline/src/wardline/scanner/taint/variable_level.py#L826-L897) | **Medium** | `src/wardline/scanner/taint/variable_level.py` | Static Analysis / Taint |
| **WLN-MED-10** | [Ineffective Caching / Performance Architecture Flaw](file:///home/john/wardline/src/wardline/scanner/analyzer.py#L111-L200) | **Medium** | `src/wardline/scanner/*` | Systems / Caching |
| **WLN-MED-11** | [Inert Configuration Option provenance_clash](file:///home/john/wardline/src/wardline/scanner/taint/propagation.py#L160-L182) | **Medium** | `src/wardline/scanner/*` | Systems / Taint Algebra |
| **WLN-MED-12** | [Git Ref Option/Argument Injection in get_changed_files_since](file:///home/john/wardline/src/wardline/core/delta.py#L34-L44) | **Medium** | `src/wardline/core/delta.py` | Security |
| **WLN-LOW-01** | [Incomplete MCP Handshake verification/enforcement](file:///home/john/wardline/src/wardline/mcp/protocol.py#L67-L78) | **Low** | `src/wardline/mcp/protocol.py` | CLI & MCP |
| **WLN-LOW-02** | [Undocumented path property in verify_attestation schema](file:///home/john/wardline/src/wardline/mcp/server.py#L607-L615) | **Low** | `src/wardline/mcp/server.py` | CLI & MCP |
| **WLN-LOW-03** | [Test Coverage Gaps in Error Hierarchy and Path Rejection](file:///home/john/wardline/tests/unit/core/test_errors.py#L1-L14) | **Low** | `tests/unit/core/*` | Quality / Robustness |
| **WLN-LOW-04** | [FQN Resolution Limitation for Nested/Dotted Attribute Calls](file:///home/john/wardline/src/wardline/scanner/ast_primitives.py#L171-L197) | **Low** | `src/wardline/scanner/ast_primitives.py` | Python / Static Analysis |
| **WLN-LOW-05** | [Redundant/Dead Code in SCC Propagation](file:///home/john/wardline/src/wardline/scanner/taint/propagation.py#L337-L347) | **Low** | `src/wardline/scanner/taint/propagation.py` | Static Analysis / Tarjan |
| **WLN-LOW-06** | [Transitive Core-Scanner Coupling in Clarion Extra](file:///home/john/wardline/src/wardline/clarion/facts.py#L25) | **Low** | `src/wardline/clarion/*` | Architecture / Coupling |
| **WLN-LOW-07** | [False-Positive Local Pack Detection for Built-ins](file:///home/john/wardline/src/wardline/core/config.py#L64-L91) | **Low** | `src/wardline/core/config.py` | Security / Custom Packs |
| **WLN-LOW-08** | [Untrusted Custom Pack Loading via wardline.yaml](file:///home/john/wardline/src/wardline/core/config.py#L112-L133) | **Low** | `src/wardline/core/config.py` | Security |
| **WLN-LOW-09** | [Uncontrolled Resource Consumption (OOM) in JSON-RPC stdio](file:///home/john/wardline/src/wardline/mcp/protocol.py#L100-L115) | **Low** | `src/wardline/mcp/protocol.py` | Security / DoS |
| **WLN-LOW-10** | [Fragile Assignment Type Suppression in Variable-Level Control Flow](file:///home/john/wardline/src/wardline/scanner/taint/variable_level.py#L823) | **Low** | `src/wardline/scanner/taint/variable_level.py` | Python Engineering |

---

## 🛑 Critical Severity Findings

### WLN-CRIT-01: Parameter Default Expressions Ignored
* **Focus Area**: Systems / Taint Propagation
* **Target Location**: [_seed_parameters in variable_level.py](file:///home/john/wardline/src/wardline/scanner/taint/variable_level.py#L163-L185)
* **Description**:
  Parameter default value expressions (e.g., `def func(x=get_untrusted_data())`) are evaluated at the call site at runtime when the argument is omitted. However, Wardline's L2 taint analysis does not evaluate the taint of parameter default expressions. In `_seed_parameters`, if a parameter is not bound in `param_meets` (meaning it wasn't supplied at the call site), it defaults to `function_taint`.
  
  If the function is `@trusted(level="ASSURED")`, `function_taint` is `ASSURED`. Thus, when called without arguments, `x` is seeded with `ASSURED` even if the default expression returns `EXTERNAL_RAW` data. This allows untrusted data to leak from trusted functions via default arguments without triggering `PY-WL-101`.
* **Concrete Remediation**:
  Evaluate the default expressions using L2 resolver logic during parameter seeding. If a default is defined, compute its taint and use it as the fallback seed rather than `function_taint`:
  ```python
  def _seed_parameters(
      func_node: ast.FunctionDef | ast.AsyncFunctionDef,
      function_taint: TaintState,
      var_taints: dict[str, TaintState],
      param_meets: dict[str, TaintState] | None = None,
      taint_map: dict[str, TaintState] | None = None,
  ) -> None:
      args = func_node.args
      defaults = args.defaults
      kw_defaults = args.kw_defaults
      
      default_taints: dict[str, TaintState] = {}
      
      # Map positional parameter defaults
      total_pos_args = len(args.posonlyargs) + len(args.args)
      num_defaults = len(defaults)
      all_pos_params = args.posonlyargs + args.args
      for i, default_expr in enumerate(defaults):
          param_idx = total_pos_args - num_defaults + i
          if 0 <= param_idx < len(all_pos_params):
              param_name = all_pos_params[param_idx].arg
              default_taints[param_name] = _resolve_expr(default_expr, TaintState.INTEGRAL, taint_map or {}, {})

      # Map keyword-only parameter defaults
      for param, default_expr in zip(args.kwonlyargs, kw_defaults):
          if default_expr is not None:
              default_taints[param.arg] = _resolve_expr(default_expr, TaintState.INTEGRAL, taint_map or {}, {})

      # Seed parameters with default fallback
      for arg in (*args.posonlyargs, *args.args, *args.kwonlyargs):
          fallback = default_taints.get(arg.arg, function_taint)
          seed_val = fallback
          if param_meets is not None and arg.arg in param_meets:
              seed_val = least_trusted(seed_val, param_meets[arg.arg])
          var_taints[arg.arg] = seed_val
  ```

---

## ⚡ High Severity Findings

### WLN-HIGH-01: Python Standard Input Buffer blocking in MCP Server
* **Focus Area**: CLI & MCP
* **Target Location**: [protocol.py](file:///home/john/wardline/src/wardline/mcp/protocol.py#L107-L108)
* **Description**:
  The MCP server uses `for raw in in_stream:` (where `in_stream` defaults to `sys.stdin`) to read incoming JSON-RPC messages. Because Python's file iterator implements internal read-ahead block buffering when standard input is a pipe (non-TTY), it blocks/buffers input data (up to 8KB) instead of yielding lines immediately as they are flushed by the client. This causes the MCP server to hang or experience high latency in interactive stdio sessions.
* **Concrete Remediation**:
  Modify `run_stdio` in [protocol.py](file:///home/john/wardline/src/wardline/mcp/protocol.py#L107-L108) to use a `while True:` loop calling `.readline()` to prevent read-ahead buffering:
  ```diff
  -        for raw in in_stream:
  -            line = raw.strip()
  +        while True:
  +            raw = in_stream.readline()
  +            if not raw:
  +                break
  +            line = raw.strip()
  ```

### WLN-HIGH-02: Fragile Skip Invariant in File Discovery
* **Focus Area**: Quality / Discovery
* **Target Location**: [discovery.py](file:///home/john/wardline/src/wardline/core/discovery.py#L32-L34)
* **Description**:
  In `discover`, files are skipped using:
  ```python
  if any(part in _ALWAYS_SKIP for part in path.parts):
      continue
  ```
  Because `path` resolves to an absolute path, checking `path.parts` scans the *entire* path hierarchy, including parent directories. If a developer clones the repository or runs the scanner inside a directory path containing any element of `_ALWAYS_SKIP` (such as `venv`, `.venv`, or `.git` — e.g., `/home/user/venv/wardline/`), **every single file is silently skipped**, yielding an empty scan.
* **Concrete Remediation**:
  Restrict the `_ALWAYS_SKIP` check to parts of the path that are relative to the project root.
  ```diff
          for path in sorted(base.rglob("*.py")):
  -           if any(part in _ALWAYS_SKIP for part in path.parts):
  -               continue
  +           try:
  +               rel_parts = path.relative_to(root).parts
  +           except ValueError:
  +               rel_parts = path.parts
  +           if any(part in _ALWAYS_SKIP for part in rel_parts):
  +               continue
  ```

### WLN-HIGH-03: Lack of Import Alias Resolution in TaintedSinkRule
* **Focus Area**: Static Analysis / Soundness
* **Target Location**: [_sink_helpers.py](file:///home/john/wardline/src/wardline/scanner/rules/_sink_helpers.py#L76-L82)
* **Description**:
  Rules extending `TaintedSinkRule` identify matching sink calls by checking whether `dotted_name(call.func)` is in their static `SINKS` set. `dotted_name` merely extracts the raw AST name chain as written. It does not resolve imports or aliases. Any import alias or direct function import—such as `from subprocess import run; run(..., shell=True)` or `import pickle as p; p.loads(raw)`—completely bypasses the checks, leading to severe False Negatives.
* **Concrete Remediation**:
  Resolve aliases using `resolve_call_fqn` against the module's `alias_map` retrieved from `context.alias_maps`.
  Update `sink_calls` in [_sink_helpers.py](file:///home/john/wardline/src/wardline/scanner/rules/_sink_helpers.py#L76-L82) to:
  ```python
  def sink_calls(
      func_node: ast.AST,
      sink_names: frozenset[str],
      alias_map: dict[str, str],
      module_prefix: str
  ) -> Iterator[tuple[ast.Call, str]]:
      from wardline.scanner.ast_primitives import resolve_call_fqn
      for call in _own_calls(func_node):
          # Try to resolve via imports/aliases
          fqn = resolve_call_fqn(call, alias_map, frozenset(), module_prefix)
          if fqn is not None and fqn in sink_names:
              yield call, fqn
          else:
              # Fallback for un-aliased builtin names
              dotted = dotted_name(call.func)
              if dotted is not None and dotted in sink_names:
                  yield call, dotted
  ```
  And update `TaintedSinkRule.check` to fetch `alias_map` and pass it to `sink_calls`:
  ```python
              module = module_dotted_name(entity.location.path) or ""
              alias_map = context.alias_maps.get(module) or {}
              for call, dotted in sink_calls(entity.node, self.SINKS, alias_map, module):
  ```

### WLN-HIGH-04: Soundness Gap for Generators Yielding Untrusted Data
* **Focus Area**: Static Analysis / Soundness
* **Target Location**: [variable_level.py](file:///home/john/wardline/src/wardline/scanner/taint/variable_level.py#L1337-L1367)
* **Description**:
  In Python, generators yield values to their callers via `yield` or `yield from` rather than `return`. However, `_collect_return_paths` only extracts `ast.Return` statements. Consequently, any `@trusted` generator that yields untrusted data (e.g., `yield read_raw(p)`) completely escapes return-taint validation under `PY-WL-101`.
* **Concrete Remediation**:
  Modify `_collect_return_paths` to check for and collect `ast.Yield` and `ast.YieldFrom` expressions:
  ```python
  def _collect_return_paths(
      nodes: list[ast.AST],
      function_taint: TaintState,
      taint_map: dict[str, TaintState],
      var_taints: dict[str, TaintState],
      out: list[tuple[TaintState, str | None, ast.expr]],
  ) -> None:
      for node in nodes:
          if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
              continue
          if isinstance(node, ast.Return) and node.value is not None:
              taint = _resolve_expr(node.value, function_taint, taint_map, var_taints)
              out.append((taint, _return_callee(node.value), node.value))
          elif isinstance(node, (ast.Yield, ast.YieldFrom)) and node.value is not None:
              taint = _resolve_expr(node.value, function_taint, taint_map, var_taints)
              out.append((taint, _return_callee(node.value), node.value))
          _collect_return_paths(list(ast.iter_child_nodes(node)), function_taint, taint_map, var_taints, out)
  ```

### WLN-HIGH-05: Module-Level Import-Time Dependency on `pyyaml` in Base Core Package
* **Focus Area**: Architecture / Layering
* **Target Location**:
  - [baseline.py](file:///home/john/wardline/src/wardline/core/baseline.py#L18)
  - [descriptor.py](file:///home/john/wardline/src/wardline/core/descriptor.py#L27)
  - [judged.py](file:///home/john/wardline/src/wardline/core/judged.py#L19)
  - [waivers.py](file:///home/john/wardline/src/wardline/core/waivers.py#L18)
* **Description**:
  The core package is designed to be dependency-free. However, several modules in `core/` import `yaml` (provided by the optional `scanner` extra) at module-level. When the package is imported or used as a lightweight base library (e.g. for trust decorators only) without the `scanner` extra, it fails with an `ImportError` on these modules at import time.
* **Concrete Remediation**:
  Move `import yaml` from the module level to the local function scopes where serialization or deserialization is actually performed (e.g. inside `load_baseline`, `write_baseline`, `descriptor_to_yaml`, `load_judged`, `write_judged`, `parse_waivers`, `add_waiver`).

### WLN-HIGH-06: Static Analysis Bypass via Undecorated Nested Helper Functions
* **Focus Area**: Python Engineering
* **Target Location**:
  - [_sink_helpers.py](file:///home/john/wardline/src/wardline/scanner/rules/_sink_helpers.py#L215-L219)
  - [broad_exception.py](file:///home/john/wardline/src/wardline/scanner/rules/broad_exception.py#L44-L46)
  - [silent_exception.py](file:///home/john/wardline/src/wardline/scanner/rules/silent_exception.py#L44-L46)
* **Description**:
  In `TaintedSinkRule` and exception rules, checks and severity modulation are determined by looking up the function's `qualname` in `context.project_taints`. Nested helper functions (e.g., `def helper()`) inside a decorated `@trusted` function are indexed as separate entities (e.g., `module.parent.<locals>.helper`) but do not have decorators. Thus, their trust level resolves to `TaintState.UNKNOWN_RAW`. This causes all modulated rules (sink checks, broad exceptions) to downgrade their severity to `Severity.NONE`, suppressing all findings inside the helper. A developer can bypass any of these checks by nesting a dangerous sink call (such as `pickle.loads`) in a nested helper function.
* **Concrete Remediation**:
  Ensure nested functions inherit the trust tier/context of their enclosing function. When querying `context.project_taints`, check if the `qualname` contains `.<locals>.` and resolve to the parent qualname:
  ```python
  parent_qualname = qualname.split(".<locals>.")[0]
  tier = context.project_taints.get(parent_qualname, TaintState.UNKNOWN_RAW)
  ```

### WLN-HIGH-07: Static Analysis Evasion via Lambda Expressions
* **Focus Area**: Python Engineering
* **Target Location**:
  - [ast_primitives.py](file:///home/john/wardline/src/wardline/scanner/ast_primitives.py#L102-L103)
  - [ast_primitives.py](file:///home/john/wardline/src/wardline/scanner/ast_primitives.py#L122-L124)
  - [_sink_helpers.py](file:///home/john/wardline/src/wardline/scanner/rules/_sink_helpers.py#L69-L70)
* **Description**:
  The AST iterator and the sink helper search explicitly skip `ast.Lambda` nodes and do not traverse their bodies for calls. Since lambda expressions are also not indexed as independent entities, any dangerous sinks or violations wrapped in a lambda (e.g. `lambda x: exec(x)`) completely evade detection by sink rules.
* **Concrete Remediation**:
  Ensure lambda bodies are traversed when checking for sink violations within the parent function scope. Modify the iterator helper `_own_calls` to traverse lambda bodies (e.g., `isinstance(child, ast.Lambda)` should descend into `child.body`) instead of skipping them.

---

## 🟨 Medium Severity Findings

### WLN-MED-01: Transitive Import-Time Dependency on `scanner` from Base Core Modules
* **Focus Area**: Architecture / Layering
* **Target Location**:
  - [assure.py](file:///home/john/wardline/src/wardline/core/assure.py#L40)
  - [attest.py](file:///home/john/wardline/src/wardline/core/attest.py#L56)
  - [dossier.py](file:///home/john/wardline/src/wardline/core/dossier.py#L42)
  - [explain.py](file:///home/john/wardline/src/wardline/core/explain.py#L20)
  - [judge_run.py](file:///home/john/wardline/src/wardline/core/judge_run.py#L35)
  - [delta.py](file:///home/john/wardline/src/wardline/core/delta.py#L9)
  - [run.py](file:///home/john/wardline/src/wardline/core/run.py#L33-L36)
* **Description**:
  Base package modules import `run_scan` at import time, which in turn imports `scanner` modules at import time in `core/run.py`. Additionally, `delta.py` and `judge_run.py` import `scanner` modules directly at the module level. This forces an import-time load of `scanner` (and transitively `yaml`), which triggers `ImportError` when `scanner` is not installed.
* **Concrete Remediation**:
  1. Move the `scanner` imports in `run.py` into the local scope of `run_scan`.
  2. Move the `from wardline.core.run import run_scan` imports in `assure.py`, `attest.py`, `dossier.py`, and `explain.py` into their respective calling functions.
  3. Move the `WardlineAnalyzer` import in `judge_run.py` inside `run_judge`.
  4. Move the `Entity` import in `delta.py` under `if TYPE_CHECKING:`.

### WLN-MED-02: Module-Level Import of Optional Dependency (`pyyaml`) in Base Install Subpackage
* **Focus Area**: Architecture / Layering
* **Target Location**: [pack.py](file:///home/john/wardline/src/wardline/install/pack.py#L8)
* **Description**:
  The `install` package is part of the base package. Importing `install/pack.py` at import time will raise an `ImportError` if `pyyaml` is not installed.
* **Concrete Remediation**:
  Move the `import yaml` statement inside the `activate_pack` function.

### WLN-MED-03: Import-Time Coupling in Dependency-Free MCP Server
* **Focus Area**: Architecture / Layering
* **Target Location**:
  - [server.py](file:///home/john/wardline/src/wardline/mcp/server.py#L24)
  - [server.py](file:///home/john/wardline/src/wardline/mcp/server.py#L35)
  - [lsp.py](file:///home/john/wardline/src/wardline/mcp/lsp.py#L14)
* **Description**:
  The MCP server is intended to be a dependency-free stdlib-only server. However, it imports `descriptor_to_yaml`, `_ALL_RULE_CLASSES`, and `run_scan` at import time. This causes the MCP module to crash on startup if `scanner` and PyYAML are not installed.
* **Concrete Remediation**:
  1. Move the `_ALL_RULE_CLASSES` import inside the `_read_resource` method of `WardlineMCPServer` (specifically when serving the `wardline://rules` URI).
  2. Move the `descriptor_to_yaml` import inside `_read_resource`.
  3. Move the `run_scan` import inside `LspServer` methods or functions where it is dynamically executed.

### WLN-MED-04: Waiver Tool in MCP Server hardcodes configuration path to `wardline.yaml`
* **Focus Area**: CLI & MCP
* **Target Location**: [server.py](file:///home/john/wardline/src/wardline/mcp/server.py#L402) & [server.py](file:///home/john/wardline/src/wardline/mcp/server.py#L687-L698)
* **Description**:
  The MCP server's `waiver_add` tool does not support a custom configuration path (it is missing the `config` property in its schema). The tool handler `_waiver_add` hardcodes the config path to `root / "wardline.yaml"`. If a user is running scans using a custom configuration path, waivers added via this tool will be written to `wardline.yaml` instead, having no effect on the custom configuration path scans.
* **Concrete Remediation**:
  1. Add `config` parameter of type string to `waiver_add` tool input schema.
  2. Modify `_waiver_add` handler to resolve and use the custom config path.

### WLN-MED-05: Missing `context_lines` option in MCP `judge` tool
* **Focus Area**: CLI & MCP
* **Target Location**: [server.py](file:///home/john/wardline/src/wardline/mcp/server.py#L344-L356) & [server.py](file:///home/john/wardline/src/wardline/mcp/server.py#L645-L653)
* **Description**:
  The CLI `judge` command accepts a `--context-lines` option to customize the context window excerpt radius sent to the LLM. However, the MCP `judge` tool does not define `context_lines` in its `input_schema` and does not pass it from `args` to `run_judge`.
* **Concrete Remediation**:
  Add `context_lines` of type integer to `judge` tool `input_schema` and pass it in the `_judge` function.

### WLN-MED-06: Absolute Path Match Failure in `explain_finding`
* **Focus Area**: Quality / Explanations
* **Target Location**: [explain.py](file:///home/john/wardline/src/wardline/core/explain.py#L77-L92)
* **Description**:
  The private helper `_match` matches findings using `f.location.path == path`. Since `f.location.path` is normalized as a project-relative POSIX path (e.g. `src/main.py`), passing an absolute path for `path` causes the comparison to fail.
* **Concrete Remediation**:
  Convert `path` to a project-relative POSIX path prior to matching inside `explain_finding` or `_explain_local`.

### WLN-MED-07: Inconsistent Defaults for `confine_to_root` in Attestation
* **Focus Area**: Quality / Integrity
* **Target Location**: [attest.py](file:///home/john/wardline/src/wardline/core/attest.py#L270-L288)
* **Description**:
  In `build_attestation`, the parameter `confine_to_root` defaults to `False`. However, in `verify_attestation`, the parameter `confine_to_root` defaults to `True`. This inconsistency causes programmatic verification with `reproduce=True` (using defaults) to re-run the scan with differing root confinement rules compared to the build step, potentially causing verification to fail with `reproduced=False`.
* **Concrete Remediation**:
  Align default arguments across both functions to default to `False`.

### WLN-MED-08: Under-Tainting in L3 parameter-meet generation with `**kwargs` Unpacking
* **Focus Area**: Static Analysis / Taint
* **Target Location**: [analyzer.py](file:///home/john/wardline/src/wardline/scanner/analyzer.py#L317-L318)
* **Description**:
  During L2 analysis parameter-meet collection, when a caller passes keyword arguments via dictionary unpack (e.g. `callee(**kwargs)`), the argument taints contain `None: taint`. If the callee signature does not have a `**kwargs` dictionary collector parameter (i.e. `args_node.kwarg` is `None`), this taint is completely ignored. Consequently, callee's named parameters do not receive the taint of the unpacked dictionary.
* **Concrete Remediation**:
  If `None` is present in `arg_taints` (meaning there was a `**kwargs` unpack), conservatively mix this taint (via `least_trusted`) into ALL parameters of the callee to enforce fail-closed behavior.

### WLN-MED-09: Under-Tainting via Loop-Carried Dependencies
* **Focus Area**: Static Analysis / Taint
* **Target Location**: [variable_level.py](file:///home/john/wardline/src/wardline/scanner/taint/variable_level.py#L826-L897)
* **Description**:
  Loop statements (`_handle_for` and `_handle_while`) are only walked a single time. Any loop-carried data dependency where a variable is read before it is written in the loop body (e.g., `y = x; x = raw`) will use the pre-loop value of the variable, resulting in an under-tainted final state for `y` after the loop.
* **Concrete Remediation**:
  Iterate the walk of the loop body until the dictionary of variable taints (`var_taints`) converges (stabilizes). Since the trust model is finite and monotonic, the loop is guaranteed to converge in at most 8 iterations.

### WLN-MED-10: Ineffective Caching / Performance Architecture Flaw
* **Focus Area**: Systems / Caching
* **Target Location**:
  - [analyzer.py](file:///home/john/wardline/src/wardline/scanner/analyzer.py#L111-L200)
  - [project_resolver.py](file:///home/john/wardline/src/wardline/scanner/taint/project_resolver.py#L111-L137)
* **Description**:
  The `SummaryCache` mechanism is designed to cache module summaries to avoid re-invoking analysis for unchanged files. However, the current execution pipeline runs parsing and L2 analysis unconditionally for all files before checking/resolving project taints. The cache is only used to bypass `summarise_module`, which merely packages already-computed seeds and counts, saving virtually zero CPU cycles.
* **Concrete Remediation**:
  Re-architect the analysis loop to check the cache (via file path and content hash) *before* parsing and running L2 analysis, and only perform parsing and L2 analysis for modified files or those in the transitive dirty frontier.

### WLN-MED-11: Inert Configuration Option `provenance_clash` (Dead Engine Path)
* **Focus Area**: Systems / Taint Algebra
* **Target Location**:
  - [propagation.py](file:///home/john/wardline/src/wardline/scanner/taint/propagation.py#L160-L182)
  - [variable_level.py](file:///home/john/wardline/src/wardline/scanner/taint/variable_level.py#L777-L824)
* **Description**:
  The configuration parameter `provenance_clash` is designed to switch combinations from rank-meet (`least_trusted`) to provenance-clash (`taint_join`). Although unit tests verify `combine()` delegates correctly, all production code paths in both L2 (expression combiners, control-flow joins) and L3 (callee sets, external influence, SCC seeds) call `least_trusted` directly. As a result, enabling `provenance_clash: true` has zero effect on the static analysis.
* **Concrete Remediation**:
  Either wire combination sites to call `combine` or check the context variable instead of calling `least_trusted` directly, or systematically deprecate/remove the option if it is deprecated.

### WLN-MED-12: Git Ref Option/Argument Injection in `get_changed_files_since`
* **Focus Area**: Security
* **Target Location**: [delta.py](file:///home/john/wardline/src/wardline/core/delta.py#L34-L44)
* **Description**:
  The `new_since` parameter is passed directly to the `subprocess.run` command line as `["git", "diff", "--name-only", ref]`. Although `shell=False` blocks shell command injection, there is no validation on the `ref` string. If an attacker controls the `ref` argument, they can pass git options like `--output=filename` to write diff output to arbitrary locations in the filesystem.
* **Concrete Remediation**:
  Validate that the `ref` string does not start with a hyphen (`-`). A valid Git branch name, tag, or commit hash cannot begin with a hyphen:
  ```python
  if ref.startswith("-"):
      raise WardlineError(f"Invalid Git reference name: {ref!r}")
  ```

---

## 🟢 Low Severity Findings

### WLN-LOW-01: Incomplete MCP Handshake verification/enforcement
* **Focus Area**: CLI & MCP
* **Target Location**: [protocol.py](file:///home/john/wardline/src/wardline/mcp/protocol.py#L67-L78)
* **Description**:
  The MCP specification requires that no requests be processed by the server until the full initialization handshake is complete (`initialize` request followed by `notifications/initialized`). However, `JsonRpcServer.dispatch` sets `self._initialized = True` immediately upon receiving the `initialize` request, prematurely accepting requests sent before the `notifications/initialized` handshake notification is received.
* **Concrete Remediation**:
  Track an intermediate initialization state `_initializing`, and set `_initialized` to `True` only when receiving `notifications/initialized` or `initialized`.

### WLN-LOW-02: Undocumented `path` property in `verify_attestation` tool schema
* **Focus Area**: CLI & MCP
* **Target Location**: [server.py](file:///home/john/wardline/src/wardline/mcp/server.py#L607-L615)
* **Description**:
  The `_verify_attestation` handler fetches the optional `path` property from the tool arguments via `args.get("path")` and resolves it using `_resolve_under_root`. However, the `verify_attestation` tool's `input_schema` does not list `path` in its `properties` block.
* **Concrete Remediation**:
  Add the `path` parameter to the `verify_attestation` tool's `input_schema` in `server.py`.

### WLN-LOW-03: Test Coverage Gaps in Error Hierarchy and Path Rejection
* **Focus Area**: Quality / Robustness
* **Target Location**: [test_errors.py](file:///home/john/wardline/tests/unit/core/test_errors.py#L1-L14) & [test_source_excerpt.py](file:///home/john/wardline/tests/unit/core/test_source_excerpt.py#L30-L34)
* **Description**:
  `test_errors.py` only validates inheritance for `ConfigError` and `DiscoveryError`, leaving several `WardlineError` subclasses unverified. Additionally, `test_source_excerpt.py` does not explicitly test absolute escapes (e.g. `/etc/passwd`).
* **Concrete Remediation**:
  Assert that all subclasses defined in `core/errors.py` subclass `WardlineError`, and add an explicit test case in `test_source_excerpt.py` for absolute path inputs escaping the scan root.

### WLN-LOW-04: FQN Resolution Limitation for Nested/Dotted Attribute Calls
* **Focus Area**: Python / Static Analysis
* **Target Location**: [resolve_call_fqn in ast_primitives.py](file:///home/john/wardline/src/wardline/scanner/ast_primitives.py#L171-L197)
* **Description**:
  `resolve_call_fqn` only resolves call targets of the form `mod.func()`. For nested paths (e.g. `package.submodule.func()`), the receiver is an `ast.Attribute` node, causing resolution to fail and return `None`.
* **Concrete Remediation**:
  Implement a recursive dotted-path resolver to extract all components of the call receiver, resolve the base name via `alias_map`, and combine the resolved prefix with the remaining components.

### WLN-LOW-05: Redundant/Dead Code in SCC Propagation
* **Focus Area**: Static Analysis / Tarjan
* **Target Location**: [propagation.py](file:///home/john/wardline/src/wardline/scanner/taint/propagation.py#L337-L347)
* **Description**:
  The unresolved calls floor check in `propagation.py` is redundant because a previous floor check already pins the refined taint to be at least as severe as the L1/unresolved floor.
* **Concrete Remediation**:
  Remove the redundant block or add a comment explaining that it is dead/unreachable.

### WLN-LOW-06: Transitive Core-Scanner Coupling in Optional Clarion Extra
* **Focus Area**: Architecture / Coupling
* **Target Location**: [facts.py](file:///home/john/wardline/src/wardline/clarion/facts.py#L25) & [write.py](file:///home/john/wardline/src/wardline/clarion/write.py#L17)
* **Description**:
  Even if a user installs `wardline[clarion]` (which does not declare a dependency on `scanner`), importing `clarion/facts.py` or `clarion/write.py` will trigger the import of `core/run.py` at import time, leading to `ImportError` because `yaml` is missing.
* **Concrete Remediation**:
  Move the `ScanResult` imports under the `if TYPE_CHECKING:` block, as they are only used as type annotations in these files.

### WLN-LOW-07: False-Positive Local Pack Detection for Built-in/Frozen Modules
* **Focus Area**: Security / Custom Packs
* **Target Location**: [config.py](file:///home/john/wardline/src/wardline/core/config.py#L64-L91)
* **Description**:
  For built-in/frozen modules like `sys` or `os`, the `spec.origin` is `'built-in'` or `'frozen'`. Calling `Path('built-in').resolve()` resolves it relative to the current working directory, e.g. `/path/to/project/built-in`. Since this resolved path falls within the current directory, it is incorrectly flagged as a local pack, raising a false-positive `ConfigError`.
* **Concrete Remediation**:
  Filter out `'built-in'` and `'frozen'` values from `spec.origin` before converting them to Path objects:
  ```python
  origins = []
  if spec.origin and spec.origin not in ("built-in", "frozen"):
      origins.append(Path(spec.origin))
  ```

### WLN-LOW-08: Untrusted Custom Pack Loading via `wardline.yaml`
* **Focus Area**: Security
* **Target Location**: [config.py](file:///home/john/wardline/src/wardline/core/config.py#L112-L133)
* **Description**:
  If `wardline scan` or the MCP server's `scan` tool is run on an untrusted workspace containing a `wardline.yaml`, the `packs` key allows specifying custom packages to import. While `trust_local_packs=False` blocks imports under the root, it does not block importing globally installed Python packages.
* **Concrete Remediation**:
  Restrict custom packs to an explicit allowlist or require a command-line flag/environment variable parameter to authorize imports from external packs.

### WLN-LOW-09: Uncontrolled Resource Consumption (OOM) in JSON-RPC stdio transport
* **Focus Area**: Security / DoS
* **Target Location**: [protocol.py](file:///home/john/wardline/src/wardline/mcp/protocol.py#L100-L115)
* **Description**:
  The stdio read loop iterates over `in_stream` directly using `for raw in in_stream: line = raw.strip()`. Python's stdio stream reading doesn't limit the line length. A massive line payload sent over stdin will consume a huge amount of memory during parsing, causing an Out Of Memory (OOM) crash.
* **Concrete Remediation**:
  Enforce a reasonable upper bound limit on line length (e.g. 10MB) before processing.

### WLN-LOW-10: Fragile Assignment Type Suppression in Variable-Level Control Flow Merge
* **Focus Area**: Python Engineering
* **Target Location**: [variable_level.py](file:///home/john/wardline/src/wardline/scanner/taint/variable_level.py#L823)
* **Description**:
  Mypy type-ignore is used because of set-keys mismatch inference. This can be cleanly written in a type-safe manner without type ignores.
* **Concrete Remediation**:
  Restructure the conditionals to ensure type checker alignment without resorting to `type: ignore`.
