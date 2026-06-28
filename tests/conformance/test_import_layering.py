# tests/conformance/test_import_layering.py
"""Structural invariant: no deferred import masks a runtime import cycle.

Wardline's modules carry ~100 function-local (deferred) ``from wardline.`` imports.
Most are legitimate lazy loads (optional federation surfaces, fast CLI start-up). A
*few*, historically, existed only to break a real import cycle — and a deferred
cycle-breaker is invisible debt: a reorg, a new top-level import, or moving the code
re-surfaces the cycle as a runtime ``ImportError``.

This oracle builds the COMBINED runtime import graph — every module-level edge *plus*
every deferred (function-local) edge, excluding ``TYPE_CHECKING``-only edges — and
asserts it is acyclic. If it is, then no deferred import is load-bearing for a
*direct module<->module* cycle: the deferred imports that remain are there for
lazy-loading/optionality, not to hide a latent cycle of that shape.

Scope of the guarantee (read before trusting it): the graph models direct
``import`` / ``from ... import`` edges between wardline modules, statically. It does
NOT model (a) the ancestor-package ``__init__`` execution that a deep-submodule import
triggers at runtime — a cycle mediated purely by a package ``__init__`` aggregator
reached via a deep import is therefore NOT proven absent here; nor (b) dynamic
``importlib``/``__import__`` edges (used only for external pack names, not internal
modules). So a green run is a strong signal, not a proof that promoting *any* deferred
import is ``ImportError``-free in every case.

This complements the ``import-linter`` contracts in ``pyproject.toml``: those forbid
*upward* cross-tier edges (engine/policy purity); this forbids *intra-tier* cycles
(e.g. the ``scanner.grammar`` <-> ``scanner.rules`` cycle), which a layering contract
cannot express because both ends sit in the same tier. ``test_tier_purity_holds`` below
ALSO mirrors the import-linter tier classification in Python over EVERY module (not just
the contracts' enumerated source list), and ``test_contract_modules_resolve`` guards the
contracts against import-linter's silent drop of a forbidden_modules entry that no longer
resolves.

See ``wardline-a0eaa7dd12`` / ``wardline-9ec283d168`` for the two cycles this closed:
``scanner.grammar -> rules -> {contradictory_trust, invalid_decorator_level,
decorator_provider} -> grammar`` and ``run -> suppression -> finding_identity ->
baseline -> run``.
"""

from __future__ import annotations

import ast
from pathlib import Path

SRC_ROOT = Path(__file__).resolve().parents[2] / "src"
PKG_ROOT = SRC_ROOT / "wardline"


def _module_name(path: Path) -> str:
    rel = path.relative_to(SRC_ROOT).with_suffix("")
    parts = list(rel.parts)
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _resolve(node: ast.ImportFrom, current: str) -> str:
    """Resolve an ImportFrom (absolute or relative) to its dotted module target."""
    if node.level:
        base = current.split(".")
        base = base[: len(base) - node.level]
        prefix = ".".join(base)
        return f"{prefix}.{node.module}" if node.module else prefix
    return node.module or ""


def _wardline_targets(node: ast.AST, current: str) -> list[str]:
    out: list[str] = []
    if isinstance(node, ast.ImportFrom):
        mod = _resolve(node, current)
        if mod == "wardline" or mod.startswith("wardline."):
            out.append(mod)
            # `from wardline.pkg import submod` may name a submodule, not a symbol
            for alias in node.names:
                out.append(f"{mod}.{alias.name}")
    elif isinstance(node, ast.Import):
        for alias in node.names:
            if alias.name == "wardline" or alias.name.startswith("wardline."):
                out.append(alias.name)
    return out


class _ImportVisitor(ast.NodeVisitor):
    """Collect a module's runtime imports, split into module-level and deferred
    (function-local), skipping ``TYPE_CHECKING`` blocks."""

    def __init__(self, module: str) -> None:
        self.module = module
        self.module_targets: set[str] = set()
        self.deferred_targets: set[tuple[str, int]] = set()
        self._func_depth = 0
        self._type_checking_depth = 0

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._func_depth += 1
        self.generic_visit(node)
        self._func_depth -= 1

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

    def visit_If(self, node: ast.If) -> None:
        test = node.test
        is_tc = (isinstance(test, ast.Name) and test.id == "TYPE_CHECKING") or (
            isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING"
        )
        if is_tc:
            self._type_checking_depth += 1
            for child in node.body:
                self.visit(child)
            self._type_checking_depth -= 1
            for child in node.orelse:
                self.visit(child)
        else:
            self.generic_visit(node)

    def _record(self, node: ast.Import | ast.ImportFrom) -> None:
        if self._type_checking_depth:
            return  # annotation-only edge: not a runtime dependency
        for target in _wardline_targets(node, self.module):
            if self._func_depth:
                self.deferred_targets.add((target, node.lineno))
            else:
                self.module_targets.add(target)

    def visit_Import(self, node: ast.Import) -> None:
        self._record(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        self._record(node)


def _build_combined_graph() -> tuple[set[str], dict[str, set[str]], dict[str, set[tuple[str, int]]]]:
    """Return (all_modules, adjacency, deferred_edge_lines).

    ``adjacency`` is the combined runtime graph (module-level + deferred, no
    TYPE_CHECKING). ``deferred_edge_lines`` records, per source module, the
    (target, lineno) of each deferred edge so a cycle can be reported actionably.
    """
    all_mods: set[str] = set()
    raw_module: dict[str, set[str]] = {}
    raw_deferred: dict[str, set[tuple[str, int]]] = {}

    for path in sorted(PKG_ROOT.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        mod = _module_name(path)
        all_mods.add(mod)
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        visitor = _ImportVisitor(mod)
        visitor.visit(tree)
        raw_module[mod] = visitor.module_targets
        raw_deferred[mod] = visitor.deferred_targets

    def normalize(target: str) -> str | None:
        if target in all_mods:
            return target
        parent = target.rsplit(".", 1)[0]
        return parent if parent in all_mods else None

    adjacency: dict[str, set[str]] = {m: set() for m in all_mods}
    deferred_lines: dict[str, set[tuple[str, int]]] = {m: set() for m in all_mods}
    for mod, targets in raw_module.items():
        for target in targets:
            owner = normalize(target)
            if owner and owner != mod:
                adjacency[mod].add(owner)
    for mod, edges in raw_deferred.items():
        for target, lineno in edges:
            owner = normalize(target)
            if owner and owner != mod:
                adjacency[mod].add(owner)
                deferred_lines[mod].add((owner, lineno))
    return all_mods, adjacency, deferred_lines


def _strongly_connected_components(nodes: set[str], adjacency: dict[str, set[str]]) -> list[list[str]]:
    """Tarjan SCC (iterative, to avoid recursion-limit surprises on large graphs)."""
    index_of: dict[str, int] = {}
    low: dict[str, int] = {}
    on_stack: set[str] = set()
    stack: list[str] = []
    result: list[list[str]] = []
    counter = 0

    for root in nodes:
        if root in index_of:
            continue
        work: list[tuple[str, int]] = [(root, 0)]
        while work:
            node, child_idx = work[-1]
            if child_idx == 0:
                index_of[node] = low[node] = counter
                counter += 1
                stack.append(node)
                on_stack.add(node)
            successors = sorted(adjacency.get(node, ()))
            if child_idx < len(successors):
                work[-1] = (node, child_idx + 1)
                succ = successors[child_idx]
                if succ not in index_of:
                    work.append((succ, 0))
                elif succ in on_stack:
                    low[node] = min(low[node], index_of[succ])
            else:
                if low[node] == index_of[node]:
                    component: list[str] = []
                    while True:
                        w = stack.pop()
                        on_stack.discard(w)
                        component.append(w)
                        if w == node:
                            break
                    result.append(component)
                work.pop()
                if work:
                    parent = work[-1][0]
                    low[parent] = min(low[parent], low[node])
    return result


def test_no_deferred_import_masks_a_runtime_cycle() -> None:
    all_mods, adjacency, deferred_lines = _build_combined_graph()
    cycles = [scc for scc in _strongly_connected_components(all_mods, adjacency) if len(scc) > 1]
    if cycles:
        lines = ["Latent import cycle(s) in the combined runtime graph (module + deferred):"]
        for scc in sorted(cycles, key=len, reverse=True):
            members = set(scc)
            lines.append(f"\n  SCC ({len(scc)} modules): {sorted(scc)}")
            for src in sorted(members):
                for target, lineno in sorted(deferred_lines.get(src, set())):
                    if target in members:
                        lines.append(f"      deferred edge {src}:{lineno} -> {target}")
        lines.append(
            "\nA deferred import is masking a real cycle. Break it structurally (move the "
            "shared code to a lower layer) rather than re-hiding it behind another "
            "function-local import."
        )
        raise AssertionError("\n".join(lines))


def test_known_cycles_stay_broken() -> None:
    """Named regression guard for the two cycles closed by wardline-a0eaa7dd12:
    the cycle-closing back-edges must not reappear."""
    _all, adjacency, _deferred = _build_combined_graph()
    # Scanner cycle: the back-edges were on the rule/provider MEMBER modules importing
    # grammar (NOT the rules package __init__, which never imported grammar). Pin the
    # real members so a revert is caught here, not only by the catch-all.
    for member in (
        "wardline.scanner.rules.contradictory_trust",
        "wardline.scanner.rules.invalid_decorator_level",
        "wardline.scanner.taint.decorator_provider",
    ):
        assert "wardline.scanner.grammar" not in adjacency.get(member, set()), member
    # Core cycle: the policy-tier baseline module must not import the orchestrator.
    assert "wardline.core.run" not in adjacency.get("wardline.core.baseline", set())


def test_imports_are_absolute() -> None:
    """The graph builder's relative-import resolution is best-effort; the package is
    absolute-imports-only by convention. Enforce that so the resolver's assumption holds
    and no edge is silently dropped (a relative ``from . import x`` the resolver mishandles
    would be an invisible hole in the acyclicity guarantee)."""
    offenders: list[str] = []
    for path in sorted(PKG_ROOT.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.level:
                offenders.append(f"{path.relative_to(SRC_ROOT)}:{node.lineno}")
    assert not offenders, (
        "relative imports found (package is absolute-only by convention); either switch "
        f"to absolute imports or harden _resolve() for the package-__init__ case: {offenders}"
    )


# --- Tier-purity backstop (mirrors the import-linter contracts over EVERY module) -------
# The import-linter contracts in pyproject.toml enforce engine-purity only over their
# enumerated source_modules (scanner/decorators/rust + the 7 policy modules). This Python
# mirror classifies EVERY wardline module and enforces the same two relations over all of
# them — so a future engine-floor core module (e.g. core.taints) importing up is caught
# here even though it is not an import-linter source. Tier order (low->high):
# engine < policy < {federation, surface}; federation<->surface intentionally unlayered.
_POLICY = frozenset(
    {
        "baseline",
        "suppression",
        "waivers",
        "judged",
        "finding_identity",
        "delta",
        "delta_scope",
    }
)
_FEDERATION_CORE = frozenset(
    {"filigree_emit", "filigree_issue", "legis", "federation_status", "sei_resolution", "delta_resolve"}
)
_SURFACE_CORE = frozenset(
    {
        "run",
        "scan_jobs",
        "scan_file_workflow",
        "attest",
        "attest_key",
        "assure",
        "dossier",
        "emit",
        "sarif",
        "explain",
        "agent_summary",
        "decorator_coverage",
        "judge",
        "judge_run",
        "triage",
        "rekey",
        "autofix",
        "baseline_ops",
    }
)
_ENGINE = 0
_POLICY_T = 1
_FEDERATION_T = 2
_SURFACE_T = 3
_TIER_NAME = {0: "engine", 1: "policy", 2: "federation", 3: "surface"}


def _tier(module: str) -> int:
    if (
        module.startswith("wardline.loomweave")
        or module.startswith("wardline.filigree")
        or module in ("wardline.weft_decorator_coverage", "wardline.weft_dossier")
    ):
        return _FEDERATION_T
    if (
        module.startswith("wardline.cli")
        or module.startswith("wardline.mcp")
        or module == "wardline.lsp"
        or module.startswith("wardline.install")
    ):
        return _SURFACE_T
    if module.startswith("wardline.core."):
        leaf = module.split(".", 2)[2].split(".")[0]
        if leaf in _POLICY:
            return _POLICY_T
        if leaf in _FEDERATION_CORE:
            return _FEDERATION_T
        if leaf in _SURFACE_CORE:
            return _SURFACE_T
    return _ENGINE  # scanner.*, decorators.*, rust.*, engine-floor core, __init__, _version


def test_tier_purity_holds() -> None:
    """Engine modules import only engine; policy modules import only engine + policy.
    Complete-by-construction mirror of the import-linter contracts (covers EVERY module,
    module-level + deferred, excluding TYPE_CHECKING). federation/surface are intentionally
    unlayered, so only the two downward-floor relations are asserted here."""
    all_mods, adjacency, deferred_lines = _build_combined_graph()
    violations: list[str] = []
    for src in sorted(all_mods):
        src_tier = _tier(src)
        if src_tier > _POLICY_T:  # only engine + policy are the depended-upon floor
            continue
        deferred_targets = {dst for dst, _ln in deferred_lines.get(src, set())}
        for dst in sorted(adjacency.get(src, set())):
            dst_tier = _tier(dst)
            if dst_tier > src_tier:  # importing a strictly-higher tier = upward = violation
                where = "deferred" if dst in deferred_targets else "module-level"
                violations.append(f"[{_TIER_NAME[src_tier]}->{_TIER_NAME[dst_tier]}] {src} -> {dst} ({where})")
    assert not violations, "engine/policy tier purity violated:\n  " + "\n  ".join(violations)


def test_contract_modules_resolve() -> None:
    """import-linter SILENTLY drops a forbidden_modules entry that no longer resolves
    (a typo or a rename leaves the contract 'kept' while no longer enforcing that edge).
    Assert every module named in the pyproject import-linter contracts still maps to a
    real package/module in the tree, so such drift fails loudly here."""
    import tomllib

    pyproject = SRC_ROOT.parent / "pyproject.toml"
    data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    contracts = data["tool"]["importlinter"]["contracts"]
    all_mods, _adj, _deferred = _build_combined_graph()

    def resolves(name: str) -> bool:
        # a contract entry may name a package (covers descendants) or an exact module
        return name in all_mods or any(m == name or m.startswith(name + ".") for m in all_mods)

    missing: list[str] = []
    for contract in contracts:
        for key in ("source_modules", "forbidden_modules"):
            for name in contract.get(key, []):
                if not resolves(name):
                    missing.append(f"{contract['name']} :: {key} :: {name}")
    assert not missing, "import-linter contract names that no longer resolve in the tree:\n  " + "\n  ".join(missing)
