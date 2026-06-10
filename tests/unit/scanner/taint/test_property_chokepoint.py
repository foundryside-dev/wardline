# tests/unit/scanner/taint/test_property_chokepoint.py
"""Property/differential harness around the L2 taint chokepoint (wardline-369f54b83b).

Every L2 statement handler routes through the shared recursive core
``_resolve_expr`` / ``_resolve_call`` in ``scanner/taint/variable_level.py`` —
the engine's historical soundness-bug magnet (fail-open launder, stale
``var_types``, lambda single-slot FN, branch-locality FN, raw-receiver bypass).
This module pins four PROPERTIES over generated program corpora, so a future
engine edit that re-opens any of those bug families trips a property here
instead of shipping as a silent FN:

1. **Lattice monotonicity** (``TestLatticeMonotonicity``): a program whose one
   EXTERNAL_RAW input syntactically flows to ``return`` through propagating
   constructs never resolves a return taint outside the engine's ``RAW_ZONE``
   (no clean-direction launder).
2. **Idempotence** (``TestIdempotence``): analyzing the same file twice — a
   fresh analyzer each time, and the same analyzer re-run — yields
   byte-identical findings streams.
3. **Monotonic seeds** (``TestMonotonicSeeds``): weakening an input seed
   (trusted literal -> EXTERNAL_RAW boundary read) never REMOVES a
   taint-driven finding.
4. **Receiver-guard invariant** (``TestReceiverGuardInvariant``): a typed
   receiver whose value is DECLARED raw (EXTERNAL_RAW / MIXED_RAW) never
   resolves a trusted method-call result through its clean ``Type.method``
   summary (pins wardline-03c8805449 as a property).

The corpus generators are deterministic (``random.Random(seed)`` — Mersenne
Twister, stable across CPython versions) and hand-rolled rather than
hypothesis-driven: a frozen, replayable corpus keeps CI runtime flat and makes
a property failure a stable repro (re-run the seed) instead of a shrink hunt.
The grammar deliberately contains NO sanctioning construct (no decorated/
``taint_map``-mapped callee, no ``_CONTEXT_ENCODERS`` member, no
``_NON_PROPAGATING_BUILTINS`` validator), so every generated flow is one the
lattice must keep raw — templates that legitimately clean are excluded from
the property set by construction, per the ticket.

Contextvar coupling notes for the handlers under test live in
``CHOKEPOINT_NOTES.md`` (same directory).
"""

from __future__ import annotations

import ast
import random
from typing import TYPE_CHECKING

from wardline.core.config import WardlineConfig
from wardline.core.taints import RAW_ZONE, TRUST_RANK, TaintState
from wardline.scanner.analyzer import WardlineAnalyzer
from wardline.scanner.taint.variable_level import compute_return_taint, compute_variable_taints

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence
    from pathlib import Path

    from wardline.core.finding import Finding

T = TaintState

# ── Deterministic program generator ──────────────────────────────────────────
#
# A grammar of statement templates, each a taint-PROPAGATING construct: given
# the current tainted variable ``cur`` it emits statements that flow the taint
# into a fresh variable ``nxt``. Chains of 1–4 templates compose into a small
# function whose single EXTERNAL_RAW input (``src``) syntactically reaches the
# final ``return``. Templates cover the ``_resolve_expr`` dispatch surface
# (Name/BinOp/JoinedStr/IfExp/containers/Subscript/BoolOp/NamedExpr), the
# ``_resolve_call`` curated ops (propagating builtins, ``.join``, ``.get``,
# raw-receiver method calls), and the statement-layer merges (if/else, for,
# try/except, match, unpacking, augmented assignment).

_Template = tuple[str, "Callable[[str, str], list[str]]"]

_TEMPLATES: tuple[_Template, ...] = (
    ("alias", lambda c, n: [f"{n} = {c}"]),
    ("binop", lambda c, n: [f'{n} = {c} + "lit"']),
    ("fstring", lambda c, n: [f'{n} = f"v={{{c}}}!"']),
    ("ifexp", lambda c, n: [f'{n} = "d" if flag else {c}']),
    ("list_subscript", lambda c, n: [f'{n} = [{c}, "a"][0]']),
    ("dict_get", lambda c, n: [f'_t_{n} = {{"k": {c}}}', f'{n} = _t_{n}.get("k", "d")']),
    ("if_else_merge", lambda c, n: ["if flag:", f"    {n} = {c}", "else:", f'    {n} = "d"']),
    ("augassign", lambda c, n: [f'{n} = ""', f"{n} += {c}"]),
    ("tuple_unpack", lambda c, n: [f'{n}, _u_{n} = {c}, "d"']),
    ("str_builtin", lambda c, n: [f"{n} = str({c})"]),
    ("join_method", lambda c, n: [f'{n} = ",".join([{c}])']),
    ("raw_receiver_method", lambda c, n: [f"{n} = {c}.strip()"]),
    ("boolop", lambda c, n: [f'{n} = {c} or "d"']),
    ("walrus", lambda c, n: [f"_w_{n} = ({n} := {c})"]),
    ("for_loop", lambda c, n: [f"for _i_{n} in [{c}]:", f"    {n} = _i_{n}"]),
    ("try_except", lambda c, n: ["try:", f"    {n} = {c}", "except Exception:", f"    {n} = {c}"]),
    ("match_capture", lambda c, n: [f"match {c}:", f"    case _v_{n}:", f"        {n} = _v_{n}"]),
    ("starred_unpack", lambda c, n: [f'_a_{n}, *{n} = "d", {c}']),
)

_P1_CASES = 200


def _generate_chain(seed: int) -> tuple[str, list[str]]:
    """One generated program: ``def f(src, flag)`` + 1–4 chained templates +
    ``return <last>``. Returns ``(source, template_names_used)``."""
    rng = random.Random(seed)
    n_stmts = rng.randint(1, 4)
    lines = ["def f(src, flag):"]
    cur = "src"
    used: list[str] = []
    for i in range(n_stmts):
        name, template = rng.choice(_TEMPLATES)
        used.append(name)
        nxt = f"v{i}"
        lines.extend("    " + line for line in template(cur, nxt))
        cur = nxt
    lines.append(f"    return {cur}")
    return "\n".join(lines) + "\n", used


def _resolve_program(src: str, *, param_meets: dict[str, TaintState], taint_map: dict[str, TaintState]) -> TaintState:
    """Run a generated program through the chokepoint and return its return taint.

    ``function_taint=GUARDED`` is the neutral trusted-zone seed: every fallback
    path (unknown name, unmodelled expression) lands at rank 2, so the ONLY way
    a result reaches ``RAW_ZONE`` is genuine propagation of the raw seed — and
    the only way a raw flow LEAVES ``RAW_ZONE`` is a launder, which is exactly
    what the property must catch.
    """
    func = ast.parse(src).body[0]
    assert isinstance(func, ast.FunctionDef | ast.AsyncFunctionDef)
    var_taints = compute_variable_taints(func, T.GUARDED, dict(taint_map), param_meets=param_meets)
    result = compute_return_taint(func, T.GUARDED, dict(taint_map), var_taints)
    assert result is not None, f"generated program must have a value-bearing return:\n{src}"
    return result


class TestGeneratorMeta:
    """The corpus itself is part of the contract: deterministic and covering."""

    def test_corpus_is_deterministic(self) -> None:
        first = [_generate_chain(seed)[0] for seed in range(_P1_CASES)]
        second = [_generate_chain(seed)[0] for seed in range(_P1_CASES)]
        assert first == second

    def test_corpus_parses_and_exercises_every_template(self) -> None:
        seen: set[str] = set()
        for seed in range(_P1_CASES):
            src, used = _generate_chain(seed)
            ast.parse(src)  # every generated program is valid Python
            seen.update(used)
        missing = {name for name, _ in _TEMPLATES} - seen
        assert not missing, f"templates never exercised by the corpus: {sorted(missing)}"


class TestLatticeMonotonicity:
    """Property 1 — no clean-direction launder through the chokepoint.

    One input (``src``) is seeded EXTERNAL_RAW and flows syntactically to the
    return through propagating constructs only; the resolved return taint must
    stay in the engine's RAW_ZONE for every program in the corpus.
    """

    def test_raw_seed_never_resolves_to_trusted_zone(self) -> None:
        failures: list[str] = []
        for seed in range(_P1_CASES):
            src, used = _generate_chain(seed)
            result = _resolve_program(src, param_meets={"src": T.EXTERNAL_RAW}, taint_map={})
            if result not in RAW_ZONE:
                failures.append(f"seed={seed} return={result} (rank {TRUST_RANK[result]}) templates={used}\n{src}")
        assert not failures, "raw input laundered to the trusted zone:\n\n" + "\n".join(failures)

    def test_property_actually_discriminates(self) -> None:
        # Negative control: the SAME corpus with a GUARDED (trusted-zone) seed
        # must NOT trip the raw-zone check everywhere — i.e. the property's
        # signal comes from the seed, not from the templates being raw-by-
        # construction (a corpus that returned RAW_ZONE regardless of seed
        # would make property 1 vacuous).
        trusted_zone_results = 0
        for seed in range(_P1_CASES):
            src, _used = _generate_chain(seed)
            result = _resolve_program(src, param_meets={"src": T.GUARDED}, taint_map={})
            if result not in RAW_ZONE:
                trusted_zone_results += 1
        assert trusted_zone_results == _P1_CASES, (
            "with a trusted seed every chain should resolve in the trusted zone "
            f"(got {trusted_zone_results}/{_P1_CASES} — some template injects raw on its own)"
        )


# ── Analyzer-level corpus (properties 2 and 3) ───────────────────────────────
#
# File-level programs: an @external_boundary reader seeds EXTERNAL_RAW, a
# @trusted function carries it through a propagation chain into a sink. The
# @trusted decoration matters — undecorated functions sit in the freedom zone
# and the severity model suppresses their sink findings.

_MODULE_HEADER = (
    "import os, pickle, subprocess\n"
    "from wardline.decorators import external_boundary, trusted\n"
    "@external_boundary\n"
    "def read_raw(p):\n"
    "    return p\n"
)

# Single-line propagation templates only: the raw and trusted module variants
# must be line-for-line aligned apart from the one seed line, so findings can
# be compared by (rule_id, qualname, line_start).
_FLAT_TEMPLATES: tuple[Callable[[str, str], list[str]], ...] = (
    lambda c, n: [f"{n} = {c}"],
    lambda c, n: [f'{n} = {c} + "lit"'],
    lambda c, n: [f'{n} = f"v={{{c}}}!"'],
    lambda c, n: ["if flag:", f"    {n} = {c}", "else:", f'    {n} = "d"'],
    lambda c, n: [f"{n} = str({c})"],
    lambda c, n: [f'{n} = [{c}, "a"][0]'],
)

_SINKS: tuple[Callable[[str], str], ...] = (
    lambda v: f"os.system({v})",
    lambda v: f"pickle.loads({v})",
    lambda v: f"eval({v})",
    lambda v: f"subprocess.run({v}, shell=True)",
)

# Rules whose firing decision is driven by a resolved taint reaching a sink /
# return (the population property 3 quantifies over). Structural rules
# (PY-WL-102/103/104/110/111/113/114/119) are excluded: they gate on shape, not
# taint, so a seed change can legitimately add or remove them in either
# direction (e.g. a boundary-partition verdict that depends on what the body
# returns).
_TAINT_DRIVEN_RULES = frozenset(
    {
        "PY-WL-101",
        "PY-WL-105",
        "PY-WL-106",
        "PY-WL-107",
        "PY-WL-108",
        "PY-WL-109",
        "PY-WL-112",
        "PY-WL-115",
        "PY-WL-116",
        "PY-WL-117",
        "PY-WL-118",
        "PY-WL-120",
        "PY-WL-121",
        "PY-WL-122",
        "PY-WL-123",
        "PY-WL-124",
        "PY-WL-125",
        "PY-WL-126",
    }
)

_P3_CASES = 40


def _generate_module(seed: int, *, raw_seed: bool) -> str:
    """A sink-bearing module; ``raw_seed`` picks the one differing line
    (boundary read vs trusted literal)."""
    rng = random.Random(seed)
    n_stmts = rng.randint(0, 2)
    seed_expr = "read_raw(p)" if raw_seed else '"safe"'
    lines = ["@trusted(level='ASSURED')", f"def fn{seed}(p, flag):", f"    data = {seed_expr}"]
    cur = "data"
    for i in range(n_stmts):
        template = rng.choice(_FLAT_TEMPLATES)
        nxt = f"v{i}"
        lines.extend("    " + line for line in template(cur, nxt))
        cur = nxt
    lines.append("    " + rng.choice(_SINKS)(cur))
    lines.append(f"    return {cur}")
    return _MODULE_HEADER + "\n".join(lines) + "\n"


def _analyze_module(tmp_path: Path, name: str, src: str) -> Sequence[Finding]:
    p = tmp_path / name
    p.write_text(src, encoding="utf-8")
    return WardlineAnalyzer().analyze([p], WardlineConfig(), root=tmp_path)


def _findings_stream(findings: Sequence[Finding]) -> str:
    """The findings stream as bytes-comparable text — order-preserving, full
    serialized payload (``to_jsonl`` covers every wire-visible field)."""
    return "\n".join(f.to_jsonl() for f in findings)


class TestIdempotence:
    """Property 2 — same file in, identical findings stream out.

    Both repetition shapes: a FRESH analyzer per run (no shared state at all)
    and the SAME analyzer re-run (per-run state must be fully reset between
    ``analyze`` calls — a stale cache / leaked contextvar shows up here).
    """

    # A construct-dense module on top of the generated ones: branch-bound
    # lambdas, container mutators, typed receivers, try/except, match, loops —
    # the id()-keyed and contextvar-coupled paths most likely to destabilise.
    _RICH_MODULE = _MODULE_HEADER + (
        "@trusted(level='ASSURED')\n"
        "def rich(p, flag):\n"
        "    data = read_raw(p)\n"
        "    box = []\n"
        "    box.append(data)\n"
        "    if flag:\n"
        "        cb = lambda v: os.system(v)\n"
        "    else:\n"
        "        cb = lambda v: eval(v)\n"
        "    cb(data)\n"
        "    try:\n"
        "        out = box[0]\n"
        "    except Exception:\n"
        "        out = 'd'\n"
        "    match out:\n"
        "        case v:\n"
        "            acc = ''\n"
        "    for item in box:\n"
        "        acc += item\n"
        "    subprocess.run(acc, shell=True)\n"
        "    return acc\n"
    )

    def _corpus(self) -> list[str]:
        return [_generate_module(seed, raw_seed=True) for seed in (3, 7, 11)] + [self._RICH_MODULE]

    def test_fresh_analyzer_twice_is_byte_identical(self, tmp_path: Path) -> None:
        for idx, src in enumerate(self._corpus()):
            name = f"m_fresh_{idx}.py"
            first = _findings_stream(_analyze_module(tmp_path, name, src))
            second = _findings_stream(_analyze_module(tmp_path, name, src))
            assert first == second, f"fresh-analyzer re-analysis diverged for module {idx}:\n{src}"

    def test_same_analyzer_rerun_is_byte_identical(self, tmp_path: Path) -> None:
        for idx, src in enumerate(self._corpus()):
            p = tmp_path / f"m_same_{idx}.py"
            p.write_text(src, encoding="utf-8")
            analyzer = WardlineAnalyzer()
            first = _findings_stream(analyzer.analyze([p], WardlineConfig(), root=tmp_path))
            second = _findings_stream(analyzer.analyze([p], WardlineConfig(), root=tmp_path))
            assert first == second, f"same-analyzer re-run diverged for module {idx}:\n{src}"

    def test_idempotence_corpus_produces_findings(self, tmp_path: Path) -> None:
        # Anti-vacuity: the corpus must actually exercise the finding pipeline
        # (byte-equality of two empty streams proves nothing).
        for idx, src in enumerate(self._corpus()):
            findings = _analyze_module(tmp_path, f"m_av_{idx}.py", src)
            assert any(f.rule_id in _TAINT_DRIVEN_RULES for f in findings), (
                f"idempotence module {idx} produced no taint-driven findings:\n{src}"
            )


class TestMonotonicSeeds:
    """Property 3 — weakening a seed (trusted -> raw) never removes a
    taint-driven finding: findings(raw) ⊇ findings(trusted) restricted to
    ``_TAINT_DRIVEN_RULES``, compared on (rule_id, qualname, line_start).
    """

    @staticmethod
    def _taint_keys(findings: Sequence[Finding]) -> set[tuple[str, str | None, int | None]]:
        return {(f.rule_id, f.qualname, f.location.line_start) for f in findings if f.rule_id in _TAINT_DRIVEN_RULES}

    def test_variants_differ_in_exactly_the_seed_line(self) -> None:
        # Meta: the (rule_id, qualname, line_start) comparison is only valid if
        # the two variants are line-aligned apart from the seed expression.
        for seed in range(_P3_CASES):
            raw_lines = _generate_module(seed, raw_seed=True).splitlines()
            trusted_lines = _generate_module(seed, raw_seed=False).splitlines()
            assert len(raw_lines) == len(trusted_lines)
            diff = [i for i, (a, b) in enumerate(zip(raw_lines, trusted_lines, strict=True)) if a != b]
            assert len(diff) == 1, f"seed={seed}: variants must differ on exactly one line, got {diff}"

    def test_raw_seed_findings_superset_of_trusted_seed(self, tmp_path: Path) -> None:
        failures: list[str] = []
        nonempty_raw_cases = 0
        for seed in range(_P3_CASES):
            raw_keys = self._taint_keys(
                _analyze_module(tmp_path, f"m_{seed}_raw.py", _generate_module(seed, raw_seed=True))
            )
            trusted_keys = self._taint_keys(
                _analyze_module(tmp_path, f"m_{seed}_tr.py", _generate_module(seed, raw_seed=False))
            )
            if raw_keys:
                nonempty_raw_cases += 1
            lost = trusted_keys - raw_keys
            if lost:
                failures.append(
                    f"seed={seed}: weakening the seed REMOVED findings {sorted(lost)}\n"
                    f"{_generate_module(seed, raw_seed=True)}"
                )
        assert not failures, "seed monotonicity violated:\n\n" + "\n".join(failures)
        # Anti-vacuity: the raw variants must actually fire taint-driven rules.
        assert nonempty_raw_cases == _P3_CASES, (
            f"only {nonempty_raw_cases}/{_P3_CASES} raw-seed programs produced taint-driven findings"
        )


class TestReceiverGuardInvariant:
    """Property 4 — the declared-raw typed-receiver guard (wardline-03c8805449).

    A receiver with a tracked type AND a DECLARED-raw value (EXTERNAL_RAW /
    MIXED_RAW — a boundary-seeded parameter, not a constructor default) must
    never resolve a trusted result through its clean ``Type.method`` summary:
    the summary describes a trustworthy instance, not the attacker-controlled
    object actually flowing in.

    UNKNOWN_RAW receivers are DELIBERATELY out of scope: an unmodelled
    ``Type()`` constructor defaults to UNKNOWN_RAW, and gating those would
    false-positive the ``h = Helper(); h.get_assured()`` pattern — the engine
    resolves the clean summary there by design (pinned as the negative control
    below, so a future edit that silently widens or narrows the guard trips
    one of the two tests).
    """

    _SHAPES = (
        # direct assignment from the typed-receiver method call
        "def f(h: {cls}):\n    x = h.{meth}()\n    return x\n",
        # with an argument, then an alias hop
        "def f(h: {cls}):\n    y = h.{meth}('a')\n    x = y\n    return x\n",
    )

    def test_declared_raw_receiver_never_resolves_trusted(self) -> None:
        failures: list[str] = []
        for cls, meth in (("Helper", "get_assured"), ("Vault", "load")):
            for summary in (T.INTEGRAL, T.ASSURED, T.GUARDED):
                for receiver in (T.EXTERNAL_RAW, T.MIXED_RAW):
                    for shape in self._SHAPES:
                        src = shape.format(cls=cls, meth=meth)
                        func = ast.parse(src).body[0]
                        assert isinstance(func, ast.FunctionDef)
                        taint_map = {f"{cls}.{meth}": summary}
                        var_taints = compute_variable_taints(func, T.GUARDED, taint_map, param_meets={"h": receiver})
                        if var_taints["x"] not in RAW_ZONE:
                            failures.append(
                                f"summary={summary} receiver={receiver} resolved x={var_taints['x']}\n{src}"
                            )
        assert not failures, "declared-raw receiver laundered through a clean summary:\n\n" + "\n".join(failures)

    def test_unknown_raw_receiver_still_resolves_summary(self) -> None:
        # Negative control / guard-boundary pin: an UNKNOWN_RAW-valued typed
        # receiver (the constructor-default provenance) DOES resolve the clean
        # summary — the FP-avoidance side of wardline-03c8805449.
        src = "def f(h: Helper):\n    x = h.get_assured()\n    return x\n"
        func = ast.parse(src).body[0]
        assert isinstance(func, ast.FunctionDef)
        taint_map = {"Helper.get_assured": T.ASSURED}
        var_taints = compute_variable_taints(func, T.GUARDED, taint_map, param_meets={"h": T.UNKNOWN_RAW})
        assert var_taints["x"] == T.ASSURED
