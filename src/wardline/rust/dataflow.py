"""WP4: builder-dataflow L2 for ``std::process::Command`` (the genuinely-new core).

Walks one function body's top-level statements and reconstructs each ``Command``
invocation — both the stepwise form (``let mut c = Command::new(p); c.arg(a); c.output();``)
and the fluent chain (``Command::new(p).arg(a).output()``) — producing a ``CommandTrigger``
per terminal (``.output()``/``.spawn()``/``.status()``) that the rules (WP5) judge.

Taint model (slice-1, Tier-A): taint flows ONLY from known vocabulary sources and from
locals proven tainted by a prior ``let`` — default-clean, because a finding-producer
flags *provable* taint, not fail-closed unknowns (that would flood FPs). ``format!``
contributes the worst taint of its **direct interpolation-arg tokens** only (the captured
``{x}`` form carries no arg token → a documented FN); ``.args`` is an opaque vec; a
sanitizer is invisible (an accepted bounded FP). Intra-function, single-block — nested
control flow is a documented limitation. tree-sitter types are TYPE_CHECKING-only.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from wardline.core.node_id import NodeId
from wardline.core.taints import TaintState, least_trusted
from wardline.rust.vocabulary import load_rust_taint

if TYPE_CHECKING:
    from tree_sitter import Node

    from wardline.rust.nodeid import NodeIdMap

__all__ = ["CommandTrigger", "analyze_command_dataflow"]

_TERMINALS = frozenset({"output", "spawn", "status"})
# Shell command-string flags, compared case-folded: sh/bash -c, cmd /C, powershell -Command.
_SHELL_FLAGS = frozenset({"-c", "/c", "-command"})
# Expression wrappers that sit between a statement/tail position and the call beneath —
# the dominant `Command::new(x).output()?` / `.await` / `return ...` idioms. Peeled so the
# command beneath is not silently invisible.
_WRAPPERS = frozenset({"try_expression", "await_expression", "return_expression"})
_CLEAN = TaintState.ASSURED  # the default "not proven tainted" tier (not in RAW_ZONE)


@dataclass(frozen=True, slots=True)
class CommandTrigger:
    """One terminal ``Command`` invocation's reconstructed state, for the rules to judge."""

    trigger_node_id: NodeId  # the .output()/.spawn()/.status() call node (anchor + fingerprint)
    trigger_line: int
    constructor_line: int  # the Command::new(...) line — RS-WL-108 cites both
    program_literal: str | None  # "sh" for Command::new("sh"); None if the program is non-literal
    program_taint: TaintState  # taint of the Command::new(...) program argument
    shell_flag_seen: bool  # a literal "-c"/"/C" arg is present
    arg_taints: tuple[tuple[NodeId, TaintState], ...]  # (.arg node, its taint) for every .arg(...)


@dataclass(slots=True)
class _CmdAccum:
    program_literal: str | None
    program_taint: TaintState
    constructor_line: int
    shell_flag_seen: bool = False
    arg_taints: list[tuple[NodeId, TaintState]] = field(default_factory=list)


def analyze_command_dataflow(fn_body: Node, nmap: NodeIdMap) -> list[CommandTrigger]:
    """Reconstruct every ``Command`` invocation in ``fn_body`` (a ``block`` node)."""
    return _Analyzer(nmap).run(fn_body)


class _Analyzer:
    def __init__(self, nmap: NodeIdMap) -> None:
        self._nmap = nmap
        tables = load_rust_taint()
        self._sources: dict[str, TaintState] = {
            path: src.returns_taint for (_crate, path), src in tables.sources.items()
        }
        # The constructor suffix to recognise (last two segments of a `command` sink path,
        # so `Command::new`, `std::process::Command::new`, etc. all match).
        self._command_suffixes: set[str] = {
            "::".join(path.split("::")[-2:])
            for (_crate, path), sink in tables.sinks.items()
            if sink.sink_kind == "command"
        }
        self._local_taints: dict[str, TaintState] = {}
        self._commands: dict[str, _CmdAccum] = {}
        self._triggers: list[CommandTrigger] = []

    def run(self, fn_body: Node) -> list[CommandTrigger]:
        for stmt in fn_body.named_children:
            if stmt.type == "let_declaration":
                self._let(stmt)
                continue
            # an expression in statement position, OR the block's tail expression (no `;`),
            # under any number of try/await/return wrappers.
            expr = stmt.named_children[0] if stmt.type == "expression_statement" and stmt.named_children else stmt
            call = _unwrap_to_call(expr)
            if call is not None:
                self._try_command_chain(call, bound_name=None)
        return self._triggers

    def _let(self, let_node: Node) -> None:
        value = let_node.child_by_field_name("value")
        if value is None:
            return
        name = _name_of(let_node.child_by_field_name("pattern"))
        if name is not None:
            self._local_taints.pop(name, None)  # a fresh binding clears this name's prior taint
            # ...and a stale Command builder bound to this name. Without this, a shadowing
            # `let c = non_command();` strands the prior `_CmdAccum` and a later `c.output()`
            # reconstructs it — a phantom trigger carrying the old binding's taint (false
            # RS-WL-108). If the new value IS a builder, `_try_command_chain` re-adds it below.
            self._commands.pop(name, None)
        call = _unwrap_to_call(value)
        if call is not None and self._try_command_chain(call, bound_name=name):
            return  # a Command builder bound to `name` (or terminated inline)
        if name is not None:
            taint = self._expr_taint(value)  # taint over the ORIGINAL value (wrappers and all)
            if taint != _CLEAN:  # record only proven taint
                self._local_taints[name] = taint

    def _try_command_chain(self, call_node: Node, *, bound_name: str | None) -> bool:
        """Process a (possible) Command builder chain. Returns True if it was one."""
        base, steps = _unwind(call_node)
        if base.type == "call_expression" and self._is_command_new(base):
            accum = self._accum_from_new(base)
            self._apply_steps(accum, steps)
            if bound_name is not None and not any(m in _TERMINALS for m, _ in steps):
                self._commands[bound_name] = accum  # a live builder bound to a local
            return True
        if base.type == "identifier":
            tracked = self._commands.get(_text(base))
            if tracked is None:
                return False  # not a tracked command local
            self._apply_steps(tracked, steps)
            return True
        return False

    def _apply_steps(self, accum: _CmdAccum, steps: list[tuple[str, Node]]) -> None:
        for method, call_node in steps:
            if method == "arg":
                arg = _first_arg(call_node)
                if arg is not None:
                    if arg.type == "string_literal" and _string_value(arg).lower() in _SHELL_FLAGS:
                        accum.shell_flag_seen = True
                    accum.arg_taints.append((self._nmap.node_id(arg), self._expr_taint(arg)))
            elif method == "args":
                continue  # an opaque vec — not introspected in slice 1
            elif method in _TERMINALS:
                self._triggers.append(
                    CommandTrigger(
                        trigger_node_id=self._nmap.node_id(call_node),
                        trigger_line=call_node.start_point[0] + 1,
                        constructor_line=accum.constructor_line,
                        program_literal=accum.program_literal,
                        program_taint=accum.program_taint,
                        shell_flag_seen=accum.shell_flag_seen,
                        arg_taints=tuple(accum.arg_taints),
                    )
                )

    def _accum_from_new(self, new_call: Node) -> _CmdAccum:
        prog = _first_arg(new_call)
        literal = _string_value(prog) if prog is not None and prog.type == "string_literal" else None
        taint = self._expr_taint(prog) if prog is not None else _CLEAN
        return _CmdAccum(literal, taint, new_call.start_point[0] + 1)

    def _is_command_new(self, call_node: Node) -> bool:
        path = _call_function_path(call_node)
        return path is not None and _path_matches(path, self._command_suffixes)

    def _expr_taint(self, node: Node) -> TaintState:
        """The proven taint of an expression; default ``_CLEAN`` (taint flows only from
        known sources / tainted locals). Combines over sub-expressions, so taint reached
        through ``.unwrap()``, an unmodelled call, or indexing still propagates."""
        kind = node.type
        if kind == "identifier":
            return self._local_taints.get(_text(node), _CLEAN)
        if kind == "string_literal":
            return _CLEAN
        if kind == "macro_invocation":
            return self._format_taint(node)
        if kind == "call_expression":
            path = _call_function_path(node)
            if path is not None:
                for suffix, taint in self._sources.items():
                    if _path_matches(path, {suffix}):
                        return taint
        worst = _CLEAN
        for child in node.named_children:
            worst = least_trusted(worst, self._expr_taint(child))
        return worst

    def _format_taint(self, macro_node: Node) -> TaintState:
        name = macro_node.child_by_field_name("macro")
        if name is None or _text(name) != "format":
            return _CLEAN  # only format! is modelled in slice 1
        tree = next((c for c in macro_node.named_children if c.type == "token_tree"), None)
        if tree is None:
            return _CLEAN
        worst = _CLEAN
        for child in tree.named_children:
            if child.type == "string_literal":
                continue  # the format string (and any literal arg) is clean
            worst = least_trusted(worst, self._expr_taint(child))
        return worst


# --------------------------------------------------------------------------- #
# tree-sitter helpers
# --------------------------------------------------------------------------- #


def _unwrap_to_call(node: Node | None) -> Node | None:
    """Peel ``try_expression``/``await_expression``/``return_expression`` wrappers to the
    ``call_expression`` beneath, or ``None``. ``Command::new(x).output()?`` is the dominant
    Rust spawn idiom; without this the whole invocation is invisible to the rules."""
    depth = 0
    while node is not None and node.type in _WRAPPERS and depth < 8:
        node = node.named_children[0] if node.named_children else None
        depth += 1
    return node if node is not None and node.type == "call_expression" else None


def _unwind(call_node: Node) -> tuple[Node, list[tuple[str, Node]]]:
    """Walk a method chain from the outer (terminal) call inward. Returns ``(base, steps)``
    where ``base`` is the chain root (a ``Command::new(...)`` call for a fluent chain, or an
    identifier receiver for a stepwise ``c.arg(...)``), and ``steps`` is ``(method, call)``
    base→terminal."""
    steps: list[tuple[str, Node]] = []
    cur: Node | None = call_node
    while cur is not None and cur.type == "call_expression":
        fn = cur.child_by_field_name("function")
        if fn is not None and fn.type == "field_expression":
            method = fn.child_by_field_name("field")
            steps.append((_text(method) if method is not None else "", cur))
            cur = fn.child_by_field_name("value")
        else:
            break  # `cur` is the base call (e.g. Command::new(...))
    assert cur is not None
    return cur, list(reversed(steps))


def _call_function_path(call_node: Node) -> str | None:
    """The ``::``-path of a call's function (``std::env::var``, ``Command::new``,
    ``sanitize``), or ``None`` for a method call (``field_expression`` function)."""
    fn = call_node.child_by_field_name("function")
    if fn is not None and fn.type in ("scoped_identifier", "identifier"):
        return _text(fn)
    return None


def _path_matches(path: str, suffixes: set[str]) -> bool:
    return any(path == suffix or path.endswith("::" + suffix) for suffix in suffixes)


def _first_arg(call_node: Node) -> Node | None:
    args = call_node.child_by_field_name("arguments")
    if args is None:
        return None
    return args.named_children[0] if args.named_children else None


def _string_value(node: Node) -> str:
    content = next((c for c in node.named_children if c.type == "string_content"), None)
    return _text(content) if content is not None else ""


def _name_of(node: Node | None) -> str | None:
    return _text(node) if node is not None and node.type == "identifier" else None


def _text(node: Node) -> str:
    return node.text.decode("utf-8") if node.text is not None else ""
