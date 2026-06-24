"""ADR-049 Amendment 8: the ``#[path]`` mount overlay — logical module routing.

Two producers minting one module id was the clarion-bdb1eccf48 family: the file walk
routed a mounted file by filesystem path while the AST walk emitted the inline facade at
the same dotted path. The fix is a targeted mount overlay WITH a filesystem default:
every literal ``#[path = "…"] mod name;`` declaration is collected (rustc's
relative-path rule), resolved through a memoized fixed point (mounts chain; cycles drop
to the filesystem fallback; a doubly-claimed target resolves first-by-sorted-
(declaring-file, byte offset) — the R5 determinism pin), and ``logical_module_path``
then routes every file: exact mount hit, else longest mounted-subtree prefix, else the
unchanged pure-filesystem ``qualname.rust_module_route``.

Invisible BY DIALECT RULE (never resolved): a macro-wrapped mount (inside an unexpanded
macro invocation) and a ``#[cfg_attr(pred, path = "…")]``-delivered mount are NOT
mounts — only a literal ``#[path]`` attribute is. Their targets route by filesystem
fallback. No producer expands macros or evaluates cfg predicates. Both fall out of the
walk structurally: a token tree never surfaces ``attribute_item``/``mod_item`` siblings
at a walked item list, and ``_path_attr_of`` matches only the attribute literally named
``path``. A ``#[path]`` on an INLINE ``mod name { … }`` is likewise not a mount (the
normative rule covers the decl form only); the inline body still nests by name.

Twin discipline (ADR-049 §3, extended): a mount's own segment appends the normalised
``@cfg(...)`` discriminant only when its module name is TWINNED in the declaring item
list — counted across BOTH inline-``mod`` and decl-``mod`` forms. A mount declared
INSIDE a cfg-twin inline mod composes that mod's ``@cfg``-suffixed segment into its
logical PREFIX — the SAME twin counting + rendering the AST walk applies to the inline
mod's own entity path (counted over inline-with-body mods only, matching
``index._named_item_key``), so file-walk and AST-walk agree byte-for-byte. The
``#[path]`` target itself always resolves against the BARE would-be directory, which
carries no cfg.

This is SP2 scope (mount discovery needs the parent chain — a declaring file's
directory anchors the relative target); ``module_route`` rows keep driving
``rust_module_route`` directly, pinned as the no-mount-context FALLBACK. The corpus
``module_mounts`` section pins the mounted routes end-to-end. A file tree-sitter cannot
fully parse contributes NO mounts (fail-closed: no routing derived from a file we
refuse to analyze).

All paths are project-root-relative POSIX strings (the R5 sort rule is "declaring-file
path relative to the project root"); ``build_mount_overlay`` is the pure corpus-facing
entry, ``analyzer.analyze`` builds one overlay per crate from the scanned in-src
sources. tree-sitter types appear only under ``TYPE_CHECKING`` so importing this module
never pulls the ``wardline[rust]`` extra.
"""

from __future__ import annotations

import posixpath
from collections import Counter
from dataclasses import dataclass
from typing import TYPE_CHECKING

from wardline.rust import qualname as q
from wardline.rust.parse import has_errors, parse_rust

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Mapping

    from tree_sitter import Node

__all__ = ["MountOverlay", "build_mount_overlay"]

# Files whose own stem contributes no module segment; for nesting they anchor the
# would-be directory at their OWN directory (a non-root file anchors at dir/stem).
_ROOT_BASENAMES = frozenset({"lib.rs", "main.rs", "mod.rs"})

# Token-stream-invisible to the oracle — never resets the pending-attribute run
# (mirrors index._COMMENT_TYPES; the corpus pins the discipline for cfg attrs).
_COMMENT_TYPES = frozenset({"line_comment", "block_comment"})


@dataclass(frozen=True, slots=True)
class _Mount:
    """One literal ``#[path = "…"] mod name;`` declaration, resolved to its target."""

    declaring_file: str  # project-root-relative posix path (R5 sort key 1)
    offset: int  # byte offset of the `mod name;` item (R5 sort key 2)
    segments: tuple[str, ...]  # inline-mod prefix segments (cfg-composed) + own segment
    target: str  # normalised posix path of the mounted file


class MountOverlay:
    """The per-crate routing table: mounted files/subtrees overlay the filesystem route.

    ``crate``/``src_root`` parameterise the filesystem DEFAULT (``rust_module_route``);
    every path handed to ``logical_module_path`` must use the same base the mounts were
    discovered under (project-root-relative posix)."""

    def __init__(self, mounts: Iterable[_Mount], *, crate: str, src_root: str) -> None:
        self._crate = crate
        self._src_root = src_root
        exact: dict[str, _Mount] = {}
        prefixes: dict[str, _Mount] = {}
        # R5 determinism: first by sorted (declaring-file, byte offset) wins a
        # doubly-claimed target file (and likewise a doubly-claimed subtree prefix).
        for mount in sorted(mounts, key=lambda m: (m.declaring_file, m.offset)):
            exact.setdefault(mount.target, mount)
            target_dir, basename = posixpath.split(mount.target)
            if basename == "mod.rs":
                # A <dir>/mod.rs target registers <dir>/ as a logical subtree prefix.
                prefixes.setdefault(target_dir, mount)
            elif basename.endswith(".rs"):
                # An x.rs target registers <target_dir>/x/ for its child directory
                # (rustc's non-mod-rs child rule).
                prefixes.setdefault(posixpath.join(target_dir, basename[: -len(".rs")]), mount)
        self._exact = exact
        self._prefixes = prefixes
        self._memo: dict[str, str] = {}

    def logical_module_path(self, file: str) -> str:
        """Route ``file``: exact mount hit, else longest mounted-subtree prefix, else
        the unchanged pure-filesystem ``rust_module_route``."""
        file = posixpath.normpath(file)
        if file not in self._memo:
            self._memo[file] = self._resolve(file, frozenset())
        return self._memo[file]

    def _resolve(self, file: str, resolving: frozenset[str]) -> str:
        if file in resolving:
            # Mount cycle: drop this link to the filesystem fallback (deterministic;
            # the corpus does not pin cycles — unit-tested as Wardline behavior).
            return self._fs_route(file)
        mount = self._exact.get(file)
        if mount is not None:
            return self._mount_logical(mount, resolving | {file})
        hit = self._longest_prefix(file)
        if hit is not None:
            prefix_dir, mount = hit
            base = self._mount_logical(mount, resolving | {file})
            # Children rewrite under the mount with the same stem discipline as the
            # filesystem route (trailing `mod` stem collapses): reuse it verbatim,
            # the mount's logical path standing in as the "crate" prefix.
            return q.rust_module_route(crate=base, src_root=prefix_dir, file=file)
        return self._fs_route(file)

    def _mount_logical(self, mount: _Mount, resolving: frozenset[str]) -> str:
        # The mount's own logical path: the DECLARING file's logical path (which may
        # itself route through a mount — the chained fixed point) + its segments.
        return ".".join([self._resolve(mount.declaring_file, resolving), *mount.segments])

    def _longest_prefix(self, file: str) -> tuple[str, _Mount] | None:
        best: tuple[str, _Mount] | None = None
        for prefix_dir, mount in self._prefixes.items():
            if file.startswith(prefix_dir + "/") and (best is None or len(prefix_dir) > len(best[0])):
                best = (prefix_dir, mount)
        return best

    def _fs_route(self, file: str) -> str:
        return q.rust_module_route(crate=self._crate, src_root=self._src_root, file=file)


def build_mount_overlay(
    sources: Mapping[str, str],
    *,
    crate: str,
    src_root: str,
    error_callback: Callable[[str, Exception], None] | None = None,
) -> MountOverlay:
    """Discover every literal ``#[path]`` mount across ``sources`` (path -> source text,
    paths project-root-relative posix) and build the crate's routing overlay."""
    mounts: list[_Mount] = []
    for file in sorted(sources):
        if not file.endswith(".rs"):
            continue
        try:
            tree = parse_rust(sources[file])
            if has_errors(tree):
                continue  # fail-closed: no routing derived from a file we refuse to analyze
            file_dir = posixpath.dirname(file)
            # rustc's relative-path rule: a top-level #[path] resolves against the declaring
            # FILE's directory; one declared inside inline mods resolves against the would-be
            # directory of the nesting — anchored at the file's own dir for a mod-rs file
            # (lib.rs/main.rs/mod.rs), at the file's stem directory otherwise.
            stem_base = file_dir if posixpath.basename(file) in _ROOT_BASENAMES else file[: -len(".rs")]
            file_mounts: list[_Mount] = []
            _collect_mounts(
                tree.root_node.children, file, attr_dir=file_dir, nest_base=stem_base, prefix=(), out=file_mounts
            )
            mounts.extend(file_mounts)
        except Exception as exc:  # noqa: BLE001 - hostile source must not crash the scan
            if error_callback is None:
                raise
            error_callback(file, exc)
    return MountOverlay(mounts, crate=crate, src_root=src_root)


def _collect_mounts(
    children: Iterable[Node],
    file: str,
    *,
    attr_dir: str,
    nest_base: str,
    prefix: tuple[str, ...],
    out: list[_Mount],
) -> None:
    items = _mod_items_with_attrs(children)
    # The mount's OWN segment twin-gates its @cfg across BOTH forms per declaring item
    # list; the inline-mod PREFIX segment twin-gates over inline-with-body mods only
    # (the AST walk's _named_item_key rule) — so prefix composition matches the inline
    # mod's own entity path byte-for-byte.
    cross_form_counts: Counter[str] = Counter()
    inline_counts: Counter[str] = Counter()
    for node, _cfgs, _target in items:
        name = _mod_name(node)
        cross_form_counts[name] += 1
        if node.child_by_field_name("body") is not None:
            inline_counts[name] += 1
    for node, cfgs, target in items:
        name = _mod_name(node)
        body = node.child_by_field_name("body")
        if body is None:
            if target is None:
                continue  # plain `mod foo;` — filesystem-routed, not a mount
            segment = name
            if cfgs and cross_form_counts[name] > 1:
                segment += q.cfg_discriminant(cfgs)
            resolved = posixpath.normpath(posixpath.join(attr_dir, target))
            out.append(_Mount(file, node.start_byte, (*prefix, segment), resolved))
        else:
            segment = name
            if cfgs and inline_counts[name] > 1:
                segment += q.cfg_discriminant(cfgs)
            # The #[path] target inside an inline mod resolves against the BARE
            # would-be directory (no cfg ever reaches the filesystem side).
            child_dir = posixpath.join(nest_base, name)
            _collect_mounts(
                body.children, file, attr_dir=child_dir, nest_base=child_dir, prefix=(*prefix, segment), out=out
            )


def _mod_items_with_attrs(children: Iterable[Node]) -> list[tuple[Node, list[str], str | None]]:
    """``(mod_item, raw cfg predicates, #[path] target | None)`` triples of one item
    list, with the SAME pending-attribute discipline as ``index._walk_scope`` (comments
    transparent, attributes accumulate, any other node resets)."""
    out: list[tuple[Node, list[str], str | None]] = []
    pending_cfgs: list[str] = []
    pending_path: str | None = None
    for child in children:
        if child.type in _COMMENT_TYPES:
            continue
        if child.type == "attribute_item":
            pred = q.cfg_predicate_of(child)
            if pred is not None:
                pending_cfgs.append(pred)
            else:
                target = _path_attr_of(child)
                if target is not None:
                    pending_path = target
            continue
        if child.type == "mod_item":
            out.append((child, pending_cfgs, pending_path))
        pending_cfgs = []
        pending_path = None
    return out


def _path_attr_of(attribute_item: Node) -> str | None:
    """The literal target of a ``#[path = "…"]`` attribute, or ``None``.

    Only the literal form is a mount: a ``cfg_attr``-delivered ``path`` never matches
    (its attribute path is ``cfg_attr``), and a path attribute without a string value
    is not a mount either."""
    if not attribute_item.named_children:
        return None
    attribute = attribute_item.named_children[0]
    if attribute.type != "attribute" or not attribute.named_children:
        return None
    if attribute.named_children[0].text != b"path":
        return None
    value = attribute.child_by_field_name("value")
    if value is None or value.type != "string_literal":
        return None
    content = next((c for c in value.named_children if c.type == "string_content"), None)
    if content is None or content.text is None:
        return None
    return content.text.decode("utf-8")


def _mod_name(node: Node) -> str:
    name = node.child_by_field_name("name")
    if name is not None and name.text is not None:
        return name.text.decode("utf-8")
    return ""
