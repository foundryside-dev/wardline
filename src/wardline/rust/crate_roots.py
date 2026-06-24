"""SP2 crate-root discovery — ``Cargo.toml [package].name`` as the crate name.

Mirrors the loomweave oracle (``crates/loomweave-plugin-rust/src/crate_roots.rs``)
exactly; that source is the contract for behaviors the corpus does not pin:

* **Manifest read:** a real TOML parse (stdlib ``tomllib``, mirroring the oracle's
  ``toml::Value`` — ADR-049's "read as text" means *not cargo-metadata*, not a
  hand-rolled scan). ``[package].name`` is taken only if the manifest parses AND
  the name is a string: ``name.workspace = true`` parses as a table and falls
  through; unparseable or non-UTF-8 TOML falls through.
* **Two-branch registration:** a dir is a crate root iff (a) its manifest yields a
  string ``[package].name`` -> that name ``-``->``_`` normalised; ELSE (b)
  ``src/lib.rs`` or ``src/main.rs`` exists -> the directory name normalised. A
  virtual workspace root (neither) registers NOTHING — member crates own their
  files outright.
* **Walk:** symlinked directories are never followed (an out-of-tree escape would
  register an outside crate; a cycle would re-register through an alias); an entry
  whose type cannot be determined is not recursed into (can-not-determine =>
  do-not-recurse). Vendored/build/store dirs the host also skips are skipped.
* **Lookup:** file -> owning crate by longest directory-prefix match.

SCAN-COVERAGE NOTE (the distinction from loomweave's ``scope.rs emittable_scope``):
loomweave additionally EXCLUDES out-of-src files (``tests/``, ``benches/``,
``examples/``, ``build.rs``), a ``src/main.rs`` shadowed by a sibling ``lib.rs``,
and files under no crate root — it emits no federation entity for them. That is
its *entity surface*, not a scan filter: wardline keeps scanning ALL discovered
``.rs`` files. Files outside any crate's ``src/`` tree get a wardline-local
``#out``-branded module route (see ``analyzer._module_for``: class 2 =
``{crate}.#out.{...}``, class 3 = ``crate.#out.{...}`` with the constant crate
segment) whose qualnames carry **no cross-tool conformance claim**. The reserved
``#out`` segment is structurally impossible in loomweave's locator grammar (``#``
appears only inside ``impl#<...>`` discriminators) and cargo forbids the keyword
``crate`` as a package name, so neither route can collide with a class-1 /
loomweave locator.
"""

from __future__ import annotations

import os
import tomllib
from pathlib import Path

__all__ = ["CrateRoots", "discover_crate_roots"]

# Vendored / build / store directories the host also skips (oracle `is_ignored`).
_IGNORED_DIRS = frozenset({"target", ".git", ".weft", "node_modules"})


def _normalise(name: str) -> str:
    """Underscore a crate name the way Rust does (``a-b`` -> ``a_b``)."""
    return name.replace("-", "_")


class CrateRoots:
    """Crate roots discovered under a project root: each crate's root directory
    mapped to its (underscored) crate name, longest-prefix matched."""

    def __init__(self, roots: dict[Path, str]) -> None:
        # Sorted by path so longest-prefix lookup is deterministic (oracle: BTreeMap).
        self._roots: list[tuple[Path, str]] = sorted(roots.items())

    def crate_name_for(self, file: Path) -> str | None:
        """The crate name owning ``file``, by longest directory-prefix match."""
        owner = self._owning_root(file)
        return owner[1] if owner is not None else None

    def crate_dir_for(self, file: Path) -> Path | None:
        """The crate root directory owning ``file`` (the dir holding ``Cargo.toml``
        / ``src/``), by the same longest-prefix match as ``crate_name_for``. Join
        ``src`` onto this to get the source root for ``rust_module_route``."""
        owner = self._owning_root(file)
        return owner[0] if owner is not None else None

    def _owning_root(self, file: Path) -> tuple[Path, str] | None:
        candidates = [(d, n) for d, n in self._roots if file.is_relative_to(d)]
        if not candidates:
            return None
        return max(candidates, key=lambda item: len(str(item[0])))


def discover_crate_roots(project_root: Path) -> CrateRoots:
    """Walk ``project_root`` and discover every crate root directory and its
    (underscored) crate name (oracle ``discover_crate_roots``)."""
    roots: dict[Path, str] = {}
    _visit(project_root, roots)
    return CrateRoots(roots)


def _package_name(manifest: Path) -> str | None:
    """``[package].name`` iff ``manifest`` parses as TOML and the name is a string.

    ``name.workspace = true`` parses as a TABLE -> ``None`` (falls through to the
    dir-name branch); unparseable/unreadable/non-UTF-8 TOML -> ``None`` likewise.
    """
    try:
        with manifest.open("rb") as fh:
            value = tomllib.load(fh)
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError):
        return None
    package = value.get("package")
    if not isinstance(package, dict):
        return None
    name = package.get("name")
    return name if isinstance(name, str) else None


def _visit(directory: Path, out: dict[Path, str]) -> None:
    # Mirror the oracle's order: an unreadable dir registers nothing and is not walked.
    try:
        entries = list(os.scandir(directory))
    except OSError:
        return
    cargo = directory / "Cargo.toml"
    name = _package_name(cargo) if cargo.is_file() else None
    if name is not None:
        out[directory] = _normalise(name)
    elif ((directory / "src" / "lib.rs").is_file() or (directory / "src" / "main.rs").is_file()) and directory.name:
        out.setdefault(directory, _normalise(directory.name))
    for entry in entries:
        # Do NOT follow symlinked directories (oracle crate_roots.rs:83-94): a
        # symlinked dir is an out-of-tree escape or a cycle. `entry.is_symlink()`
        # reports the link itself; on an OSError we must not fall through to a
        # follow-links check — can-not-determine => do-not-recurse.
        try:
            if entry.is_symlink() or not entry.is_dir(follow_symlinks=False):
                continue
        except OSError:
            continue
        if entry.name in _IGNORED_DIRS:
            continue
        _visit(Path(entry.path), out)
