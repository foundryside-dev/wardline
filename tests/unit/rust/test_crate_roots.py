"""Task 4 (SP2): Cargo.toml crate-root discovery + crate-prefixed module routes.

``wardline.rust.crate_roots`` mirrors the loomweave oracle
(``crates/loomweave-plugin-rust/src/crate_roots.rs``) exactly:

* **Two-branch registration:** a dir is a crate root iff (a) its ``Cargo.toml``
  parses as TOML AND ``[package].name`` is a string -> that name ``-``->``_``
  normalised; ELSE (b) ``src/lib.rs`` or ``src/main.rs`` exists -> the directory
  name normalised. A virtual workspace root (no package name, no src/lib|main.rs)
  registers NOTHING — member crates own their files outright.
* **Walk:** symlinked directories are never followed (out-of-tree escape / cycle).
* **Lookup:** file -> crate by longest path-prefix match.

The COVERAGE tests pin the panel's must-fix: wardline does NOT mirror loomweave's
``emittable_scope`` (scope.rs:21-32) for scan coverage — out-of-src files
(tests/, build.rs) and no-Cargo trees keep producing RS-WL findings via the
documented wardline-local fallback route; only the *route shape* differs.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from wardline.rust.crate_roots import discover_crate_roots

_TRUSTED = "/// @trusted(level=ASSURED)\n"
_INJECTION = _TRUSTED + 'fn run() {\n    let t = std::env::var("X").unwrap();\n    Command::new(t).output();\n}\n'


def _write_crate(root: Path, rel: str, manifest: str, *, lib: bool = True) -> Path:
    crate = root / rel
    (crate / "src").mkdir(parents=True)
    (crate / "Cargo.toml").write_text(manifest, encoding="utf-8")
    (crate / "src" / ("lib.rs" if lib else "main.rs")).write_text("pub fn f() {}\n", encoding="utf-8")
    return crate


# --------------------------------------------------------------------------- #
# Registration + lookup (pure discovery — mirrors the oracle's branches)
# --------------------------------------------------------------------------- #


def test_single_crate_registers_normalised_package_name(tmp_path: Path) -> None:
    crate = _write_crate(tmp_path, "app", '[package]\nname = "my-app"\nversion = "0.1.0"\n')
    roots = discover_crate_roots(tmp_path)
    assert roots.crate_name_for(crate / "src" / "lib.rs") == "my_app"  # - -> _ normalised
    assert roots.crate_dir_for(crate / "src" / "lib.rs") == crate


def test_virtual_workspace_root_registers_nothing(tmp_path: Path) -> None:
    # A [workspace]-only manifest with no src/lib|main.rs is NOT a crate root —
    # member crates own their files outright (oracle: no package.name -> fall
    # through; no src roots -> nothing registered).
    (tmp_path / "Cargo.toml").write_text('[workspace]\nmembers = ["m1", "m2"]\n', encoding="utf-8")
    m1 = _write_crate(tmp_path, "m1", '[package]\nname = "m-one"\n')
    m2 = _write_crate(tmp_path, "m2", '[package]\nname = "m_two"\n', lib=False)
    roots = discover_crate_roots(tmp_path)
    assert roots.crate_dir_for(tmp_path / "stray.rs") is None  # the workspace root owns nothing
    assert roots.crate_name_for(m1 / "src" / "lib.rs") == "m_one"
    assert roots.crate_name_for(m2 / "src" / "main.rs") == "m_two"


def test_nested_crates_resolve_by_longest_prefix(tmp_path: Path) -> None:
    outer = _write_crate(tmp_path, "outer", '[package]\nname = "outer"\n')
    inner = _write_crate(tmp_path, "outer/inner", '[package]\nname = "inner"\n', lib=False)
    roots = discover_crate_roots(tmp_path)
    assert roots.crate_name_for(outer / "src" / "lib.rs") == "outer"
    assert roots.crate_name_for(inner / "src" / "main.rs") == "inner"  # longest prefix wins
    assert roots.crate_dir_for(inner / "src" / "main.rs") == inner


def test_name_workspace_true_with_src_falls_back_to_dir_name(tmp_path: Path) -> None:
    # `name.workspace = true` parses as a TABLE, not a string -> branch (a) falls
    # through; src/lib.rs exists -> branch (b) dir-name fallback (normalised).
    crate = _write_crate(tmp_path, "member-a", "[package]\nname.workspace = true\n")
    roots = discover_crate_roots(tmp_path)
    assert roots.crate_name_for(crate / "src" / "lib.rs") == "member_a"


def test_package_less_manifest_without_src_is_not_a_root(tmp_path: Path) -> None:
    nodir = tmp_path / "meta"
    nodir.mkdir()
    (nodir / "Cargo.toml").write_text('[package]\nversion = "0.1.0"\n', encoding="utf-8")  # no name
    roots = discover_crate_roots(tmp_path)
    assert roots.crate_name_for(nodir / "x.rs") is None
    assert roots.crate_dir_for(nodir / "x.rs") is None


def test_unparseable_manifest_falls_back_to_dir_name(tmp_path: Path) -> None:
    crate = _write_crate(tmp_path, "broken", "this = = is not toml [\n")
    roots = discover_crate_roots(tmp_path)
    assert roots.crate_name_for(crate / "src" / "lib.rs") == "broken"


@pytest.mark.skipif(os.name != "posix", reason="symlinks: posix-only fixture")
def test_symlinked_external_crate_dir_is_not_registered(tmp_path: Path) -> None:
    # Mirrors loomweave's does_not_register_crate_roots_reached_through_symlinked_dirs:
    # a symlinked dir is an out-of-tree ESCAPE (an outside Cargo.toml would mint an
    # outside crate root) or a CYCLE (re-registration under an aliased path).
    proj = tmp_path / "proj"
    real = _write_crate(proj, "c", '[package]\nname = "c_crate"\n')
    outside = _write_crate(tmp_path, "outside", '[package]\nname = "evil_crate"\n')
    (proj / "evil").symlink_to(outside)
    (proj / "loop").symlink_to(proj)  # the walk must RETURN, not recurse forever

    roots = discover_crate_roots(proj)
    assert roots.crate_name_for(real / "src" / "lib.rs") == "c_crate"
    assert roots.crate_name_for(proj / "evil" / "src" / "lib.rs") is None, (
        "out-of-tree crate reached via symlink must not be a registered root"
    )


# --------------------------------------------------------------------------- #
# Module routing through the analyzer (the three file classes) + coverage
# preservation. These need the tree-sitter extra (they drive RustAnalyzer).
# --------------------------------------------------------------------------- #


def _analyzer_module():  # noqa: ANN202 - dynamic import behind importorskip
    pytest.importorskip("tree_sitter", reason="wardline[rust] extra not installed")
    from wardline.rust import analyzer

    return analyzer


def test_in_src_files_get_the_oracle_crate_prefixed_route(tmp_path: Path) -> None:
    analyzer = _analyzer_module()
    crate = _write_crate(tmp_path, "app", '[package]\nname = "my-app"\n')
    (crate / "src" / "a").mkdir()
    (crate / "src" / "a" / "b.rs").write_text("", encoding="utf-8")
    (crate / "src" / "a" / "mod.rs").write_text("", encoding="utf-8")
    roots = discover_crate_roots(tmp_path)

    route = analyzer._module_for  # noqa: SLF001 - the unit under test
    assert route(crate / "src" / "lib.rs", tmp_path, roots) == "my_app"
    assert route(crate / "src" / "a" / "b.rs", tmp_path, roots) == "my_app.a.b"
    assert route(crate / "src" / "a" / "mod.rs", tmp_path, roots) == "my_app.a"


def test_workspace_member_files_route_to_their_own_crates(tmp_path: Path) -> None:
    analyzer = _analyzer_module()
    (tmp_path / "Cargo.toml").write_text('[workspace]\nmembers = ["m1", "m2"]\n', encoding="utf-8")
    m1 = _write_crate(tmp_path, "m1", '[package]\nname = "m-one"\n')
    m2 = _write_crate(tmp_path, "m2", '[package]\nname = "m_two"\n', lib=False)
    roots = discover_crate_roots(tmp_path)

    route = analyzer._module_for  # noqa: SLF001
    assert route(m1 / "src" / "lib.rs", tmp_path, roots) == "m_one"
    assert route(m2 / "src" / "main.rs", tmp_path, roots) == "m_two"


def test_out_of_src_files_get_the_out_branded_crate_route(tmp_path: Path) -> None:
    # Class 2: under a crate root but OUTSIDE its src/ — loomweave's emittable_scope
    # emits NOTHING here; wardline routes mechanically from the crate dir under the
    # real crate name + the reserved `#out` segment (no cross-tool conformance claim;
    # `#` appears only inside loomweave's `impl#<...>` discriminators, so the route
    # can never collide with a class-1/loomweave locator). ALL stems are literal —
    # no main/lib/mod collapsing.
    analyzer = _analyzer_module()
    crate = _write_crate(tmp_path, "c", '[package]\nname = "c-app"\n')
    (crate / "tests").mkdir()
    (crate / "tests" / "integration.rs").write_text("", encoding="utf-8")
    (crate / "build.rs").write_text("", encoding="utf-8")
    roots = discover_crate_roots(tmp_path)

    route = analyzer._module_for  # noqa: SLF001
    assert route(crate / "build.rs", tmp_path, roots) == "c_app.#out.build"
    assert route(crate / "tests" / "integration.rs", tmp_path, roots) == "c_app.#out.tests.integration"


def test_class2_route_cannot_collide_with_an_in_src_twin(tmp_path: Path) -> None:
    # The keystone panel's collision repro, inverted: <crate>/tests/integration.rs
    # (class 2) and <crate>/src/tests/integration.rs (class 1) used to mint the SAME
    # qualname prefix (`c_app.tests.integration`). The `#out` branding separates them.
    analyzer = _analyzer_module()
    crate = _write_crate(tmp_path, "c", '[package]\nname = "c-app"\n')
    (crate / "src" / "tests").mkdir()
    (crate / "src" / "tests" / "integration.rs").write_text("", encoding="utf-8")
    (crate / "tests").mkdir()
    (crate / "tests" / "integration.rs").write_text("", encoding="utf-8")
    roots = discover_crate_roots(tmp_path)

    route = analyzer._module_for  # noqa: SLF001
    in_src = route(crate / "src" / "tests" / "integration.rs", tmp_path, roots)
    out_of_src = route(crate / "tests" / "integration.rs", tmp_path, roots)
    assert in_src == "c_app.tests.integration"  # class 1: the conformance-bearing route
    assert out_of_src == "c_app.#out.tests.integration"  # class 2: #out-branded
    assert in_src != out_of_src


def test_no_crate_files_get_the_relpath_pure_constant_crate_route(tmp_path: Path) -> None:
    # Class 3: no owning crate root anywhere. The crate segment is the CONSTANT
    # "crate" (cargo forbids the keyword as a package name, so it cannot collide
    # with class 1) + the `#out` branding + literal relpath stems — relpath-pure,
    # scan-root-name-INDEPENDENT (renaming the root directory does not rekey).
    analyzer = _analyzer_module()
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "m.rs").write_text("", encoding="utf-8")
    roots = discover_crate_roots(tmp_path)

    assert roots.crate_dir_for(tmp_path / "src" / "m.rs") is None  # no lib.rs/main.rs -> no root
    got = analyzer._module_for(tmp_path / "src" / "m.rs", tmp_path, roots)  # noqa: SLF001
    assert got == "crate.#out.src.m"  # NOT f"{tmp_path.name}..." — root-name-independent


def test_scan_coverage_is_not_narrowed_to_emittable_scope(tmp_path: Path) -> None:
    # The panel's must-fix, end-to-end: build.rs, tests/, and a bare no-Cargo tree
    # all still produce RS-WL findings (loomweave EXCLUDES them from its federation
    # entity surface; wardline keeps scanning them via the fallback route).
    analyzer = _analyzer_module()
    from wardline.core.config import WardlineConfig

    crate = _write_crate(tmp_path, "c", '[package]\nname = "c-app"\n')
    (crate / "src" / "cmd.rs").write_text(_INJECTION, encoding="utf-8")
    (crate / "build.rs").write_text(_INJECTION, encoding="utf-8")
    (crate / "tests").mkdir()
    (crate / "tests" / "integration.rs").write_text(_INJECTION, encoding="utf-8")
    bare = tmp_path / "bare"
    bare.mkdir()
    (bare / "m.rs").write_text(_INJECTION, encoding="utf-8")

    files = [crate / "src" / "cmd.rs", crate / "build.rs", crate / "tests" / "integration.rs", bare / "m.rs"]
    findings = list(analyzer.RustAnalyzer().analyze(files, WardlineConfig(), root=tmp_path))

    rs = [f for f in findings if f.rule_id == "RS-WL-108"]
    assert sorted(f.location.path for f in rs) == [
        "bare/m.rs",
        "c/build.rs",
        "c/src/cmd.rs",
        "c/tests/integration.rs",
    ]
    by_path = {f.location.path: f.qualname for f in rs}
    assert by_path["c/src/cmd.rs"] == "c_app.cmd.run"  # class 1: the oracle route
    assert by_path["c/build.rs"] == "c_app.#out.build.run"  # class 2: #out-branded crate route
    assert by_path["c/tests/integration.rs"] == "c_app.#out.tests.integration.run"
    assert by_path["bare/m.rs"] == "crate.#out.bare.m.run"  # class 3: relpath-pure constant crate
