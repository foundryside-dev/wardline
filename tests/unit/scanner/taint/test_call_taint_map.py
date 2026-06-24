from __future__ import annotations

import ast

from wardline.core.taints import TaintState as T
from wardline.scanner.ast_primitives import build_import_alias_map
from wardline.scanner.taint.call_taint_map import build_call_taint_map
from wardline.scanner.taint.variable_level import compute_variable_taints


def _aliases(src: str, module: str) -> dict[str, str]:
    return build_import_alias_map(ast.parse(src), module_path=module)


def test_local_function_keyed_bare() -> None:
    aliases = _aliases("def a(): pass\ndef b(): pass\n", "m")
    tm = build_call_taint_map(
        module_path="m",
        alias_map=aliases,
        project_by_module={"m": {"a": T.MIXED_RAW, "b": T.UNKNOWN_RAW}},
    )
    assert tm["a"] == T.MIXED_RAW
    assert tm["b"] == T.UNKNOWN_RAW


def test_from_import_project_function_keyed_bare() -> None:
    aliases = _aliases("from other import helper\n", "m")
    tm = build_call_taint_map(
        module_path="m",
        alias_map=aliases,
        project_by_module={"other": {"helper": T.EXTERNAL_RAW}},
    )
    assert tm["helper"] == T.EXTERNAL_RAW


def test_dotted_module_project_call_keyed_dotted() -> None:
    aliases = _aliases("import other\n", "m")
    tm = build_call_taint_map(
        module_path="m",
        alias_map=aliases,
        project_by_module={"other": {"fn": T.MIXED_RAW}},
    )
    assert tm["other.fn"] == T.MIXED_RAW


def test_multicomponent_project_plain_import_keyed_fully() -> None:
    aliases = _aliases("import pkg.sources\n", "m")
    tm = build_call_taint_map(
        module_path="m",
        alias_map=aliases,
        project_by_module={"pkg.sources": {"read": T.EXTERNAL_RAW}},
    )
    assert tm["pkg.sources.read"] == T.EXTERNAL_RAW


def test_stdlib_external_dotted_taint_carries() -> None:
    # Positive external-dotted channel: a non-sink stdlib entry, aliased.
    aliases = _aliases("import subprocess as sp\n", "m")
    tm = build_call_taint_map(module_path="m", alias_map=aliases)
    assert tm["sp.check_output"] == T.EXTERNAL_RAW


def test_multicomponent_stdlib_plain_import_keyed_fully() -> None:
    # `import urllib.request` collapses the alias to `urllib`; the call is
    # written `urllib.request.urlopen`. The curated EXTERNAL_RAW must NOT be
    # dropped on this (idiomatic) form.
    aliases = _aliases("import urllib.request\n", "m")
    tm = build_call_taint_map(module_path="m", alias_map=aliases)
    assert tm["urllib.request.urlopen"] == T.EXTERNAL_RAW


def test_multicomponent_stdlib_aliased_import_keyed() -> None:
    aliases = _aliases("import urllib.request as ur\n", "m")
    tm = build_call_taint_map(module_path="m", alias_map=aliases)
    assert tm["ur.urlopen"] == T.EXTERNAL_RAW


def test_multicomponent_stdlib_from_import_keyed_bare() -> None:
    aliases = _aliases("from urllib.request import urlopen\n", "m")
    tm = build_call_taint_map(module_path="m", alias_map=aliases)
    assert tm["urlopen"] == T.EXTERNAL_RAW


def test_aliased_serialisation_sink_overrides_to_unknown_raw() -> None:
    # THE collision-fix gate: json.loads is stdlib GUARDED, but it is a
    # serialisation sink; under aliasing the literal sink check is bypassed, so
    # the taint_map entry MUST be UNKNOWN_RAW (conservative wins).
    aliases = _aliases("import json as j\n", "m")
    tm = build_call_taint_map(module_path="m", alias_map=aliases)
    assert tm["j.loads"] == T.UNKNOWN_RAW


def test_unaliased_serialisation_sink_also_unknown_raw() -> None:
    aliases = _aliases("import json\n", "m")
    tm = build_call_taint_map(module_path="m", alias_map=aliases)
    assert tm["json.loads"] == T.UNKNOWN_RAW


def test_from_import_sink_keyed_bare_unknown_raw() -> None:
    aliases = _aliases("from json import loads\n", "m")
    tm = build_call_taint_map(module_path="m", alias_map=aliases)
    assert tm["loads"] == T.UNKNOWN_RAW


def test_project_function_takes_precedence_over_stdlib() -> None:
    # A project function shadowing a stdlib name keeps its refined taint.
    aliases = _aliases("import subprocess as sp\n", "m")
    tm = build_call_taint_map(
        module_path="m",
        alias_map=aliases,
        project_by_module={"m": {"sp": T.INTEGRAL}},  # local 'sp' bare function
    )
    assert tm["sp"] == T.INTEGRAL  # local bare entry untouched by stdlib dotted


def test_l2_aliased_sink_yields_unknown_raw_end_to_end() -> None:
    src = "import json as j\ndef f(p):\n    x = j.loads(p)\n"
    func = ast.parse(src).body[1]
    assert isinstance(func, ast.FunctionDef)
    aliases = build_import_alias_map(ast.parse(src), module_path="m")
    tm = build_call_taint_map(module_path="m", alias_map=aliases)
    out = compute_variable_taints(func, T.ASSURED, dict(tm))
    assert out["x"] == T.UNKNOWN_RAW  # NOT GUARDED, NOT ASSURED


def test_l2_aliased_nonsink_stdlib_carries_external_raw() -> None:
    src = "import subprocess as sp\ndef f(c):\n    x = sp.check_output(c)\n"
    func = ast.parse(src).body[1]
    assert isinstance(func, ast.FunctionDef)
    aliases = build_import_alias_map(ast.parse(src), module_path="m")
    tm = build_call_taint_map(module_path="m", alias_map=aliases)
    out = compute_variable_taints(func, T.INTEGRAL, dict(tm))
    assert out["x"] == T.EXTERNAL_RAW


def test_l2_urllib_plain_import_carries_external_raw_end_to_end() -> None:
    src = "import urllib.request\ndef f(u):\n    x = urllib.request.urlopen(u)\n"
    func = ast.parse(src).body[1]
    assert isinstance(func, ast.FunctionDef)
    aliases = build_import_alias_map(ast.parse(src), module_path="m")
    tm = build_call_taint_map(module_path="m", alias_map=aliases)
    out = compute_variable_taints(func, T.INTEGRAL, dict(tm))
    assert out["x"] == T.EXTERNAL_RAW  # the curated network-source taint, not dropped


def test_l2_project_plain_submodule_import_carries_return_taint_end_to_end() -> None:
    src = "import pkg.sources\ndef f(p):\n    x = pkg.sources.read(p)\n"
    func = ast.parse(src).body[1]
    assert isinstance(func, ast.FunctionDef)
    aliases = build_import_alias_map(ast.parse(src), module_path="m")
    tm = build_call_taint_map(
        module_path="m",
        alias_map=aliases,
        project_by_module={"pkg.sources": {"read": T.EXTERNAL_RAW}},
    )
    out = compute_variable_taints(func, T.ASSURED, dict(tm))
    assert out["x"] == T.EXTERNAL_RAW


def test_stdlib_plain_import_does_not_trust_project_submodule_spoof_end_to_end() -> None:
    src = "import os\ndef f(p):\n    x = os.path.normpath(p)\n"
    func = ast.parse(src).body[1]
    assert isinstance(func, ast.FunctionDef)
    aliases = build_import_alias_map(ast.parse(src), module_path="m")
    tm = build_call_taint_map(
        module_path="m",
        alias_map=aliases,
        project_by_module={"os.path": {"normpath": T.ASSURED}},
    )
    assert "os.path.normpath" not in tm

    out = compute_variable_taints(func, T.INTEGRAL, dict(tm), alias_map=aliases)

    assert out["x"] == T.UNKNOWN_RAW


def test_stdlib_alias_import_does_not_trust_project_submodule_spoof_end_to_end() -> None:
    src = "import os.path as op\ndef f(p):\n    x = op.normpath(p)\n"
    func = ast.parse(src).body[1]
    assert isinstance(func, ast.FunctionDef)
    aliases = build_import_alias_map(ast.parse(src), module_path="m")
    tm = build_call_taint_map(
        module_path="m",
        alias_map=aliases,
        project_by_module={"os.path": {"normpath": T.ASSURED}},
    )
    assert "op.normpath" not in tm

    out = compute_variable_taints(func, T.INTEGRAL, dict(tm), alias_map=aliases)

    assert out["x"] == T.UNKNOWN_RAW


def test_stdlib_from_import_parent_does_not_trust_project_submodule_spoof_end_to_end() -> None:
    src = "from os import path\ndef f(p):\n    x = path.normpath(p)\n"
    func = ast.parse(src).body[1]
    assert isinstance(func, ast.FunctionDef)
    aliases = build_import_alias_map(ast.parse(src), module_path="m")
    tm = build_call_taint_map(
        module_path="m",
        alias_map=aliases,
        project_by_module={"os.path": {"normpath": T.ASSURED}},
    )
    assert "path.normpath" not in tm

    out = compute_variable_taints(func, T.INTEGRAL, dict(tm), alias_map=aliases)

    assert out["x"] == T.UNKNOWN_RAW


def test_stdlib_from_import_function_does_not_trust_project_spoof_end_to_end() -> None:
    src = "from os.path import normpath\ndef f(p):\n    x = normpath(p)\n"
    func = ast.parse(src).body[1]
    assert isinstance(func, ast.FunctionDef)
    aliases = build_import_alias_map(ast.parse(src), module_path="m")
    tm = build_call_taint_map(
        module_path="m",
        alias_map=aliases,
        project_by_module={"os.path": {"normpath": T.ASSURED}},
    )
    assert "normpath" not in tm

    out = compute_variable_taints(func, T.INTEGRAL, dict(tm), alias_map=aliases)

    assert out["x"] == T.UNKNOWN_RAW


# ── PART D: aliased serialisation sinks NOT in stdlib_taint resolve to UNKNOWN_RAW ──
#
# json.dumps/json.dump are in _SERIALISATION_SINKS but ABSENT from stdlib_taint
# (only json.load/loads are curated). The literal sink check in _resolve_call
# only matches the written name, so an aliased `import json as j; j.dumps(x)`
# was not injected into the taint map and fell back to function_taint — a
# fail-open launder for a @trusted producer. A second override pass injects
# UNKNOWN_RAW for aliases of EVERY name in _SERIALISATION_SINKS.


def test_aliased_json_dumps_resolves_unknown_raw() -> None:
    aliases = _aliases("import json as j\n", "m")
    tm = build_call_taint_map(module_path="m", alias_map=aliases)
    assert tm["j.dumps"] == T.UNKNOWN_RAW
    assert tm["j.dump"] == T.UNKNOWN_RAW


def test_aliased_json_dumps_end_to_end_not_laundered() -> None:
    # @trusted-style seed INTEGRAL; j.dumps(read_raw(p)) must NOT launder to trusted.
    src = "import json as j\ndef f(p):\n    x = j.dumps(p)\n"
    func = ast.parse(src).body[1]
    assert isinstance(func, ast.FunctionDef)
    aliases = build_import_alias_map(ast.parse(src), module_path="m")
    tm = build_call_taint_map(module_path="m", alias_map=aliases)
    out = compute_variable_taints(func, T.INTEGRAL, dict(tm))
    assert out["x"] == T.UNKNOWN_RAW  # NOT INTEGRAL


def test_aliased_pickle_sink_resolves_unknown_raw() -> None:
    # pickle.dumps is a _SERIALISATION_SINK but uncurated in stdlib_taint — the
    # documented residual gap. The second override pass closes it.
    aliases = _aliases("import pickle as pk\n", "m")
    tm = build_call_taint_map(module_path="m", alias_map=aliases)
    assert tm["pk.dumps"] == T.UNKNOWN_RAW


def test_from_import_aliased_dumps_resolves_unknown_raw() -> None:
    aliases = _aliases("from json import dumps as d\n", "m")
    tm = build_call_taint_map(module_path="m", alias_map=aliases)
    assert tm["d"] == T.UNKNOWN_RAW


# ── Coverage: the serialisation-sink alias-closure arms that the SHIPPED sink set
# (all single-component-package dotted names) does not exercise. These defensive
# arms guard FUTURE sink shapes; we drive them by injecting such sinks. ──


def test_bare_name_sink_is_skipped(monkeypatch) -> None:
    # A sink with NO package (a bare name) has no alias form to close over, so the
    # closure loop must skip it (the `if not pkg: continue` guard) and produce no entry.
    import wardline.scanner.taint.call_taint_map as ctm

    monkeypatch.setattr(ctm, "_SERIALISATION_SINKS", frozenset({"baresink"}))
    aliases = _aliases("import baresink\n", "m")
    tm = build_call_taint_map(module_path="m", alias_map=aliases)
    assert "baresink" not in tm  # bare-name sink contributes nothing via the closure


def test_multicomponent_package_sink_keyed_under_collapsed_alias(monkeypatch) -> None:
    # A sink whose package is multi-component (``pkg.sub``): under ``import pkg.sub``
    # the alias collapses to ``pkg``, and the call is written ``pkg.sub.fn``. The
    # `pkg.startswith(target + ".")` arm must key the full written name to UNKNOWN_RAW.
    import wardline.scanner.taint.call_taint_map as ctm

    monkeypatch.setattr(ctm, "_SERIALISATION_SINKS", frozenset({"deep.pkg.dump"}))
    aliases = _aliases("import deep.pkg\n", "m")
    tm = build_call_taint_map(module_path="m", alias_map=aliases)
    assert tm["deep.pkg.dump"] == T.UNKNOWN_RAW


def test_from_import_parent_of_nested_stdlib_function() -> None:
    # from os import environ; environ.get(k)
    aliases = _aliases("from os import environ\n", "m")
    tm = build_call_taint_map(module_path="m", alias_map=aliases)
    assert tm["environ.get"] == T.EXTERNAL_RAW


def test_from_import_parent_of_nested_sink(monkeypatch) -> None:
    # from deep import pkg; pkg.dump(x)
    import wardline.scanner.taint.call_taint_map as ctm

    monkeypatch.setattr(ctm, "_SERIALISATION_SINKS", frozenset({"deep.pkg.dump"}))
    aliases = _aliases("from deep import pkg\n", "m")
    tm = build_call_taint_map(module_path="m", alias_map=aliases)
    assert tm["pkg.dump"] == T.UNKNOWN_RAW
