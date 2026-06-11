# src/wardline/scanner/taint/call_taint_map.py
"""Build the per-file L2 call-taint-map consumed by ``compute_variable_taints``.

Keyed by call-site name AS WRITTEN (bare ``foo`` / dotted ``mod.fn``), mapping to
the call's return taint. Folds in two sources, alias-resolved against the file's
import map:

  * Project function returns — from the L3 ``ResolverResult.taint_map`` (refined
    body taint; equals return taint for all non-anchored functions, SP1's whole
    universe — see ``# SP2`` note in the analyzer). Supplied pre-bucketed as
    ``project_by_module`` (``{module: {top_level_func_name: taint}}``) so this
    builder is O(aliases) per file rather than rescanning the whole project.
  * ``stdlib_taint`` — with the SERIALISATION-SINK OVERRIDE: any stdlib entry
    whose ``(pkg, fn)`` is also a serialisation sink is inserted as
    ``UNKNOWN_RAW``, never its stdlib taint. ``_resolve_call``'s sink check only
    matches the *literal* written name, so without this override an aliased
    ``import json as j; j.loads(p)`` would skip the sink check and read the
    stdlib ``GUARDED`` — an under-taint. Inserting ``UNKNOWN_RAW`` makes literal
    and aliased calls agree (conservative wins).

Multi-component stdlib packages (e.g. ``urllib.request``) are handled for all
three import forms: ``import urllib.request`` (alias map collapses to
``{"urllib": "urllib"}``; the call is written ``urllib.request.urlopen``),
``import urllib.request as ur``, and ``from urllib.request import urlopen``.

Project entries take precedence over stdlib (``setdefault`` for stdlib).
Residual known gap: an aliased serialisation sink NOT in the stdlib table (e.g.
``import pickle as p`` when pickle is uncurated) has no taint_map entry and the
literal sink check misses the alias, so it falls back to the function taint —
pre-existing, not worsened here.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING

from wardline.core.taints import TaintState
from wardline.scanner.taint.stdlib_taint import load_stdlib_taint
from wardline.scanner.taint.variable_level import _SERIALISATION_SINKS

if TYPE_CHECKING:
    from wardline.core.config import WardlineConfig


def _match_config_item(item: str, alias_map: dict[str, str]) -> list[str]:
    pkg, _, fn = item.rpartition(".")
    if not pkg:
        return []
    keys = []
    for local, target in alias_map.items():
        if target == pkg:
            keys.append(f"{local}.{fn}")
        elif target == f"{pkg}.{fn}":
            keys.append(local)
        elif pkg.startswith(target + "."):
            remainder = pkg[len(target) + 1 :]
            keys.append(f"{local}.{remainder}.{fn}")
        elif f"{pkg}.{fn}".startswith(target + "."):
            remainder = f"{pkg}.{fn}"[len(target) + 1 :]
            keys.append(f"{local}.{remainder}")
    return keys


def build_call_taint_map(
    *,
    module_path: str,
    alias_map: dict[str, str],
    project_by_module: Mapping[str, Mapping[str, TaintState]] | None = None,
    config: WardlineConfig | None = None,
    matched_sources: set[str] | None = None,
    matched_sanitisers: set[str] | None = None,
) -> dict[str, TaintState]:
    """Return ``{call-site-name: return-taint}`` for one file.

    ``project_by_module`` maps each project module to its top-level functions'
    refined taints (``{module: {func_name: taint}}``) — built once by the
    analyzer over the whole project.
    """
    project_by_module = project_by_module or {}
    tm: dict[str, TaintState] = {}

    # (a) Local top-level functions — bare-callable in this module.
    for name, taint in project_by_module.get(module_path, {}).items():
        tm[name] = taint

    # (b)+(c) Imported project symbols, via the file's alias map.
    for local, target in alias_map.items():
        bucket = project_by_module.get(target)
        if bucket is not None:
            # module import: dotted ``local.func`` calls
            for func_name, taint in bucket.items():
                tm[f"{local}.{func_name}"] = taint
        for module, module_bucket in project_by_module.items():
            if module.startswith(target + "."):
                # ``import pkg.sub`` collapses the alias to ``pkg``; the call is
                # written ``local.<rest-of-module>.fn`` just like multi-component
                # stdlib imports.
                remainder = module[len(target) + 1 :]
                for func_name, taint in module_bucket.items():
                    tm[f"{local}.{remainder}.{func_name}"] = taint
        # from-import of a project function: target == "module.func_name"
        mod, _, leaf = target.rpartition(".")
        mod_bucket = project_by_module.get(mod)
        if mod_bucket is not None and leaf in mod_bucket:
            tm[local] = mod_bucket[leaf]

    # (d) stdlib_taint with the serialisation-sink override.
    stdlib = load_stdlib_taint()
    for (pkg, fn), entry in stdlib.items():
        value = TaintState.UNKNOWN_RAW if f"{pkg}.{fn}" in _SERIALISATION_SINKS else entry.taint
        for local, target in alias_map.items():
            if target == pkg:
                tm.setdefault(f"{local}.{fn}", value)  # import pkg [as local]
            elif target == f"{pkg}.{fn}":
                tm.setdefault(local, value)  # from pkg import fn [as local]
            elif pkg.startswith(target + "."):
                # ``import top.sub`` collapses the alias to ``top``; the call is
                # written ``local.<rest-of-pkg>.fn`` (e.g. urllib.request.urlopen).
                remainder = pkg[len(target) + 1 :]
                tm.setdefault(f"{local}.{remainder}.{fn}", value)
            elif f"{pkg}.{fn}".startswith(target + "."):
                remainder = f"{pkg}.{fn}"[len(target) + 1 :]
                tm.setdefault(f"{local}.{remainder}", value)
        if pkg == "builtins":
            tm.setdefault(fn, value)

    # (e) Serialisation-sink alias closure. The override in (d) only fires for
    # sinks that are ALSO present in stdlib_taint (just json.load/loads). Sinks
    # absent from the curated table — json.dump/dumps, pickle.*, yaml.*,
    # marshal.*, tomli_w.* — would otherwise have NO map entry, and
    # ``_resolve_call``'s literal sink check misses the aliased written name
    # (``j.dumps`` ≠ ``json.dumps``), so an aliased sink fell back to the
    # function taint — a fail-open launder for a @trusted producer. Inject
    # UNKNOWN_RAW for every alias form of every serialisation sink so literal and
    # aliased calls agree. ``setdefault`` keeps any project/stdlib precedence.
    for sink in _SERIALISATION_SINKS:
        pkg, _, fn = sink.rpartition(".")
        if not pkg:
            continue
        for local, target in alias_map.items():
            if target == pkg:
                tm.setdefault(f"{local}.{fn}", TaintState.UNKNOWN_RAW)  # import pkg [as local]
            elif target == sink:
                tm.setdefault(local, TaintState.UNKNOWN_RAW)  # from pkg import fn [as local]
            elif pkg.startswith(target + "."):
                remainder = pkg[len(target) + 1 :]
                tm.setdefault(f"{local}.{remainder}.{fn}", TaintState.UNKNOWN_RAW)
            elif sink.startswith(target + "."):
                remainder = sink[len(target) + 1 :]
                tm.setdefault(f"{local}.{remainder}", TaintState.UNKNOWN_RAW)

    # (f) Add config-defined untrusted sources and sanitisers (strictly additive)
    if config is not None:
        for src in config.untrusted_sources:
            keys = _match_config_item(src, alias_map)
            if keys:
                if matched_sources is not None:
                    matched_sources.add(src)
                for k in keys:
                    tm.setdefault(k, TaintState.EXTERNAL_RAW)

        for san in config.sanitisers:
            keys = _match_config_item(san, alias_map)
            if keys:
                if matched_sanitisers is not None:
                    matched_sanitisers.add(san)
                for k in keys:
                    tm.setdefault(k, TaintState.ASSURED)

    return tm
