# src/wardline/scanner/rules/path_traversal.py
"""PY-WL-116 — untrusted data reaches a path/filesystem-traversal sink.

Passing untrusted data to filesystem APIs can lead to path traversal (CWE-22).
Three sink families (wardline-04b65cf0be + the Zip Slip eval item):

* **Direct dotted calls** with a tainted path argument — ``open``/``os.open``/
  ``os.path.join``/``pathlib.Path`` plus the filesystem-MUTATION APIs
  (``os.remove``/``os.rename``/``shutil.rmtree``/``shutil.copy``/...), where a
  tainted path is a destructive traversal (delete/move/copy outside the
  intended directory). All argument slots are path-like, so the inherited
  worst-of-all-args taint is the correct selector (a tainted destination is
  traversal too) — no :class:`ArgSpec` needed.
* **Path METHODS** (``read_text``/``write_bytes``/``open``/``unlink``/...) on a
  ``pathlib.Path`` CONSTRUCTED from tainted input, resolved through the shared
  sink-binding machinery (``p = Path(raw); p.read_text()`` and the chained
  ``pathlib.Path(raw).read_text()``). The dangerous data is the CONSTRUCTOR's
  argument, so the taint is read from the constructor call, not the
  (typically argument-less) method call.
* **Archive extraction** (Zip Slip / tarbomb): ``extractall``/``extract`` on a
  ``tarfile.open``/``tarfile.TarFile``/``zipfile.ZipFile`` instance whose
  ARCHIVE SOURCE is tainted — a malicious archive escapes the target directory
  via ``../`` member names. Exemption: an extraction call passing tarfile's
  safe filter as the literal ``filter="data"`` (blocks absolute paths,
  traversal, and device members since 3.12) does not fire; any other filter
  value (including ``"fully_trusted"`` or a dynamic expression) still fires.

v1 method-sink scope: the constructor must be a function-local binding (an
assignment / ``with ... as`` / walrus in the same scope, or the chained
receiver). Module-level constructions and annotation-only bindings carry no
resolvable constructor call and stay silent.

Tier-modulated; fires only where trust is declared.
"""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING

from wardline.core.finding import Finding, Kind, Maturity, Severity
from wardline.scanner.rules._sink_helpers import (
    RAW_ZONE,
    TaintedSinkRule,
    build_sink_finding,
    collect_ctor_call_nodes,
    enclosing_declared_tier,
    module_for_qualname,
    receiver_ctor_call,
    resolved_sink_calls,
    worst_arg_taint,
)
from wardline.scanner.rules.metadata import RuleMetadata
from wardline.scanner.rules.severity_model import modulate

if TYPE_CHECKING:
    from wardline.scanner.context import AnalysisContext

_SINKS = frozenset(
    {
        "open",
        "builtins.open",
        "os.open",
        "os.path.join",
        "pathlib.Path",
        # filesystem mutation — tainted paths here are destructive traversal
        "os.remove",
        "os.unlink",
        "os.rmdir",
        "os.makedirs",
        "os.mkdir",
        "os.rename",
        "os.renames",
        "os.replace",
        "shutil.rmtree",
        "shutil.copy",
        "shutil.copy2",
        "shutil.copyfile",
        "shutil.copytree",
        "shutil.move",
    }
)

_PATH_METHODS = ("read_text", "read_bytes", "write_text", "write_bytes", "open", "unlink", "rmdir", "mkdir")
_PATH_METHOD_SINKS = frozenset(f"pathlib.Path.{m}" for m in _PATH_METHODS)

_ARCHIVE_CTORS = ("tarfile.open", "tarfile.TarFile", "zipfile.ZipFile")
_ARCHIVE_METHOD_SINKS = frozenset(f"{ctor}.{m}" for ctor in _ARCHIVE_CTORS for m in ("extractall", "extract"))

_METHOD_SINKS = _PATH_METHOD_SINKS | _ARCHIVE_METHOD_SINKS

METADATA = RuleMetadata(
    rule_id="PY-WL-116",
    base_severity=Severity.WARN,
    kind=Kind.DEFECT,
    multi_emit=True,
    description=(
        "Untrusted data reaches a path/filesystem-traversal sink (open/os.path.join/pathlib.Path, "
        "filesystem mutation via os.remove/os.rename/shutil.*, Path methods on a tainted pathlib.Path, "
        "or tarfile/zipfile archive extraction — Zip Slip) in a trusted-tier function."
    ),
    examples_violation=(
        "@external_boundary\ndef read_raw(p):\n    return p\n"
        "@trusted(level='ASSURED')\ndef f(p):\n    open(read_raw(p))",
        "import shutil\n"
        "@external_boundary\ndef read_raw(p):\n    return p\n"
        "@trusted(level='ASSURED')\ndef f(p):\n    shutil.rmtree(read_raw(p))",
        "import pathlib\n"
        "@external_boundary\ndef read_raw(p):\n    return p\n"
        "@trusted(level='ASSURED')\ndef f(p):\n    q = pathlib.Path(read_raw(p))\n    return q.read_text()",
        "import tarfile\n"
        "@external_boundary\ndef read_raw(p):\n    return p\n"
        "@trusted(level='ASSURED')\ndef f(p):\n    tf = tarfile.open(read_raw(p))\n    tf.extractall('/dst')",
    ),
    examples_clean=(
        "@trusted(level='ASSURED')\ndef f():\n    open('safe_file.txt')",
        "import tarfile\n"
        "@external_boundary\ndef read_raw(p):\n    return p\n"
        "@trusted(level='ASSURED')\ndef f(p):\n    tf = tarfile.open(read_raw(p))\n"
        "    tf.extractall('/dst', filter='data')",
    ),
    maturity=Maturity.PREVIEW,
)


def _has_safe_extraction_filter(call: ast.Call) -> bool:
    """True iff the extraction call passes tarfile's safe filter as the LITERAL
    ``filter="data"``. Any other value — ``"fully_trusted"``, ``"tar"`` (which still
    permits in-tree hardlink tricks pre-3.12.x fixes), or a dynamic expression — is
    not accepted as a mitigation."""
    return any(
        kw.arg == "filter" and isinstance(kw.value, ast.Constant) and kw.value.value == "data" for kw in call.keywords
    )


class PathTraversal(TaintedSinkRule):
    rule_id = METADATA.rule_id
    metadata = METADATA
    SINKS = _SINKS
    sink_label = "path-traversal"

    def check(self, context: AnalysisContext) -> list[Finding]:
        findings = super().check(context)  # direct dotted sinks (worst-of-all-args)
        findings.extend(self._method_sink_findings(context))
        return findings

    def _method_sink_findings(self, context: AnalysisContext) -> list[Finding]:
        """Construct-then-method sinks: Path methods and archive extraction.

        The method call itself is usually argument-less — the dangerous data is what
        the RECEIVER was constructed from, so the taint verdict is the constructor
        call's worst argument taint (flow-sensitive, at the construction site).
        """
        findings: list[Finding] = []
        for qualname, entity in context.entities.items():
            tier = enclosing_declared_tier(qualname, context.project_taints, context.declared_qualnames)
            severity = modulate(self.base_severity, tier)
            if severity == Severity.NONE:
                continue  # freedom / fail-closed zone — suppressed
            module = module_for_qualname(qualname, context)
            alias_map = context.alias_maps.get(module, {}) if module is not None else {}
            ctor_nodes = collect_ctor_call_nodes(entity.node)
            module_bindings = context.module_bindings.get(module or "")
            for call, fqn in resolved_sink_calls(
                entity.node, _METHOD_SINKS, alias_map, module or "", module_bindings=module_bindings
            ):
                is_archive = fqn in _ARCHIVE_METHOD_SINKS
                if is_archive and _has_safe_extraction_filter(call):
                    continue
                ctor = receiver_ctor_call(call, ctor_nodes)
                if ctor is None:
                    continue  # no resolvable construction site (v1 scope)
                worst = worst_arg_taint(ctor, qualname, context)
                if worst is None or worst not in RAW_ZONE:
                    continue
                line = call.lineno
                if is_archive:
                    message = (
                        f"{qualname}: {worst.value} (untrusted) archive opened at line {ctor.lineno} "
                        f"reaches the archive extraction (Zip Slip) sink {fqn}() at line {line}"
                    )
                else:
                    message = (
                        f"{qualname}: {worst.value} (untrusted) data reaches the path-traversal sink "
                        f"{fqn}() at line {line} via a Path constructed at line {ctor.lineno}"
                    )
                # Shared constructor — identical wlfp2 discriminator shape as the base
                # loop, keyed on the METHOD call + the resolved sink FQN. The FQN
                # differs from the constructor sink's ("pathlib.Path.read_text" vs
                # "pathlib.Path"), so the chained form's co-located ctor and method
                # findings never collide.
                findings.append(
                    build_sink_finding(
                        rule_id=self.rule_id,
                        entity=entity,
                        qualname=qualname,
                        call=call,
                        dotted=fqn,
                        severity=severity,
                        tier=tier,
                        worst=worst,
                        sink_label=self.sink_label,
                        message=message,
                    )
                )
        return findings
