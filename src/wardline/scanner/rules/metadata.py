# src/wardline/scanner/rules/metadata.py
"""``RuleMetadata`` — the per-rule descriptor (id, base severity, kind, docs).

Carried by every rule and exported by SP2d's NG-25 vocabulary descriptor.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from wardline.core.finding import Kind, Maturity, Severity


@dataclass(frozen=True, slots=True)
class RuleMetadata:
    rule_id: str
    base_severity: Severity
    kind: Kind
    description: str
    examples_violation: tuple[str, ...] = field(default_factory=tuple)
    examples_clean: tuple[str, ...] = field(default_factory=tuple)
    maturity: Maturity = Maturity.STABLE
    # True iff the rule can emit >1 finding for one (rule_id, qualname) — i.e. it loops
    # over handlers / calls / decorators / returns within one entity. Such a rule MUST
    # carry a source-derived entity-relative discriminator in ``taint_path`` (a col span
    # or PY-WL-114's ordinal), since ``line_start`` no longer separates co-located
    # findings (wlfp2, wardline-8654423823). A singleton (<=1 finding per qualname)
    # may use the line-independent source-body discriminator so a different body
    # or signature under the same qualname cannot inherit a stale suppression. Default is the
    # conservative SINGLETON; the ``test_discriminator_shape`` source-AST lint enforces
    # that multi_emit rules do not use singleton discriminators.
    multi_emit: bool = False
