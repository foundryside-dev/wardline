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
