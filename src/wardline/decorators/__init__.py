"""wardline.decorators — Decorator library for wardline annotations."""

from wardline.decorators.access import privileged_operation, requires_identity
from wardline.decorators.authority import (
    external_boundary,
    integral_construction,
    integral_read,
    integral_writer,
    validates_external,
    validates_semantic,
    validates_shape,
)
from wardline.decorators.boundaries import data_flow, tier_transition, trust_boundary
from wardline.decorators.concurrency import not_reentrant, ordered_after, thread_safe
from wardline.decorators.determinism import deterministic, time_dependent
from wardline.decorators.integrity import integrity_critical
from wardline.decorators.lifecycle import deprecated_by, feature_gated, test_only
from wardline.decorators.operations import (
    atomic,
    compensatable,
    emits_or_explains,
    exception_boundary,
    fail_closed,
    fail_open,
    idempotent,
    must_propagate,
    preserve_cause,
)
from wardline.decorators.plugin import system_plugin
from wardline.decorators.provenance import int_data
from wardline.decorators.restoration import restoration_boundary
from wardline.decorators.safety import parse_at_init
from wardline.decorators.schema import all_fields_mapped, output_schema, schema_default
from wardline.decorators.secrets import handles_secrets
from wardline.decorators.sensitivity import (
    declassifies,
    handles_classified,
    handles_pii,
)

__all__ = [
    "all_fields_mapped",
    "atomic",
    "integrity_critical",
    "integral_writer",
    "integral_construction",
    "compensatable",
    "data_flow",
    "declassifies",
    "deprecated_by",
    "deterministic",
    "emits_or_explains",
    "exception_boundary",
    "external_boundary",
    "fail_closed",
    "fail_open",
    "feature_gated",
    "handles_classified",
    "handles_pii",
    "handles_secrets",
    "idempotent",
    "int_data",
    "must_propagate",
    "not_reentrant",
    "ordered_after",
    "output_schema",
    "parse_at_init",
    "preserve_cause",
    "privileged_operation",
    "requires_identity",
    "restoration_boundary",
    "schema_default",
    "system_plugin",
    "test_only",
    "thread_safe",
    "time_dependent",
    "integral_read",
    "tier_transition",
    "trust_boundary",
    "validates_external",
    "validates_semantic",
    "validates_shape",
]
