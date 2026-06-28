"""Pack-bridge: bind elspeth's ``@trust_boundary`` vocabulary to wardline's grammar.

elspeth annotates its external-data boundaries with its OWN decorator
``elspeth.contracts.trust_boundary.trust_boundary`` — a metadata-only passthrough
``@trust_boundary(tier=3, source_param="<param>", ...)`` whose contract is exactly
"untrusted input arrives on ``source_param``; validated output leaves". wardline does
not read that vocabulary, so an elspeth scan recognizes ZERO trust boundaries and the
``--fail-on`` gate is inert (Part A flags this). elspeth already has ~25 such
annotations — this pack lets wardline USE them instead of asking elspeth to re-annotate
in wardline's vocabulary.

The mapping is a clean semantic match to wardline's validating-boundary seed
(``_seed_boundary`` shape): a ``@trust_boundary`` function's arguments are EXTERNAL_RAW
(untrusted) and its declared return is ASSURED (validated). With that seed, wardline:
  * recognizes every ``@trust_boundary`` function as an anchored external-data boundary
    (the scan stops being inert), and
  * fires when such a boundary actually RETURNS raw data (a validator that doesn't
    validate) or when its untrusted argument reaches a dangerous sink unsanitized.

elspeth's own ``tier`` / ``source`` / ``source_param`` / ``invariant`` kwargs are not
trust LEVELS, so the BoundaryType declares no ``level_args`` and the matcher ignores
them (it only reads declared level args).

INSTALL (elspeth side): place this module on the import path and either add
``packs = ["elspeth_trust_boundary_pack"]`` under ``[wardline]`` in ``weft.toml`` or
pass ``wardline scan --trust-pack elspeth_trust_boundary_pack``. The pack imports only
wardline's public grammar surface; it executes no elspeth code.
"""

from __future__ import annotations

from wardline.core.taints import TaintState
from wardline.scanner.grammar import BoundaryType, default_grammar
from wardline.scanner.taint.provider import FunctionTaint

ELSPETH_TRUST_BOUNDARY = BoundaryType(
    canonical_name="trust_boundary",
    module_prefix="elspeth.contracts.trust_boundary",
    group=1,
    # tier/source/source_param/invariant are NOT trust levels — read nothing from them.
    level_args=(),
    # Validating-boundary seed: untrusted args in, validated (ASSURED) result out.
    seed=lambda _levels: FunctionTaint(TaintState.EXTERNAL_RAW, TaintState.ASSURED),
    builtin=False,
)

GRAMMAR = default_grammar().extend(boundary_types=(ELSPETH_TRUST_BOUNDARY,))
