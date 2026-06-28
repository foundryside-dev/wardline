"""Pack-bridge: bind a third-party project's own ``@trust_boundary`` vocabulary to wardline.

Some projects already annotate their external-data boundaries with their OWN decorator
rather than wardline's. This fixture demonstrates the generic pack-bridge: a fictional
``acme.security.trust_boundary`` — a metadata-only passthrough
``@trust_boundary(tier=3, source_param="<param>", ...)`` whose contract is exactly
"untrusted input arrives on ``source_param``; validated output leaves". wardline does
not read that foreign vocabulary, so a scan of such a project recognizes ZERO trust
boundaries and the ``--fail-on`` gate is inert (Part A flags this). A pack lets wardline
USE the project's existing annotations instead of asking it to re-annotate in wardline's
vocabulary.

The mapping is a clean semantic match to wardline's validating-boundary seed
(``_seed_boundary`` shape): a ``@trust_boundary`` function's arguments are EXTERNAL_RAW
(untrusted) and its declared return is ASSURED (validated). With that seed, wardline:
  * recognizes every ``@trust_boundary`` function as an anchored external-data boundary
    (the scan stops being inert), and
  * fires when such a boundary actually RETURNS raw data (a validator that doesn't
    validate) or when its untrusted argument reaches a dangerous sink unsanitized.

The third-party ``tier`` / ``source`` / ``source_param`` / ``invariant`` kwargs are not
trust LEVELS, so the BoundaryType declares no ``level_args`` and the matcher ignores
them (it only reads declared level args) — the key property a pack bridging a foreign
vocabulary relies on.

INSTALL (consumer side): place a module like this on the import path and either add
``packs = ["<module>"]`` under ``[wardline]`` in ``weft.toml`` or pass
``wardline scan --trust-pack <module>``. The pack imports only wardline's public grammar
surface; it executes no third-party code.
"""

from __future__ import annotations

from wardline.core.taints import TaintState
from wardline.scanner.grammar import BoundaryType, default_grammar
from wardline.scanner.taint.provider import FunctionTaint

THIRDPARTY_TRUST_BOUNDARY = BoundaryType(
    canonical_name="trust_boundary",
    module_prefix="acme.security.trust_boundary",
    group=1,
    # tier/source/source_param/invariant are NOT trust levels — read nothing from them.
    level_args=(),
    # Validating-boundary seed: untrusted args in, validated (ASSURED) result out.
    seed=lambda _levels: FunctionTaint(TaintState.EXTERNAL_RAW, TaintState.ASSURED),
    builtin=False,
)

GRAMMAR = default_grammar().extend(boundary_types=(THIRDPARTY_TRUST_BOUNDARY,))
