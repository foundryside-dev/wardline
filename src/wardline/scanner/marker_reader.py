# src/wardline/scanner/marker_reader.py
"""The ONE marker-reading grammar (engine floor, declaration-surface-v2 P9).

Every consumer of a trust-marker AST — the L1 seeding provider AND every
validation rule (PY-WL-110, PY-WL-114, PY-WL-130, the S2+ declaration
validators) — reads through these primitives, so a rule can never recognise or
read a marker differently than seeding does (the recogniser-agreement property,
wardline-09c09f14df). Fail-closed everywhere: a value this module cannot read is
``None``, never a guess.

Reading a LEVEL value has exactly three outcomes and each names its channel once
(design spec rev 6 §4.2.1). A bare ``Name`` satisfying P3 form 5 — a BUILTIN
marker, a reference site that is a ``def``/``async def`` DIRECTLY in the module
body, exactly one qualifying same-file module-scope binding, and that binding
LEXICALLY PRECEDING the decorated ``def`` in source order — RESOLVES; it is
an ordinary DRY refactor to a module constant, not a hole. A value that stays
unreadable is NEVER silence: on a builtin it takes the
``WLN-ENGINE-UNREADABLE-MARKER-VALUE`` FACT (``Severity.NONE``), and on a custom
``BoundaryType`` it keeps the released ``WLN-ENGINE-UNPROVABLE-BOUNDARY`` channel
with an ``UNKNOWN_RAW`` seed — one unreadable value takes exactly one channel,
never both. A token that is READ and then rejected by the ``allowed`` check stays
PY-WL-114's DEFECT and takes NO FACT.

Being asked to resolve a bare ``Name`` in a BUILTIN marker's LEVEL slot with NO
census present for the module at all is a PLUMBING DEFECT, not an input
condition: this module RAISES rather than returning a quiet ``None``. The raise
is BUILTIN-ONLY — form 5 is builtin-only, so on a custom ``BoundaryType`` a bare
``Name`` is an ordinary unreadable and no census could change that verdict. An
absent census and an empty one are different inputs — an empty census is an
ordinary unreadable.

``call_shape_offences`` is the single authority on "this marker call's SHAPE is
malformed": the provider drops the seed exactly when it returns offences, and
PY-WL-130 emits exactly one DEFECT per offence — agreement by construction.

Imports only ``core`` (acyclic floor): the provider and the rules both import
THIS; neither reaches into the other.
"""

from __future__ import annotations

import ast
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum

from wardline.core.registry import REGISTRY, MarkerCallForm
from wardline.core.taints import TaintState

VOCAB_PREFIX = "wardline.decorators"
WEFT_MARKERS_PREFIX = "weft_markers"
_TAINTSTATE_FQN = "wardline.core.taints.TaintState"
_VOCAB_PREFIXES: tuple[str, ...] = (VOCAB_PREFIX, WEFT_MARKERS_PREFIX)

# The top-level import roots of every BUILTIN marker module — the set
# ``shadowed_builtin_roots`` intersects, and therefore the set that decides which roots
# get shadow FAIL-CLOSED matching at all. A ``weft_markers`` boundary type has
# module_prefix ``weft_markers`` (root ``weft_markers``); a ``wardline.decorators`` one
# has root ``wardline``.
#
# Listed from the two prefix constants above rather than derived from
# ``BUILTIN_BOUNDARY_TYPES``, because this module is the ENGINE FLOOR and imports only
# ``core`` (see the module docstring), whereas ``scanner.boundary_types`` pulls in
# ``scanner.taint.provider`` — the package that holds this module's own consumer.
#
# THAT PLACEMENT COSTS A GUARD, AND THE GUARD IS REPLACED RATHER THAN DROPPED. The
# derivation this replaced existed so that adding a builtin marker root AUTOMATICALLY
# participated in shadow fail-closed matching. Nothing in ``boundary_types`` restores
# that: its REGISTRY consistency tripwire constrains ``canonical_name``, ``group``,
# ``kwargs`` and ``arg_kinds`` ONLY — ``module_prefix`` is entirely unconstrained by it,
# so a third builtin root would pass that tripwire while silently missing from this set,
# ``shadowed_builtin_roots`` would never report it, and a project shadowing that root
# could spoof ``@trusted`` past a green gate. The replacement guard is an equality PIN in
# tests/unit/scanner/test_marker_reader_agreement.py
# (``test_builtin_marker_roots_covers_every_builtin_boundary_type_root``), which lives on
# the TEST side precisely because a test may import ``boundary_types`` and this module may
# not. A new builtin root must be added HERE too, or that test reds.
BUILTIN_MARKER_ROOTS: frozenset[str] = frozenset({VOCAB_PREFIX.split(".")[0], WEFT_MARKERS_PREFIX.split(".")[0]})


def dotted_name(node: ast.expr) -> str | None:
    """Reconstruct a dotted name (``a.b.c``) from a Name/Attribute chain."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = dotted_name(node.value)
        return f"{base}.{node.attr}" if base is not None else None
    return None


def resolve_dotted_fqn(
    node: ast.expr,
    alias_map: Mapping[str, str],
    *,
    census: ModuleCensus | None = None,
    resolution_site: ast.AST | None = None,
) -> str | None:
    """Reconstruct ``node``'s dotted name and rewrite its visible imported head.

    When a built census and resolution site are present, the module-wide alias
    map is accepted only if its import remains the last possible binding before
    that site. This prevents a stale import entry surviving a local rebind.

    Returns None for non-name nodes (calls, subscripts, literals).
    """
    dotted = dotted_name(node)
    if dotted is None:
        return None
    head, _, rest = dotted.partition(".")
    head_fqn = alias_map.get(head)
    if head_fqn is None:
        head_fqn = head
    elif census is not None and census.binding_lines is not None and census.alias_lines is not None:
        # ``alias_map`` is a module-wide import inventory, not a source-order
        # environment. Refuse its rewrite unless the last possible module binding
        # before this use is the direct import that supplied the alias. A later
        # import also makes the map's final target unusable for an earlier site.
        line = getattr(resolution_site, "lineno", None)
        alias_lines = census.alias_lines.get(head, ())
        binding_lines = census.binding_lines.get(head, ())
        if not alias_lines:
            # A caller may supply a pre-built alias map with no corresponding
            # source import in this tree (the public reader/unit-test contract).
            # There is no source-order evidence to contradict that environment.
            pass
        elif line is None or any(import_line >= line for import_line in alias_lines):
            head_fqn = head
        else:
            # A materialised star import contributes alias lines without named
            # occurrences, so both populations participate in the last-bind test.
            prior = tuple(binding_line for binding_line in (*binding_lines, *alias_lines) if binding_line < line)
            if not prior or max(prior) not in alias_lines:
                head_fqn = head
    return f"{head_fqn}.{rest}" if rest else head_fqn


def resolve_decorator_fqn(
    deco: ast.expr,
    alias_map: Mapping[str, str],
    *,
    census: ModuleCensus | None = None,
    reference_site: ast.stmt | None = None,
) -> str | None:
    """Resolve a decorator node to a fully-qualified name via the alias map.

    Strips a call wrapper (``@d(...)`` -> ``d``) then resolves the dotted name.
    """
    func = deco.func if isinstance(deco, ast.Call) else deco
    return resolve_dotted_fqn(func, alias_map, census=census, resolution_site=reference_site)


def alias_map_for_qualname(
    qualname: str,
    alias_maps: Mapping[str, Mapping[str, str]],
) -> Mapping[str, str]:
    """Alias map for the longest module prefix that owns *qualname*."""
    module = next(
        (
            name
            for name in sorted(alias_maps, key=len, reverse=True)
            if qualname == name or qualname.startswith(name + ".")
        ),
        None,
    )
    return alias_maps.get(module, {}) if module is not None else {}


@dataclass(frozen=True, slots=True)
class KeywordExtraction:
    """Static keyword values plus extraction defects, in deterministic order."""

    items: tuple[tuple[str, ast.expr], ...]
    offences: tuple[tuple[str, str], ...]


def extract_keywords(deco: ast.expr) -> KeywordExtraction:
    """Extract direct and literal-``**`` keywords without executing target code.

    One literal dict is normalized with Python's insertion-order/last-value
    semantics before its items are appended. A dynamic or nested expansion is
    wholly unreadable; non-string literal keys are invalid but do not cause the
    reader to guess at runtime coercion.
    """
    if not isinstance(deco, ast.Call):
        return KeywordExtraction((), ())
    items: list[tuple[str, ast.expr]] = []
    offences: list[tuple[str, str]] = []
    for kw in deco.keywords:
        if kw.arg is not None:
            items.append((kw.arg, kw.value))
            continue
        if not isinstance(kw.value, ast.Dict) or any(key is None for key in kw.value.keys):
            offences.append(("<**splat>", "unreadable_splat"))
            continue
        order: list[str] = []
        final_values: dict[str, ast.expr] = {}
        for key, value in zip(kw.value.keys, kw.value.values, strict=True):
            if not isinstance(key, ast.Constant):
                # A COMPUTED key ('lev' + 'el', an f-string, a Name) is not a literal
                # key and is frequently valid at runtime — verified 2026-08-09:
                # trusted(**{'lev' + 'el': 'ASSURED'}) executes cleanly. Wardline
                # simply cannot READ it, so it belongs to the analyzer-limitation
                # channel, never the proved-runtime-invalid one. Routing it here also
                # makes it suppress missing_kwarg for free (the guard below keys on
                # unreadable_splat) — a computed key MAY supply the required name.
                offences.append(("<**splat>", "unreadable_splat"))
                continue
            if not isinstance(key.value, str):
                # A non-string CONSTANT key is a PROVED failure — verified 2026-08-09:
                # trusted(**{1: 'ASSURED'}) raises TypeError: keywords must be strings.
                offences.append(("<**splat>", "invalid_splat_key"))
                continue
            if key.value not in final_values:
                order.append(key.value)
            final_values[key.value] = value
        items.extend((name, final_values[name]) for name in order)
    return KeywordExtraction(tuple(items), tuple(offences))


@dataclass(frozen=True, slots=True)
class CensusBinding:
    """One module-scope name's census entry: a token, or why it is unreadable.

    Exactly one of ``token`` / ``unreadable_reason`` is set. ``line`` is the
    binding's line, which is what makes form 5's lexical-precedence clause
    decidable. ``unreadable_reason`` is diagnostic message text and is NEVER
    fingerprint input.
    """

    token: str | None
    unreadable_reason: str | None
    line: int


@dataclass(frozen=True, slots=True)
class ModuleCensus:
    """One module's form-5 census: bindings, star poison, eligible reference sites.

    ``reference_sites`` holds the ``def`` / ``async def`` statements that are
    DIRECT elements of ``Module.body``, by NODE IDENTITY — module source is
    parsed exactly once and both readers receive the same node objects, and no
    qualname or column-offset proxy can answer this test (a conditionally-defined
    module-level ``def`` has the same qualname as an unconditional one). Built
    once per module in the parse loop; never rebuilt, and no rule computes one.
    ``binding_lines`` and ``alias_lines`` are the source-order evidence shared by
    marker and level-head resolution so imported names cannot outlive a rebind.
    """

    values: Mapping[str, CensusBinding]
    poisoned: bool
    reference_sites: frozenset[ast.stmt]
    # Source-order evidence for deciding whether an import alias is still the
    # visible binding at a decorator or level expression. ``None`` is retained as
    # an explicit compatibility sentinel for hand-built censuses in reader unit
    # tests; the production builder always supplies both mappings.
    binding_lines: Mapping[str, tuple[int, ...]] | None = None
    alias_lines: Mapping[str, tuple[int, ...]] | None = None


def level_token(
    value: ast.expr,
    alias_map: Mapping[str, str],
    *,
    census: ModuleCensus | None,
    reference_site: ast.stmt | None,
    shadowed_roots: frozenset[str],
    builtin: bool,
) -> str | None:
    """Extract a TaintState name token from a keyword-argument value node.

    STRICT, and the ONLY reader of a LEVEL value. Three value shapes read:

    * a string literal (``"ASSURED"``);
    * P3 form 2 — an attribute access whose receiver ALIAS-RESOLVES to the exact
      export ``wardline.core.taints.TaintState`` (so ``TaintState.ASSURED`` and an
      aliased ``T.ASSURED`` both read, while a coincidental ``cfg.ASSURED`` or a
      re-exported ``shim.TaintState.ASSURED`` do NOT). The receiver is refused
      outright when its resolved FQN's FIRST dotted component is in
      ``shadowed_roots``: the scanned project shadows that import root, so the
      name may bind to project-controlled code (spec §4.2.1's pre-existing gap,
      closed here for a form-2 value written DIRECTLY in the LEVEL slot). Form 5's
      own right-hand-side shadowed-root refusal is applied at the CENSUS BUILD and
      is never re-derived here;
    * P3 form 5 — a bare ``ast.Name`` resolved through the per-module census.

    Form 5 resolves under FIVE required conditions and under nothing else:

    1. ``builtin`` is True (form 5 is builtin-only, spec :119);
    2. ``census`` is not ``None``;
    3. ``census`` is not ``poisoned`` (no unresolved star import in the module);
    4. ``reference_site`` is in ``census.reference_sites`` (a ``def`` / ``async
       def`` that is a DIRECT element of ``Module.body``), and ``census.values``
       holds an entry for that name whose ``token`` is set;
    5. LEXICAL PRECEDENCE — that entry's ``line`` is STRICTLY less than
       ``reference_site.lineno``. The anchor is the reference-site statement's OWN
       ``lineno``, which for a decorated ``FunctionDef`` / ``AsyncFunctionDef`` is
       the ``def`` line, DECORATORS EXCLUDED (measured at CPython 3.13.1; the AST
       has behaved this way since 3.8). A qualifying module-scope binding that
       precedes the ``def`` also precedes its decorators, so the choice between
       the two anchors moves no verdict; the comparison is strict because no
       module-scope binding can share the ``def``'s own line. Without this
       conjunct a binding placed AFTER the decorated ``def`` would RESOLVE — a
       minted seed where the specification requires UNREADABLE, the seed-minting
       direction and the dangerous one (spec :42, :111, :113, :133).

    Every other bare ``Name`` is unreadable. ABSENT and EMPTY censuses are
    DIFFERENT inputs: a census that is present but holds no qualifying entry — or
    a ``reference_site`` outside ``census.reference_sites``, or an entry that does
    not lexically precede it — is an ordinary unreadable and returns ``None``.
    Being handed a bare ``Name`` in a LEVEL slot on a BUILTIN marker with
    ``census=None`` is a PLUMBING DEFECT and raises :class:`ValueError`. **The
    raise is BUILTIN-ONLY:** on a custom ``BoundaryType`` a bare ``Name`` is an
    ordinary unreadable ``None``, because form 5 cannot resolve there at all and
    no census could change that verdict — raising would break the released
    ``WLN-ENGINE-UNPROVABLE-BOUNDARY`` + ``UNKNOWN_RAW`` contract for nothing.
    This reader tests only what it was HANDED, never whether some other component
    ran, so a non-``Name`` value reads normally with ``census=None``.

    Anything else (a call, an f-string, a subscript, a non-``TaintState``
    attribute) is not statically readable -> ``None`` (fail-closed).
    """
    if isinstance(value, ast.Constant) and isinstance(value.value, str):
        return value.value
    if isinstance(value, ast.Attribute):
        receiver = resolve_dotted_fqn(
            value.value,
            alias_map,
            census=census,
            resolution_site=reference_site or value,
        )
        if receiver is None:
            return None
        if receiver.split(".")[0] in shadowed_roots:
            return None
        if receiver == _TAINTSTATE_FQN:
            return value.attr
        return None
    if isinstance(value, ast.Name):
        # Conjunct 1 FIRST, so the builtin-only raise below cannot reach a custom
        # BoundaryType (form 5 is builtin-only; spec :119).
        if not builtin:
            return None
        if census is None:
            raise ValueError(
                "form-5 level reference read with no ModuleCensus for the module "
                f"(name={value.id!r}); a builtin marker's bare-Name LEVEL value "
                "requires the per-module census — this is a plumbing defect"
            )
        if census.poisoned:
            return None
        if reference_site is None or reference_site not in census.reference_sites:
            return None
        binding = census.values.get(value.id)
        if binding is None or binding.token is None:
            return None
        if binding.line >= reference_site.lineno:
            return None
        return binding.token
    return None


class LevelVerdict(Enum):
    """How ONE declared LEVEL argument read. Each verdict names its channel once."""

    RESOLVED = "resolved"  # a token was read and passed the ``allowed`` check
    REJECTED = "rejected"  # a token was READ, then rejected — PY-WL-114's DEFECT, never a FACT
    UNREADABLE = "unreadable"  # nothing was read — the residual channel


@dataclass(frozen=True, slots=True)
class LevelRead:
    """The discriminated result the old bare ``TaintState | None`` collapsed.

    ``unreadable_value`` is the ``(argument name, ast.unparse(value))`` pair the
    residual FACT is built from. It is set ONLY when ``verdict`` is
    ``UNREADABLE`` AND the marker is builtin — that is the mechanism that keeps
    the residual channel builtin-only. The text this carrier holds is RAW —
    un-normalised and untruncated. NFC normalisation and the 200-character
    truncation belong to the EMISSION site, which derives ONE key from this raw
    text and renders the fingerprint's fourth part, the diagnostic message and
    ``properties["value"]`` from that same key: one text, not two. This reader
    makes no promise about the message keeping the full text.
    """

    verdict: LevelVerdict
    level: TaintState | None
    unreadable_value: tuple[str, str] | None


def read_level(
    deco: ast.expr,
    arg: str,
    *,
    declared: frozenset[str],
    allowed: frozenset[TaintState],
    default: TaintState | None,
    alias_map: Mapping[str, str],
    census: ModuleCensus | None,
    reference_site: ast.stmt | None,
    shadowed_roots: frozenset[str],
    builtin: bool,
) -> LevelRead:
    """Read one declared level; malformed/unreadable values fail closed.

    SHAPE IS DECIDED FIRST AND SHORT-CIRCUITS: builtins have already passed
    ``call_shape_offences``, so a shape-malformed marker drops its seed there and
    its LEVEL value is never read — such a site takes PY-WL-130 and never also
    the residual FACT. Custom level-bearing packs retain the released reader
    contract: POSITIONAL ARGUMENTS, undeclared metadata, extraction defects, or
    duplicate values make the declaration unreadable — the positional guard is
    the CUSTOM side's alone, because ``call_shape_offences`` is builtin-only and
    a custom pack reaches no shape gate — and on the custom side ``REJECTED`` and
    ``UNREADABLE`` alike take the released unprovable path. A zero-level custom
    marker never calls this reader and therefore may retain metadata.
    """
    if arg not in declared:
        raise ValueError(f"level argument {arg!r} is not declared")

    def _unreadable(value: ast.expr | None) -> LevelRead:
        # The residual pair is builtin-only, and an ABSENT argument has no value
        # node to unparse — so neither ever reaches the FACT.
        pair = (arg, ast.unparse(value)) if (builtin and value is not None) else None
        return LevelRead(LevelVerdict.UNREADABLE, None, pair)

    def _defaulted() -> LevelRead:
        # ``default is None`` means the argument is REQUIRED (LevelArg's released
        # contract): absent-and-required is unreadable, exactly as today.
        return LevelRead(LevelVerdict.RESOLVED, default, None) if default is not None else _unreadable(None)

    if not isinstance(deco, ast.Call):
        return _defaulted()
    if deco.args:
        # The RELEASED contract, preserved verbatim (decorator_provider.py:165-166):
        # a positional argument makes the declaration unreadable. Builtins take
        # PY-WL-130 at the shape gate and never reach here, but registry call-form
        # validation is BUILTIN-ONLY by design (spec :105; Global Constraints' hard
        # custom-pack gate), so for a custom ``BoundaryType`` this line IS the whole
        # positional guard — delete it and a pack declaring a DEFAULTED ``LevelArg``
        # takes ``_defaulted()`` and seeds TRUSTED with no diagnostic on any channel.
        # Payload is None: positional is a SHAPE problem and never mints a residual
        # pair. Covers ``*ARGS`` too — ``deco.args`` holds the ``Starred`` node.
        return _unreadable(None)
    extracted = extract_keywords(deco)
    if extracted.offences:
        return _unreadable(None)
    if any(name not in declared for name, _value in extracted.items):
        return _unreadable(None)
    values = [value for name, value in extracted.items if name == arg]
    if not values:
        return _defaulted()
    if len(values) != 1:
        return _unreadable(values[0])
    token = level_token(
        values[0],
        alias_map,
        census=census,
        reference_site=reference_site,
        shadowed_roots=shadowed_roots,
        builtin=builtin,
    )
    if token is None:
        return _unreadable(values[0])
    try:
        level = TaintState(token)
    except ValueError:
        # READ, then rejected: PY-WL-114's DEFECT owns this. No residual pair.
        return LevelRead(LevelVerdict.REJECTED, None, None)
    if level not in allowed:
        return LevelRead(LevelVerdict.REJECTED, None, None)
    return LevelRead(LevelVerdict.RESOLVED, level, None)


def call_shape_offences(
    deco: ast.expr,
    *,
    call_form: MarkerCallForm,
    declared: frozenset[str],
    required: frozenset[str],
) -> tuple[tuple[str, str], ...]:
    """Every statically-provable malformation of one marker call's SHAPE.

    Returns ``(offender, reason)`` pairs in a pinned canonical phase order:
    call-form, positional, extraction offences (source order), keyword
    classification/duplicate events (source order), then missing names (sorted).
    Reasons are
    ``call_not_allowed`` | ``call_required`` | ``positional_args`` |
    ``undeclared_kwarg`` | ``invalid_splat_key`` | ``unreadable_splat`` |
    ``duplicate_kwarg`` | ``missing_kwarg``. The vocabulary is exactly the eight
    reasons of spec §4.2 — unchanged. Two of them cover a PROVED-invalid and an
    UNPROVABLE form under one name, split by OFFENDER token:
    ``positional_args`` is ``<positional>`` (a plain positional argument) or
    ``<*args>`` (a ``*`` expansion, which may bind zero arguments), and
    ``unreadable_splat`` covers both a dynamic/nested ``**`` and a literal dict
    with a COMPUTED (non-``ast.Constant``) key. ``invalid_splat_key`` is
    narrowed to a non-string ``ast.Constant`` key — the only splat-key form that
    proves ``TypeError: keywords must be strings``. Value problems are NOT shape
    problems: this validator looks at no value at all, so ``level=CFG``,
    ``level=get_level()`` and ``level='ASURED'`` alike return no offence here.
    Under design spec rev 6 those three then route DIFFERENTLY from one another —
    ``level=CFG`` RESOLVES when P3 form 5 is satisfied in full, a value that stays
    unreadable takes the ``WLN-ENGINE-UNREADABLE-MARKER-VALUE`` FACT rather than
    silence, and a readable-but-invalid token stays PY-WL-114's DEFECT — but none
    of the three is a shape offence.

    SHAPE IS DECIDED FIRST AND SHORT-CIRCUITS. The provider runs this validator
    BEFORE the levels loop, so a marker whose call shape is malformed drops its
    seed here and its LEVEL value is never read: such a site takes PY-WL-130 and
    NEVER also the residual FACT. That is not an exception carved out of "every
    unreadable builtin LEVEL value takes the FACT" — the value was never a
    question, the marker having been rejected on shape. Do NOT describe this
    ordering as strictly louder or as losing nothing: PY-WL-130 is a
    ``Kind.DEFECT`` and therefore IS suppressible, so a waived PY-WL-130 leaves
    that site with no signal at all, no FACT having been emitted. The ordering is
    justified on noise avoidance plus the shipped SECURE DEFAULT — not on either
    channel dominating the other. Under ``trust_suppressions=False``, ``run_scan``
    rebuilds ``gate_population_findings`` with an empty ``Baseline``, an empty
    ``WaiverSet`` and ``judged=None``, so a waived or baselined PY-WL-130 still
    trips ``--fail-on``; the site loses its signal only under an explicit
    ``--trust-suppressions`` operator decision (spec rev 9 §4.2.1).

    The drop-coverage matrix (tests/grammar/test_drop_coverage_matrix.py) pins
    the full partition.
    """
    if not isinstance(deco, ast.Call):
        if call_form is MarkerCallForm.CALL_ONLY:
            return (("<bare>", "call_required"),)
        return ()
    if call_form is MarkerCallForm.BARE_ONLY:
        # Return before inspecting args so @external_boundary() and
        # @external_boundary(**{}) are rejected for the same root reason.
        return (("<call>", "call_not_allowed"),)
    out: list[tuple[str, str]] = []
    # Phase 2 (positional). Split by offender so the two forms are distinguishable in
    # properties and fingerprints while the pinned REASON vocabulary is untouched.
    if any(not isinstance(a, ast.Starred) for a in deco.args):
        out.append(("<positional>", "positional_args"))
    if any(isinstance(a, ast.Starred) for a in deco.args):
        # ``*ARGS`` may bind ZERO arguments — verified 2026-08-09: trusted(*()) executes
        # cleanly and returns the decorator. So this is NOT a proved runtime failure;
        # the argument list is simply outside the keyword-only declaration grammar and
        # Wardline cannot prove what it supplies. Emitted AFTER the plain-positional
        # offence so the canonical phase order stays deterministic.
        out.append(("<*args>", "positional_args"))
    extracted = extract_keywords(deco)
    out.extend(extracted.offences)
    supplied: set[str] = set()
    for name, _value in extracted.items:
        if name not in declared:
            out.append((name, "undeclared_kwarg"))
            continue
        if name in supplied:
            # Emit at the second occurrence; later repeats emit again in source
            # order and receive distinct offence ordinals.
            out.append((name, "duplicate_kwarg"))
        else:
            supplied.add(name)
    # Suppression must cover EVERY unreadable-splat-class offence: a dynamic mapping
    # OR a computed literal key may be exactly the required name. Both are
    # ``unreadable_splat`` by construction (see extract_keywords) — keep it that way.
    if not any(reason == "unreadable_splat" for _name, reason in out):
        for arg in sorted(required - supplied):
            out.append((arg, "missing_kwarg"))
    return tuple(out)


def is_builtin_decorator_fqn(fqn: str, canonical_name: str, module_prefix: str) -> bool:
    """Return whether *fqn* is one of the exact builtin decorator exports.

    The accepted export table is ROOT-SPECIFIC, not a uniform ``P.<name>`` +
    ``P.trust.<name>`` pair: ``wardline.decorators`` really does re-export from an
    implementation module (``wardline/decorators/__init__.py`` +
    ``wardline/decorators/trust.py``), so both spellings are genuine, while
    ``weft_markers`` ships a single ``__init__.py`` and has NO ``weft_markers.trust``
    submodule at all. Accepting the latter would recognise a GHOST export — a path
    that cannot resolve at runtime — as a real marker. Prefix + arbitrary-nested +
    final-segment paths (e.g. ``wardline.decorators.evil.trusted``) are rejected for
    builtins.
    """
    exports = {f"{module_prefix}.{canonical_name}"}
    if module_prefix == VOCAB_PREFIX:
        exports.add(f"{module_prefix}.trust.{canonical_name}")
    return fqn in exports


def unknown_vocabulary_marker(
    deco: ast.expr,
    alias_map: Mapping[str, str],
    shadowed_roots: frozenset[str],
    *,
    census: ModuleCensus | None = None,
    reference_site: ast.stmt | None = None,
) -> str | None:
    """The resolved FQN iff *deco* is vocabulary-rooted but not a recognised export.

    Vocabulary-rooted = the FQN sits strictly under ``wardline.decorators`` or
    ``weft_markers``. Exact known exports (the REGISTRY names) are excluded —
    those are recognised markers whose malformed CALLS are PY-WL-130's concern.
    Shadow-rejected roots are excluded (builtin matching is off wholesale under
    a shadow). This is the new-markers-old-wardline observability hook:
    ``@weft_markers.audit_record`` on a wardline that predates facets resolves
    here instead of vanishing. Known FN, by design: a name arriving via
    ``from weft_markers import *`` that is NOT a current REGISTRY key stays
    unresolved in the alias map (``vocabulary_star_exports`` maps only known
    names) and cannot be attributed to the vocabulary.
    """
    fqn = resolve_decorator_fqn(deco, alias_map, census=census, reference_site=reference_site)
    if fqn is None:
        return None
    if fqn.split(".")[0] in shadowed_roots:
        return None
    if not any(fqn.startswith(prefix + ".") for prefix in _VOCAB_PREFIXES):
        return None
    for name in REGISTRY:
        for prefix in _VOCAB_PREFIXES:
            if is_builtin_decorator_fqn(fqn, name, prefix):
                return None
    return fqn


def shadowed_builtin_roots(project_modules: frozenset[str]) -> frozenset[str]:
    """Return the builtin marker roots the scanned project SHADOWS.

    Builtin marker declarations must refer to the installed marker package, not a
    module supplied by the scanned project. A root is shadowed when the project
    itself defines a TOP-LEVEL module/package equal to that root (e.g. its own
    ``wardline`` or ``weft_markers`` package): Python import resolution can then
    bind ``wardline.decorators`` / ``weft_markers`` to attacker-controlled code, so
    builtin matching fails closed for markers under that root.

    Only the FIRST dotted component is compared, so an unrelated nested module such
    as ``app.wardline_helper`` or ``myweft.wardline`` does NOT trip a shadow.
    """
    project_roots = {module.split(".", 1)[0] for module in project_modules}
    return frozenset(project_roots & BUILTIN_MARKER_ROOTS)
