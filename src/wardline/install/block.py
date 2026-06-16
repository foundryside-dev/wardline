"""Render + idempotently inject the hash-fenced wardline instruction block.

The block lands in shared agent docs (``CLAUDE.md`` / ``AGENTS.md``) that may
also carry a co-resident sibling tool's managed block (filigree / legis /
loomweave). The injector therefore obeys the weft C-4 multi-owner managed-block
contract: it mutates only its own vendor-namespaced span, never lets a rewrite
cross a foreign-namespace fence, never reorders or relocates a foreign block,
canonicalises its own duplicates only when doing so cannot reach across a
foreign block (preserving + surfacing any duplicate beyond one), and writes
atomically with a refuse-to-empty guard so a crash can never truncate the shared
doc.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import stat
import tempfile
from pathlib import Path

from wardline.core.errors import WardlineError
from wardline.core.safe_paths import safe_project_file

logger = logging.getLogger(__name__)

_BLOCK_VERSION = "1"

_BODY = (
    "This project uses **wardline** as its trust-boundary gate. Before handing "
    "back code that touches external input, run `wardline scan . --fail-on ERROR` "
    "(exit 0 = clean, 1 = gate tripped, 2 = wardline error) and fix findings at "
    "the boundary, not the sink. The full scan -> explain -> fix -> rescan loop "
    "and the baseline-vs-waiver discipline live in the `wardline-gate` skill and "
    "in `docs/agents.md`."
)

_OWN_NS = "wardline"
_END_MARKER = f"<!-- /{_OWN_NS}:instructions -->"
_WRITER_MARKER = f"<!-- {_OWN_NS}:last-writer:wardline install -->"

# A complete, well-formed wardline block (open .. close). Own-namespace only, so
# it can only ever match wardline's own spans (C-4 (b) own-namespace mutation).
# IGNORECASE so an uppercase-namespaced own duplicate (e.g. ``WARDLINE``) is still
# matched for canonicalisation, consistent with the case-insensitive namespace
# comparison used for boundary detection (C-4 (e)+(h)).
_FENCE_RE = re.compile(
    r"<!-- wardline:instructions:v\d+:[0-9a-f]+ -->.*?<!-- /wardline:instructions -->",
    re.DOTALL | re.IGNORECASE,
)

# Recognises ANY tool's instruction fence (open OR close, via the optional
# leading ``/``) and captures its vendor namespace. wardline uses it to bound its
# own rewrite at a *foreign* fence and never delete a co-resident sibling block
# in a shared CLAUDE.md / AGENTS.md. The namespace is compared case-insensitively
# (via ``.lower()``) so an uppercase-namespaced sibling (e.g. ``FILIGREE``) still
# registers as a boundary (C-4 (h)). The cross-tool multi-owner block contract
# lives in weft conventions.md (C-4).
_INSTR_FENCE_RE = re.compile(r"<!--\s*(?P<close>/?)(?P<ns>[A-Za-z0-9_-]+):instructions")


def _body_hash() -> str:
    return hashlib.sha256(_BODY.encode("utf-8")).hexdigest()[:8]


def render_block() -> str:
    return f"<!-- {_OWN_NS}:instructions:v{_BLOCK_VERSION}:{_body_hash()} -->\n{_WRITER_MARKER}\n{_BODY}\n{_END_MARKER}"


def _first_real_foreign_block_pos(content: str, search_from: int) -> int:
    """Index of the first *real* foreign block at/after *search_from*, else EOF.

    A real foreign block is a foreign-namespace OPEN fence that has a matching
    foreign CLOSE fence somewhere after it — i.e. genuine co-resident sibling
    content we must never delete or split. A *lone* foreign open (a marker quoted
    in prose or inside wardline's own body) and a stray foreign close are NOT
    boundaries: they are our own content, so a well-formed own block whose body
    happens to mention a sibling's marker is replaced in place rather than
    truncated at the quoted marker (C-4 (b)+(c)). Own-namespace fences are always
    absorbed, so duplicate / unclosed wardline blocks still collapse.

    Returns ``len(content)`` when no real foreign block follows (bound at EOF).
    The namespace match is case-insensitive (C-4 (h)).
    """
    fences = list(_INSTR_FENCE_RE.finditer(content, search_from))
    for i, m in enumerate(fences):
        ns = m.group("ns").lower()
        if ns == _OWN_NS or m.group("close"):
            continue
        # Foreign open: a boundary only if a matching foreign close follows it.
        if any(n.group("ns").lower() == ns and n.group("close") for n in fences[i + 1 :]):
            return m.start()
    return len(content)


def _first_own_open_fence_pos(content: str) -> int:
    """Index of wardline's *own* top-level open instruction fence, or -1 if none.

    A wardline open marker quoted *inside* a co-resident sibling block (a worked
    example, documentation) is textually identical to a real one, so a bare regex
    anchor would splice there and gut the sibling. This walks fences in document
    order, tracking the foreign block we are currently inside, and only returns a
    wardline open fence found at top level (not enclosed by an unclosed foreign
    block). An unclosed foreign block therefore shields any wardline marker
    beyond it: we decline to claim content we cannot prove is ours, and the
    caller falls back to an append (which deletes nothing).
    """
    inside_foreign: str | None = None
    for m in _INSTR_FENCE_RE.finditer(content):
        ns = m.group("ns").lower()
        is_close = bool(m.group("close"))
        if inside_foreign is not None:
            if is_close and ns == inside_foreign:
                inside_foreign = None
            continue
        if ns == _OWN_NS and not is_close:
            return m.start()
        if ns != _OWN_NS and not is_close:
            inside_foreign = ns
    return -1


def _canonicalise_tail(tail: str) -> tuple[str, bool]:
    """Collapse duplicate own blocks in *tail* that precede any real foreign block.

    Returns ``(cleaned_tail, foreign_shielded_dup)``. Own blocks before the first
    real foreign block are removed (own-duplicate canonicalisation, C-4 (e)).
    Everything from that foreign block onward is preserved verbatim — including
    any own duplicate beyond it, which foreign-safety forbids reaching across; the
    bool flags such a shielded duplicate so the caller can surface it.
    """
    foreign = _first_real_foreign_block_pos(tail, 0)
    head, rest = tail[:foreign], tail[foreign:]
    cleaned = _FENCE_RE.sub("", head)
    shielded_dup = _first_own_open_fence_pos(rest) != -1
    return cleaned + rest, shielded_dup


def _atomic_write_text(path: Path, content: str) -> None:
    """Write *content* to *path* atomically (temp + ``os.replace``), preserving mode.

    Refuse-to-empty guard (C-4 (g)): every caller always has non-empty content (a
    rendered block, or existing text plus a block), so an empty / whitespace-only
    payload can only be corruption or a logic bug — refuse loudly rather than
    rename an empty temp file over a populated CLAUDE.md / AGENTS.md. The
    write-temp-then-replace makes truncation structurally impossible: a crash
    leaves the prior file intact, never a partial shared agent doc.

    ``tempfile.mkstemp`` creates 0o600 files; without an explicit chmod the
    rename would leak that owner-only mode onto a user-visible file, so the
    destination's existing mode is preserved (or the process umask is respected
    for a new file).
    """
    if not content.strip():
        raise WardlineError(f"refusing to write empty content to {path}")
    existing_mode: int | None
    try:
        existing_mode = stat.S_IMODE(path.stat().st_mode)
    except FileNotFoundError:
        existing_mode = None
    fd, tmp = tempfile.mkstemp(dir=path.parent, suffix=".tmp", prefix=path.name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
        if existing_mode is not None:
            os.chmod(tmp, existing_mode)
        else:
            umask = os.umask(0)
            os.umask(umask)
            os.chmod(tmp, 0o666 & ~umask)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def inject_block(file_path: Path) -> str:
    """Create / append / replace the block, collapsing to one canonical block.

    Foreign-safe per the weft C-4 multi-owner managed-block contract: never
    deletes, reorders, or relocates a co-resident sibling tool's block, and never
    lets a rewrite span across a foreign-namespace fence. Returns
    created|updated|unchanged.
    """
    file_path = safe_project_file(file_path.parent, file_path, label=file_path.name)
    block = render_block()
    if not file_path.exists():
        _atomic_write_text(file_path, block + "\n")
        return "created"
    text = file_path.read_text(encoding="utf-8")
    start = _first_own_open_fence_pos(text)
    own_end = text.find(_END_MARKER, start) if start != -1 else -1

    if start == -1 or own_end == -1:
        # No own block we can claim — either none at all, an own open with no
        # close (so we cannot prove its extent), or an open marker shielded
        # inside an unclosed foreign block. Append a fresh block and preserve all
        # existing text verbatim (C-4 (d) append-on-missing-end). This is NOT
        # recovery-to-EOF: trailing user text after an unclosed own marker is
        # kept, never deleted.
        if block in text:
            # An identical current block already exists but is unreachable to the
            # claim logic (shielded inside an unclosed foreign block, whose own
            # close we must not invent). Appending another copy each run would
            # grow the file unboundedly across repeated hook invocations; decline
            # instead. Purely read-only, so foreign-safety is untouched.
            return "unchanged"
        sep = "" if text.endswith("\n") else "\n"
        _atomic_write_text(file_path, f"{text}{sep}\n{block}\n")
        return "updated"

    # An own block exists with a close marker. Bound the span we rewrite so it
    # never crosses a *real* foreign block (C-4 (c)). A foreign marker merely
    # quoted inside our own body is not a boundary (see
    # _first_real_foreign_block_pos) — that block is replaced in place.
    foreign = _first_real_foreign_block_pos(text, start)
    if own_end < foreign:
        # Well-formed own block, closing before any real foreign block: replace it
        # in place, then canonicalise duplicate own blocks in the tail up to (but
        # never across) the first real foreign block (C-4 (e)).
        bound = own_end + len(_END_MARKER)
        tail, shielded_dup = _canonicalise_tail(text[bound:])
        sep = ""
    else:
        # Bounded recovery (C-4 (c)): the own open is malformed, or its close lies
        # beyond a real foreign block (so a naive open..close match would swallow
        # the foreign block). Cut at the foreign block (or EOF) instead. Re-insert
        # the separating newline we may have eaten so our close marker is never
        # glued mid-line against a following foreign fence — keeping us
        # independent of whether a sibling's detector is line-anchored.
        bound = foreign
        tail = text[bound:]
        sep = "\n" if (bound < len(text) and not tail.startswith("\n")) else ""
        shielded_dup = _first_own_open_fence_pos(tail) != -1

    if shielded_dup:
        # A second own block survives beyond a foreign block because
        # canonicalising it would mean reaching across a block we don't own. It
        # is STALE, conflicting guidance — not a harmless duplicate — so surface
        # it instead of silently shipping a split brain (foreign-safety wins over
        # own-dedup, C-4 (e)).
        logger.warning(
            "wardline instruction block in %s has a duplicate beyond another "
            "tool's block that could not be canonicalised without crossing it; "
            "the stale copy was left in place. Resolve it by hand.",
            file_path,
        )

    candidate = text[:start] + block + sep + tail
    if candidate == text:
        return "unchanged"
    _atomic_write_text(file_path, candidate)
    return "updated"
