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
from wardline.core.safe_paths import safe_project_file, safe_read_text_if_regular

logger = logging.getLogger(__name__)

CLAUDE_MD = "CLAUDE.md"
AGENTS_MD = "AGENTS.md"

_BLOCK_VERSION = "1"


def _compose_body(grant_suffix: str = "", grant_sentence: str = "") -> str:
    return (
        "This project uses **wardline** as its trust-boundary gate. Before handing "
        f"back code that touches external input, run `wardline scan . --fail-on ERROR{grant_suffix}` "
        "(exit 0 = clean, 1 = gate tripped, 2 = wardline error) and fix findings at "
        f"the boundary, not the sink.{grant_sentence} The full scan -> explain -> fix -> rescan loop "
        "and the baseline-vs-waiver discipline live in the `wardline-gate` skill and "
        "in `docs/agents.md`."
    )


_BODY = _compose_body()


def _pack_guidance(project_root: Path) -> tuple[str, str]:
    """(scan-command grant suffix, explanatory sentence) when the project's weft.toml
    declares trust-grammar packs, else ``("", "")``.

    Without the grants the stock command exits 2 ("pack not trusted") in every
    pack-declaring project — guidance that cannot work for the very feature it
    supports (wardline-2e4443418c). The suffix documents the command the human
    already sanctioned by declaring the pack; it grants nothing by itself.
    Fail-soft: an unreadable/malformed config reads as no packs (stock text).
    """
    import tomllib

    from wardline.core.config import _local_pack_import_root

    weft = project_root / "weft.toml"
    try:
        parsed = tomllib.loads(weft.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError):
        return "", ""
    table = parsed.get("wardline")
    packs = table.get("packs") if isinstance(table, dict) else None
    if not isinstance(packs, list):
        return "", ""
    names = [p for p in packs if isinstance(p, str)]
    if not names:
        return "", ""
    suffix = "".join(f" --trust-pack {name}" for name in names)
    if any(_local_pack_import_root(name, weft) is not None for name in names):
        suffix += " --allow-custom-packs"
    sentence = (
        f" This project declares trust-grammar pack(s) {', '.join(names)} in weft.toml; "
        "the grant flags shown are REQUIRED — without them the scan exits 2 (pack not "
        "trusted), because repository config cannot self-authorise importing code."
    )
    return suffix, sentence


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


def _body_hash(body: str) -> str:
    return hashlib.sha256(body.encode("utf-8")).hexdigest()[:8]


def render_block(project_root: Path | None = None) -> str:
    """The canonical block: stock text, or — given a project root — the pack-aware
    text whose scan command carries the project's required trust grants."""
    body = _BODY if project_root is None else _compose_body(*_pack_guidance(project_root))
    open_fence = f"<!-- {_OWN_NS}:instructions:v{_BLOCK_VERSION}:{_body_hash(body)} -->"
    return f"{open_fence}\n{_WRITER_MARKER}\n{body}\n{_END_MARKER}"


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
    closes_after: set[str] = set()
    boundary: int | None = None
    for m in reversed(list(_INSTR_FENCE_RE.finditer(content, search_from))):
        ns = m.group("ns").lower()
        is_close = bool(m.group("close"))
        if ns == _OWN_NS:
            continue
        if is_close:
            closes_after.add(ns)
        elif ns in closes_after:
            boundary = m.start()
    return boundary if boundary is not None else len(content)


def _own_open_fence_positions(content: str) -> list[int]:
    """Indices of wardline's *own* top-level open instruction fences, in order.

    A wardline open marker quoted *inside* a co-resident sibling block (a worked
    example, documentation) is textually identical to a real one, so a bare regex
    anchor would splice there and gut the sibling. This walks fences in document
    order, tracking the foreign block we are currently inside, and only reports a
    wardline open fence found at top level (not enclosed by an unclosed foreign
    block). An unclosed foreign block therefore shields any wardline marker
    beyond it: we decline to claim content we cannot prove is ours.

    The list *length* is the number of distinct wardline blocks. More than one is
    a split brain — two divergent copies of the guidance — which the injector
    tolerates when it cannot canonicalise across a sibling's block (it warns and
    leaves the stale copy), and which :func:`remove_block` refuses to guess at.
    """
    positions: list[int] = []
    inside_foreign: str | None = None
    for m in _INSTR_FENCE_RE.finditer(content):
        ns = m.group("ns").lower()
        is_close = bool(m.group("close"))
        if inside_foreign is not None:
            if is_close and ns == inside_foreign:
                inside_foreign = None
            continue
        if ns == _OWN_NS and not is_close:
            positions.append(m.start())
            continue
        if ns != _OWN_NS and not is_close:
            inside_foreign = ns
    return positions


def _first_own_open_fence_pos(content: str) -> int:
    """Index of wardline's first *own* top-level open instruction fence, or -1.

    The caller falls back to an append (which deletes nothing) on -1. See
    :func:`_own_open_fence_positions` for the foreign-shielding rules.
    """
    positions = _own_open_fence_positions(content)
    return positions[0] if positions else -1


def has_own_block(file_path: Path) -> bool:
    """Whether *file_path* carries wardline's own top-level instruction block.

    The READ side of :func:`inject_block` / :func:`remove_block`, and it must walk
    fences exactly as they do. A bare ``"wardline:instructions:" in content`` substring
    test does NOT: it also matches a marker a *sibling's* managed block merely quotes,
    which :func:`_own_open_fence_positions` deliberately declines to claim. Two symmetric
    failures follow from that disagreement, both observed before this became one
    function (wardline release-1.5.0 review, H2):

    - **False present.** A detector that sees a quoted marker reports a block the
      writers cannot find, so ``doctor --repair`` runs :func:`remove_block`, which
      correctly no-ops, and the check stays red on the next pass — forever, with no
      operator action that clears it.
    - **False absent.** The inverse reading — reporting a block as *configured* when
      the only marker is inside a sibling's block and wardline's own is genuinely
      missing — is a false all-clear.

    Total by construction: a missing, unreadable, or non-regular file reads as *no
    block*. Doctor must be able to diagnose a file it cannot read.
    """
    try:
        if not file_path.is_file():
            return False
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return bool(_own_open_fence_positions(content))


def _first_any_foreign_fence_pos(content: str, search_from: int) -> int:
    """Index of the first *any* foreign instruction fence at/after *search_from*.

    Strictly more conservative than :func:`_first_real_foreign_block_pos`: a
    *lone* foreign open or a stray foreign close is a boundary here, where the
    injector absorbs it. Only :func:`remove_block` uses this. The injector can
    always fall back to an append — which deletes nothing — so it may safely
    treat an unmatched foreign marker as our own content. Removal has no such
    fallback: a mis-bounded delete eats a sibling's block, so it stops at any
    foreign fence at all. Own-namespace fences are absorbed either way.

    Returns ``len(content)`` when no foreign fence follows (bound at EOF).
    """
    for m in _INSTR_FENCE_RE.finditer(content, search_from):
        if m.group("ns").lower() != _OWN_NS:
            return m.start()
    return len(content)


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
    block = render_block(file_path.parent)
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


def remove_block(file_path: Path) -> tuple[bool, str]:
    """Remove wardline's own instruction block from *file_path*, or refuse.

    The delete-side mirror of :func:`inject_block`, and deliberately more
    conservative than it. Injection can always fall back to an append — which
    deletes nothing — so it may safely bound a malformed block at a foreign
    fence. Removal has no such fallback: a mis-bounded delete eats a sibling's
    block. So every case where ownership is not *provable* is a no-op that
    deletes nothing:

    - no own top-level open fence → nothing to remove (success, no write);
    - own marker shielded inside an unclosed foreign block → not ours, no-op;
    - own close marker missing, or sitting beyond a foreign fence → refuse;
    - more than one own block (split brain) → refuse, matching the injector's
      "resolve it by hand" posture rather than guessing which copy to drop.

    Returns ``(ok, message)`` rather than raising: a conservative refusal is a
    deliberate outcome that callers must *surface*, not an error that should
    abort an install. Only genuine unsafety (a symlinked target) raises.
    """
    file_path = safe_project_file(file_path.parent, file_path, label=file_path.name)
    if not file_path.exists():
        return True, f"no wardline block in {file_path.name}"
    try:
        content = file_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        return False, f"could not read {file_path.name}: {exc}"

    positions = _own_open_fence_positions(content)
    if not positions:
        return True, f"no wardline block in {file_path.name}"
    if len(positions) > 1:
        return False, (
            f"{file_path.name} has {len(positions)} wardline instruction blocks "
            "(split brain); refusing to guess which copy to remove — resolve it by hand"
        )

    start = positions[0]
    own_end = content.find(_END_MARKER, start)
    foreign = _first_any_foreign_fence_pos(content, start + len(f"<!-- {_OWN_NS}:instructions"))
    if own_end == -1 or own_end >= foreign:
        return False, (
            f"the wardline instruction block in {file_path.name} is unclosed or its close "
            "marker sits beyond another tool's block; refusing to delete across a boundary "
            "we cannot prove is ours"
        )

    # Excise, then tidy only at the seam. The injector appends as
    # "\n" + block + "\n", so a naive cut leaves a doubled blank line; trimming
    # newlines on each side of the seam restores the single blank line without
    # touching blank runs elsewhere in the file.
    head = content[:start].rstrip("\n")
    tail = content[own_end + len(_END_MARKER) :].lstrip("\n")
    remainder = head + "\n\n" + tail if (head and tail) else (head or tail)

    if not remainder.strip():
        # The file held nothing but wardline's block — i.e. exactly what
        # inject_block creates for a missing file. Removing it is the symmetric
        # inverse of that create; leaving a blank file behind would also trip the
        # refuse-to-empty guard in _atomic_write_text.
        file_path.unlink()
        return True, f"removed {file_path.name} (it held nothing but the wardline block)"

    if not remainder.endswith("\n"):
        remainder += "\n"
    _atomic_write_text(file_path, remainder)
    return True, f"removed the wardline block from {file_path.name}"


# ---------------------------------------------------------------------------
# CLAUDE.md -> AGENTS.md redirect routing (C-20)
# ---------------------------------------------------------------------------

# A line that is *solely* an @-import of AGENTS.md. Anchored both ends against
# the stripped line, so `See @AGENTS.md for details` (not solely an import) and
# `@AGENTS.md.bak` (a different file) both correctly fail to match. Case-
# insensitive, covering `@agents.md` / `@AGENTS.MD`. The `./` is matched as a
# unit so the `@./AGENTS.md` spelling works while an absolute `@/AGENTS.md` does
# NOT — that names a different path, and treating it as a redirect would stop us
# maintaining the block this CLAUDE.md actually carries.
_AGENTS_REDIRECT_RE = re.compile(r"^@(?:\./)?AGENTS\.md$", re.IGNORECASE)


def _mask_managed_blocks(content: str) -> str:
    """Blank every managed instruction block, preserving line structure.

    Characters inside any tool's block — wardline's own as well as a sibling's —
    become spaces while newlines survive, so a caller can scan line-anchored
    markers without seeing text a block merely *quotes*. An unclosed block masks
    to EOF: we cannot prove where it ends, so we decline to read anything past it
    as free-standing project prose.

    Known limitation, accepted as spec and shared with the sibling
    implementations: masking covers managed blocks only, so an ``@AGENTS.md``
    example inside a plain markdown fence still reads as a redirect. Uniform
    behaviour across the federation beats a wardline-only refinement here.
    """
    out = list(content)
    inside: str | None = None
    block_start = 0
    for m in _INSTR_FENCE_RE.finditer(content):
        ns = m.group("ns").lower()
        is_close = bool(m.group("close"))
        if inside is None:
            if not is_close:
                inside = ns
                block_start = m.start()
            continue
        if is_close and ns == inside:
            close_end = content.find("-->", m.start())
            close_end = len(content) if close_end == -1 else close_end + len("-->")
            for i in range(block_start, close_end):
                if out[i] != "\n":
                    out[i] = " "
            inside = None
    if inside is not None:
        for i in range(block_start, len(content)):
            if out[i] != "\n":
                out[i] = " "
    return "".join(out)


def claude_md_redirects_to_agents_md(project_root: Path) -> bool:
    """Whether ``CLAUDE.md`` is merely a redirect to ``AGENTS.md`` (C-20).

    True when, *outside* every managed instruction block, ``CLAUDE.md`` carries a
    line that is solely an @-import of ``AGENTS.md``. Such a project keeps one
    source of agent context, so wardline maintains its block in ``AGENTS.md``
    only (see :func:`instruction_targets`).

    Anything we cannot read as a plain project file — absent, unreadable, not
    valid UTF-8, a symlink, a non-regular file, or outside the project root —
    reads as *no* redirect, so the caller keeps the existing dual-write
    behaviour. Failing safe here costs a redundant block; failing open would
    silently stop maintaining the block a project actually reads.
    """
    content = safe_read_text_if_regular(project_root, project_root / CLAUDE_MD, label=CLAUDE_MD)
    if content is None:
        return False
    return any(_AGENTS_REDIRECT_RE.match(line.strip()) for line in _mask_managed_blocks(content).splitlines())


def instruction_targets(project_root: Path) -> tuple[list[str], list[str]]:
    """Return ``(write_to, migrate_off)`` agent-context filenames for a project.

    Normally wardline dual-writes ``CLAUDE.md`` and ``AGENTS.md`` and migrates
    nothing. When ``CLAUDE.md`` only redirects to ``AGENTS.md`` the block belongs
    in ``AGENTS.md`` alone, and any legacy block left in ``CLAUDE.md`` is listed
    for migration — a redirect already supplies that content, so a second copy is
    duplicate guidance that drifts.
    """
    if claude_md_redirects_to_agents_md(project_root):
        return [AGENTS_MD], [CLAUDE_MD]
    return [CLAUDE_MD, AGENTS_MD], []


def inject_block_for_project(
    project_root: Path,
    *,
    claude_md: bool = True,
    agents_md: bool = True,
) -> list[tuple[bool, str, str]]:
    """Install/refresh wardline's block across a project's agent-context files.

    The redirect-aware (C-20) counterpart of :func:`inject_block`, which it
    delegates to unchanged for each selected file. Migration runs first, so a
    redirecting project never briefly carries two blocks. Returns one
    ``(ok, filename, message)`` per action taken.

    ``claude_md`` / ``agents_md`` mirror the CLI's ``--no-claude-md`` /
    ``--no-agents-md`` opt-outs, which the normative sibling implementations do
    not have. Two judgment calls follow from them, both chosen so an opt-out can
    never *destroy* guidance:

    - Under a redirect, ``--no-claude-md`` means "do not touch CLAUDE.md", so it
      suppresses the migration (the only CLAUDE.md action left).
    - A migration only runs when the write that replaces it actually ran. With
      ``--no-agents-md`` under a redirect, migrating would delete the block from
      CLAUDE.md while nothing wrote it to AGENTS.md, leaving the project with no
      block at all — an opt-out must skip work, not erase it.
    """
    write_to, migrate_off = instruction_targets(project_root)
    allowed = {CLAUDE_MD: claude_md, AGENTS_MD: agents_md}
    wrote = [name for name in write_to if allowed[name]]

    results: list[tuple[bool, str, str]] = []
    for filename in migrate_off:
        if not allowed[filename] or not wrote:
            continue
        ok, message = remove_block(project_root / filename)
        results.append((ok, filename, message))
    for filename in wrote:
        results.append((True, filename, inject_block(project_root / filename)))
    return results
