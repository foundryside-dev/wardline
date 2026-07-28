"""C-20 budget guards for wardline's always-loaded agent injections.

Cites weft-6a1fdb0192. The always-loaded surface is budgeted: every agent
session pays for these bytes whether or not it ever touches wardline, so they
are capped and the cap is enforced here rather than re-measured by hand.

Budgets (weft conventions C-20):

- injected instruction block   <=  800 chars
- SKILL.md                     <= 4000 chars
- SKILL.md frontmatter description <= 500 chars

The measurement convention matches the sibling implementation in filigree
(``tests/mcp/test_tools.py::test_skill_stays_within_c18_budget``): SKILL.md is
measured *whole file*, not body-after-frontmatter, and both the character count
and the UTF-8 byte count must fit. Divergent per-member guards are exactly the
drift C-20 exists to stop, so keep this aligned with the siblings.

One deliberate difference from filigree: filigree measures its instruction
*template* because its assembled block embeds a version string that differs
between a source checkout and an installed dist. wardline's ``render_block()``
is deterministic (a literal block version plus a hash of ``_BODY``), so this
measures the assembled block — what actually lands in a project's CLAUDE.md /
AGENTS.md.

When a budget trips, the fix is NEVER to delete unique content: move the
overflow verbatim into ``references/*.md`` alongside SKILL.md (shipped by
``install_skill``'s copytree) and leave the scan -> explain -> fix -> rescan
loop in SKILL.md itself.
"""

from __future__ import annotations

import re
from pathlib import Path

from wardline.install.block import render_block

SKILL_DIR = Path(__file__).resolve().parents[3] / "src" / "wardline" / "skills" / "wardline-gate"

BLOCK_BUDGET = 800
SKILL_BUDGET = 4000
DESCRIPTION_BUDGET = 500


def _skill_text(name: str = "SKILL.md") -> str:
    return (SKILL_DIR / name).read_text(encoding="utf-8")


def test_injected_block_stays_within_c20_budget() -> None:
    """C-20 budget: <= 800 chars for the block injected into CLAUDE.md/AGENTS.md."""
    block = render_block()
    assert len(block) <= BLOCK_BUDGET, (
        f"the injected wardline instruction block is {len(block)} chars "
        f"(C-20 budget: {BLOCK_BUDGET}). Defer detail to the wardline-gate skill "
        "rather than growing the always-loaded block."
    )
    assert len(block.encode("utf-8")) <= BLOCK_BUDGET


def test_skill_stays_within_c20_budget() -> None:
    """C-20 budget: <= 4000 chars for SKILL.md, <= 500 for its description."""
    text = _skill_text()
    assert len(text) <= SKILL_BUDGET, (
        f"SKILL.md is {len(text)} chars (C-20 budget: {SKILL_BUDGET}). "
        "Move the overflow VERBATIM into references/*.md in the same skill "
        "directory — never delete unique content. Keep the scan -> explain -> "
        "fix -> rescan loop in SKILL.md."
    )
    assert len(text.encode("utf-8")) <= SKILL_BUDGET

    frontmatter = re.match(r"---\n(.*?)\n---\n", text, re.DOTALL)
    assert frontmatter is not None, "SKILL.md lost its frontmatter"
    description = frontmatter.group(1).split("description: >", 1)[1].strip()
    assert len(description) <= DESCRIPTION_BUDGET, (
        f"the skill description is {len(description)} chars "
        f"(C-20 budget: {DESCRIPTION_BUDGET}). It is a trigger, not a summary — "
        "say when to reach for the skill, not what it contains."
    )


def test_skill_keeps_the_core_loop_in_skill_md() -> None:
    """The loop is the one thing that must never be relocated to a reference sheet.

    A budget trip is fixed by moving *detail* out; if a future shrink pushed the
    loop itself into references/, the skill would no longer answer the question
    it exists to answer without a second hop.
    """
    text = _skill_text()
    for step in ("Scan", "Explain", "BOUNDARY", "Re-scan"):
        assert step in text, f"SKILL.md no longer states the {step!r} step of the loop"


def test_skill_references_are_shipped_alongside_skill_md() -> None:
    """Any reference sheet must live in the skill dir so ``install_skill`` ships it.

    ``install_skill`` copies the whole ``wardline-gate`` tree, so a sheet placed
    here is installed; a sheet placed anywhere else would be dangling guidance
    that an installed project cannot open.
    """
    for sheet in SKILL_DIR.rglob("*.md"):
        assert sheet.is_relative_to(SKILL_DIR)
        assert sheet.read_text(encoding="utf-8").strip(), f"{sheet.name} is empty"
