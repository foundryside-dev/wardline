"""The byte-identity oracle (Track 2, Task 0 / design spec §5).

Freezes today's full builtin-grammar findings stream over the T1.4 labeled corpus
(``tests/corpus/fixtures`` — see ``golden_harness`` for why corpus, not dogfood).
Every Track 2 task must keep this green: the grammar refactor
re-expresses the 4 builtin rules + 3 decorators on the open grammar and must
reproduce this stream BYTE-FOR-BYTE. The only sanctioned new finding is the
custom-only ``WLN-ENGINE-UNPROVABLE-BOUNDARY`` FACT, which never fires on the
builtin vocabulary (so it never appears here).
"""

from __future__ import annotations

from grammar.golden_harness import GOLDEN, produce_stream


def test_builtin_findings_match_golden() -> None:
    expected = GOLDEN.read_text(encoding="utf-8")
    actual = produce_stream()
    assert actual == expected, "builtin findings stream drifted from the frozen golden"
