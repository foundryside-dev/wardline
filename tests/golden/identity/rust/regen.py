"""Regenerate the Rust identity golden corpus.

Run ONLY for an intentional, versioned rekey — NEVER to paper over an accidental
drift (mirrors the Python oracle's discipline; see
``docs/decisions/2026-06-05-wardline-finding-identity-frozen-contract.md``).
Requires ``--reason`` and stamps it into ``corpus/META.json``.

Run with ``tests/`` on the path so the ``golden.identity.rust`` package resolves:

    cd tests && PYTHONPATH=. python -m golden.identity.rust.regen --reason "<why>"
"""

from __future__ import annotations

import argparse
from pathlib import Path

from golden.identity.rust import _capture as c  # type: ignore[import-not-found]
from wardline.core.finding import FINGERPRINT_SCHEME

_HERE = Path(__file__).parent
_INPUTS = {
    "rustapp": _HERE / "fixtures" / "rustapp",
}
# 1: initial freeze (SP2 completion gate) — crate-prefixed RS-WL-* identity.
# 2: graduation — drop the provisional_identity property (rules.py no longer emits it;
#    RS-WL-* baseline-eligible). Fingerprints unchanged (the property was never folded in).
CORPUS_VERSION = 2


def main() -> None:
    parser = argparse.ArgumentParser(description="Regenerate the Rust identity golden corpus.")
    parser.add_argument("--reason", required=True, help="Why the corpus is being rekeyed (accountability record).")
    args = parser.parse_args()

    out = _HERE / "corpus"
    out.mkdir(exist_ok=True)
    for name, root in sorted(_INPUTS.items()):
        (out / f"{name}.json").write_text(c.to_json(c.capture(root)), encoding="utf-8")
    (out / "META.json").write_text(
        c.to_json({"corpus_version": CORPUS_VERSION, "fingerprint_scheme": FINGERPRINT_SCHEME, "reason": args.reason}),
        encoding="utf-8",
    )
    print(f"wrote Rust identity corpus ({len(_INPUTS)} inputs + META) to {out}")


if __name__ == "__main__":
    main()
