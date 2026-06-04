"""Regenerate the identity golden corpus.

Run ONLY for an intentional, versioned rekey (see the ADR
``docs/decisions/2026-06-05-wardline-finding-identity-frozen-contract.md``) —
NEVER to paper over an accidental drift. Requires ``--reason`` and stamps it into
``corpus/META.json`` as the accountability record (the real enforcement is the
parity test + CODEOWNERS on ``corpus/**``, which fails any PR that changes the
corpus without a matching production change).

Run with ``tests/`` on the path so the ``golden.identity`` package resolves:

    cd tests && PYTHONPATH=. python -m golden.identity.regen --reason "<why>"
"""

from __future__ import annotations

import argparse
from pathlib import Path

from golden.identity import _capture as c  # type: ignore[import-not-found]

_HERE = Path(__file__).parent
_INPUTS = {
    "sampleapp": _HERE / "fixtures" / "sampleapp",
    "stress": _HERE / "fixtures" / "stress",
}
CORPUS_VERSION = 1


def main() -> None:
    parser = argparse.ArgumentParser(description="Regenerate the identity golden corpus.")
    parser.add_argument("--reason", required=True, help="Why the corpus is being rekeyed (accountability record).")
    args = parser.parse_args()

    out = _HERE / "corpus"
    out.mkdir(exist_ok=True)
    for name, root in sorted(_INPUTS.items()):
        (out / f"{name}.json").write_text(c.to_json(c.capture(root)), encoding="utf-8")
    (out / "assure.json").write_text(
        c.to_json({k: c.capture_assure(v) for k, v in sorted(_INPUTS.items())}),
        encoding="utf-8",
    )
    (out / "META.json").write_text(
        c.to_json({"corpus_version": CORPUS_VERSION, "reason": args.reason}),
        encoding="utf-8",
    )
    print(f"wrote identity corpus ({len(_INPUTS)} inputs + assure + META) to {out}")


if __name__ == "__main__":
    main()
