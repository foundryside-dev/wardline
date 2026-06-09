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
from wardline.core.finding import FINGERPRINT_SCHEME

_HERE = Path(__file__).parent
_INPUTS = {
    "sampleapp": _HERE / "fixtures" / "sampleapp",
    "stress": _HERE / "fixtures" / "stress",
    "sinks": _HERE / "fixtures" / "sinks",
}
# 2->3: P1 scheme-infra (format-only — fingerprint VALUES byte-identical).
# 3->4: P3 value-rekey (wardline-8654423823) — line_start dropped from the hash +
# move-stable entity-relative discriminators, so every PY-WL-*/RS-WL-* fingerprint
# VALUE changes and META.fingerprint_scheme advances wlfp1->wlfp2.
CORPUS_VERSION = 4


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
        c.to_json({"corpus_version": CORPUS_VERSION, "fingerprint_scheme": FINGERPRINT_SCHEME, "reason": args.reason}),
        encoding="utf-8",
    )
    print(f"wrote identity corpus ({len(_INPUTS)} inputs + assure + META) to {out}")


if __name__ == "__main__":
    main()
