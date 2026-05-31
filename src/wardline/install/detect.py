"""Detect sibling tools (Clarion, Filigree) and record bindings in wardline.yaml.

Presence is detectable (a marker file or a binary on PATH / an env URL); a service
URL is not discoverable, so we write a live stanza only when an env URL is set,
otherwise a commented stanza for the user to fill. Writes are text-appends guarded
by a key/sentinel check, so re-running never duplicates or clobbers.
"""

from __future__ import annotations

import json
import os
import re
import shutil
from pathlib import Path


def _detect_clarion() -> tuple[bool, str | None]:
    url = os.environ.get("WARDLINE_CLARION_URL") or None
    present = bool(url) or shutil.which("clarion") is not None
    return present, url


def _detect_filigree(root: Path) -> tuple[bool, str | None]:
    url = os.environ.get("WARDLINE_FILIGREE_URL") or None
    present = bool(url) or (root / ".filigree.conf").is_file()
    return present, url


def _live_stanza(key: str, url: str) -> str:
    # json.dumps yields a YAML-valid, properly escaped double-quoted scalar
    # (so a URL containing a quote/backslash can't corrupt wardline.yaml).
    return f"{key}:\n  url: {json.dumps(url)}  # wardline-install:{key} (from env at install time)\n"


_COMMENTED = {
    "clarion": (
        "# wardline-install:clarion — Clarion taint store detected, no URL configured.\n"
        "# Set the taint-store URL to enable per-entity taint-fact enrichment:\n"
        "# clarion:\n"
        '#   url: "http://localhost:PORT"\n'
    ),
    "filigree": (
        "# wardline-install:filigree — Filigree detected (.filigree.conf), no URL configured.\n"
        "# Set the Loom scan-results URL to POST findings into Filigree:\n"
        "# filigree:\n"
        '#   url: "http://localhost:PORT/api/loom/scan-results"\n'
    ),
}


def _already_recorded(text: str, key: str) -> bool:
    # Live key at column 0, or our sentinel from a previous commented write.
    return bool(re.search(rf"(?m)^{key}:", text)) or f"wardline-install:{key}" in text


def record_bindings(root: Path) -> dict[str, str]:
    """Detect siblings and append stanzas to wardline.yaml. Returns per-key status."""
    cfg = root / "wardline.yaml"
    text = cfg.read_text(encoding="utf-8") if cfg.exists() else ""
    detections = {"clarion": _detect_clarion(), "filigree": _detect_filigree(root)}
    additions: list[str] = []
    results: dict[str, str] = {}
    for key, (present, url) in detections.items():
        if not present:
            results[key] = "absent"
            continue
        if _already_recorded(text + "".join(additions), key):
            results[key] = "present (left untouched)"
            continue
        if url:
            additions.append(_live_stanza(key, url))
            results[key] = "wired (env URL)"
        else:
            additions.append(_COMMENTED[key])
            results[key] = "detected (commented)"
    if additions:
        sep = "" if (not text or text.endswith("\n")) else "\n"
        lead = "\n" if text else ""
        cfg.write_text(text + sep + lead + "\n".join(additions), encoding="utf-8")
    return results
