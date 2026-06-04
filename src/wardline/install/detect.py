"""Detect sibling tools (Clarion, Filigree) and record bindings in wardline.yaml.

Presence is detectable (a marker file, local config, binary on PATH, or env URL).
Known local URL conventions are discoverable from sibling project files; otherwise
we write a commented stanza for the user to fill. Writes are text-appends guarded
by a key/sentinel check, so re-running never duplicates or clobbers.
"""

from __future__ import annotations

import json
import os
import re
import shutil
from pathlib import Path

from wardline.core.safe_paths import safe_project_file


def _strip_scalar(value: str) -> str:
    return value.split("#", 1)[0].strip().strip('"').strip("'")


def _http_url_from_bind(bind: str) -> str | None:
    bind = _strip_scalar(bind)
    if not bind:
        return None
    if bind.startswith(("http://", "https://")):
        return bind
    if ":" not in bind:
        return None
    host, port = bind.rsplit(":", 1)
    host = host.strip()
    port = port.strip()
    if not port.isdigit():
        return None
    if host in ("0.0.0.0", "::"):
        host = "127.0.0.1"
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    return f"http://{host}:{port}"


def _clarion_url_from_config(root: Path) -> str | None:
    path = root / "clarion.yaml"
    if not path.is_file():
        return None
    enabled = False
    bind: str | None = None
    in_serve = False
    in_http = False
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        if indent == 0:
            in_serve = stripped == "serve:"
            in_http = False
            continue
        if in_serve and indent == 2:
            in_http = stripped == "http:"
            continue
        if in_serve and in_http and indent >= 4:
            if stripped.startswith("enabled:"):
                enabled = _strip_scalar(stripped.split(":", 1)[1]).lower() in {"true", "yes", "on", "1"}
            elif stripped.startswith("bind:"):
                bind = stripped.split(":", 1)[1]
    if not enabled or bind is None:
        return None
    return _http_url_from_bind(bind)


def _filigree_url_from_project(root: Path) -> str | None:
    port_file = root / ".filigree" / "ephemeral.port"
    if not port_file.is_file():
        return None
    text = port_file.read_text(encoding="utf-8", errors="replace").strip()
    if not text.isdigit():
        return None
    port = int(text)
    if not 1 <= port <= 65535:
        return None
    return f"http://localhost:{port}/api/loom/scan-results"


def _detect_clarion(root: Path) -> tuple[bool, str | None, str | None]:
    url = os.environ.get("WARDLINE_CLARION_URL") or None
    if url:
        return True, url, "env"
    discovered = _clarion_url_from_config(root)
    present = discovered is not None or (root / "clarion.yaml").is_file() or shutil.which("clarion") is not None
    return present, discovered, "discovered" if discovered else None


def _detect_filigree(root: Path) -> tuple[bool, str | None, str | None]:
    url = os.environ.get("WARDLINE_FILIGREE_URL") or None
    if url:
        return True, url, "env"
    discovered = _filigree_url_from_project(root)
    present = discovered is not None or (root / ".filigree.conf").is_file()
    return present, discovered, "discovered" if discovered else None


def _live_stanza(key: str, url: str, source: str) -> str:
    # json.dumps yields a YAML-valid, properly escaped double-quoted scalar
    # (so a URL containing a quote/backslash can't corrupt wardline.yaml).
    origin = "from env at install time" if source == "env" else "discovered at install time"
    return f"{key}:\n  url: {json.dumps(url)}  # wardline-install:{key} ({origin})\n"


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
    cfg = safe_project_file(root, root / "wardline.yaml", label="wardline.yaml")
    text = cfg.read_text(encoding="utf-8") if cfg.exists() else ""
    detections = {"clarion": _detect_clarion(root), "filigree": _detect_filigree(root)}
    additions: list[str] = []
    results: dict[str, str] = {}
    for key, (present, url, source) in detections.items():
        if not present:
            results[key] = "absent"
            continue
        if _already_recorded(text + "".join(additions), key):
            results[key] = "present (left untouched)"
            continue
        if url:
            additions.append(_live_stanza(key, url, source or "discovered"))
            results[key] = "wired (env URL)" if source == "env" else "wired (discovered URL)"
        else:
            additions.append(_COMMENTED[key])
            results[key] = "detected (commented)"
    if additions:
        sep = "" if (not text or text.endswith("\n")) else "\n"
        lead = "\n" if text else ""
        cfg.write_text(text + sep + lead + "\n".join(additions), encoding="utf-8")
    return results
