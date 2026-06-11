"""Detect sibling tools (Loomweave, Filigree) — detection only, never persisted.

Presence is detectable (a marker file, local config, binary on PATH, or env URL).
Known local URL conventions are discoverable from sibling project files. We do NOT
write any config: the shared ``weft.toml`` is operator-authored and read-only for
us, and live URLs are resolved on demand via the published ``.weft/<sibling>/
ephemeral.port`` rung (see ``core/config.resolve_*_url``). An operator who wants a
fixed URL sets the ``WARDLINE_LOOMWEAVE_URL`` / ``WARDLINE_FILIGREE_URL`` env var (or
passes a ``--*-url`` flag); sibling-endpoint *config keys* are hub-pinned and pending,
so wardline reads none today.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

from wardline.core.config import filigree_server_scoped_url
from wardline.core.paths import legacy_sibling_dir, sibling_state_dir
from wardline.core.safe_paths import safe_read_text_if_regular


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


def _loomweave_url_from_config(root: Path) -> str | None:
    path = root / "loomweave.yaml"
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
    # Prefer the consolidated .weft/filigree/ location; tolerate the legacy
    # .filigree/ dot-dir during the federation transition window.
    for base in (sibling_state_dir(root, "filigree"), legacy_sibling_dir(root, "filigree")):
        # ascii read, mirroring core/config._read_published_port: ephemeral.port is
        # an ASCII integer by protocol, so non-ASCII bytes (incl. Unicode "digit"
        # chars that pass isdigit() but raise in int()) are rejected at decode time.
        port_text = safe_read_text_if_regular(root, base / "ephemeral.port", label="ephemeral.port", encoding="ascii")
        if port_text is None:
            continue
        text = port_text.strip()
        # Guard int(): isdigit() is a superset of what int() parses, so an all-digit
        # payload over CPython's 4300-digit cap raises ValueError (the ascii read
        # above already excludes Unicode digits). Catch it so a planted ephemeral.port
        # stays fail-soft and never crashes detection.
        if text.isdigit():
            try:
                port = int(text)
            except ValueError:
                continue
            if 1 <= port <= 65535:
                return f"http://localhost:{port}/api/weft/scan-results"
    return None


def _detect_loomweave(root: Path) -> tuple[bool, str | None, str | None]:
    url = os.environ.get("WARDLINE_LOOMWEAVE_URL") or None
    if url:
        return True, url, "env"
    discovered = _loomweave_url_from_config(root)
    present = discovered is not None or (root / "loomweave.yaml").is_file() or shutil.which("loomweave") is not None
    return present, discovered, "discovered" if discovered else None


def _detect_filigree(root: Path) -> tuple[bool, str | None, str | None]:
    url = os.environ.get("WARDLINE_FILIGREE_URL") or None
    if url:
        return True, url, "env"
    # Server mode first: a multi-project daemon publishes no per-project ephemeral.port,
    # so its project scope is discoverable only from the home-global registry. Report the
    # SCOPED URL so install output matches the scoped target merge_mcp_entry persists
    # (without it, install would print "filigree absent" right after wiring it).
    scoped = filigree_server_scoped_url(root)
    if scoped is not None:
        return True, scoped, "server-mode scope"
    discovered = _filigree_url_from_project(root)
    present = discovered is not None or (root / ".filigree.conf").is_file()
    return present, discovered, "discovered" if discovered else None


def detect_siblings(root: Path) -> dict[str, str]:
    """Detect sibling tools without persisting anything.

    Binding persistence was dropped in the Weft config consolidation: live URLs are
    resolved on demand via the published ``.weft/<sibling>/ephemeral.port`` rung
    (see ``core/config.resolve_*_url``); an operator who wants a fixed URL sets the
    ``WARDLINE_LOOMWEAVE_URL`` / ``WARDLINE_FILIGREE_URL`` env var (sibling-endpoint
    config keys are hub-pinned and pending). We never write the operator's config
    file. Returns a per-sibling human-readable status.
    """
    results: dict[str, str] = {}
    for key, detector in (("loomweave", _detect_loomweave), ("filigree", _detect_filigree)):
        present, url, source = detector(root)
        if not present:
            results[key] = "absent"
        elif url:
            results[key] = f"detected ({source} URL)"
        else:
            results[key] = f"detected (no URL — set WARDLINE_{key.upper()}_URL or rely on live .weft/{key}/ discovery)"
    return results
