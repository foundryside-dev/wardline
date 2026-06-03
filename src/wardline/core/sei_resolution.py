# src/wardline/core/sei_resolution.py
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from wardline.core.errors import WardlineError

logger = logging.getLogger(__name__)


def locator_to_qualname(locator: str) -> str:
    """Extract a Wardline qualname from a Clarion locator string.

    A locator looks like 'python:function:pkg.mod.func' or 'python:class:pkg.mod.Class'.
    """
    for prefix in ("python:function:", "python:class:", "python:"):
        if locator.startswith(prefix):
            return locator[len(prefix) :]
    return locator


def resolve_query_filters(
    where: dict[str, Any] | None,
    root: Path,
    config_path: Path | None,
    clarion_client: Any = None,
) -> dict[str, Any] | None:
    """Resolve a `qualname` filter starting with `sei:` in findings queries to its resolved qualname."""
    if not where or "qualname" not in where:
        return where

    qval = where["qualname"]
    if not isinstance(qval, str) or not qval.startswith("sei:"):
        return where

    if clarion_client is None:
        from wardline.core.config import resolve_clarion_url

        clarion_url = resolve_clarion_url(None, root, config_path)
        if clarion_url is not None:
            from wardline.clarion.client import ClarionClient
            from wardline.clarion.config import load_clarion_token, resolve_project_name

            clarion_client = ClarionClient(
                clarion_url,
                secret=load_clarion_token(root),
                project=resolve_project_name(root),
            )

    if clarion_client is None:
        raise WardlineError(f"no Clarion URL configured; cannot resolve SEI filter {qval}")

    from wardline.clarion.identity import SeiCapability, SeiResolver

    resolver = SeiResolver(clarion_client, SeiCapability.from_capabilities(clarion_client.capabilities()))
    if not resolver.capability.supported:
        raise WardlineError(f"Clarion instance does not support SEI; cannot resolve filter {qval}")

    data = clarion_client.resolve_sei(qval)
    if data is None or "current_locator" not in data:
        raise WardlineError(f"cannot resolve SEI to a qualname: {qval}")

    locator = data["current_locator"]
    qualname = locator_to_qualname(locator)

    new_where = dict(where)
    new_where["qualname"] = qualname
    return new_where
