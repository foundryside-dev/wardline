# src/wardline/core/baseline_ops.py
"""Scan-running baseline orchestration (surface tier).

``collect_and_write_baseline`` / ``generate_baseline`` run a full scan and write
the result to ``.weft/wardline/baseline.yaml``. They are split out of
:mod:`wardline.core.baseline` (which holds the policy-tier IO/derive helpers —
``Baseline``, ``load_baseline``, ``write_baseline``, ``build_baseline_document``)
precisely because they call :func:`wardline.core.run.run_scan`: keeping that call
inside ``baseline`` made ``baseline`` (a module the gate/suppression/identity layer
depends on) import the orchestrator ``run``, closing the
``run -> suppression -> finding_identity -> baseline -> run`` cycle. With the scan
runners up here, ``baseline`` no longer imports ``run`` and the cycle is gone; the
``run_scan`` import below is a plain downward (surface -> surface) dependency.
"""

from __future__ import annotations

from pathlib import Path

from wardline.core.baseline import _is_baselineable_finding, write_baseline
from wardline.core.finding import Finding, SuppressionState
from wardline.core.paths import baseline_path as baseline_file
from wardline.core.run import run_scan


def collect_and_write_baseline(
    root: Path,
    *,
    overwrite: bool,
    config_path: Path | None = None,
    cache_dir: Path | None = None,
    confine_to_root: bool = True,
    trust_local_packs: bool = False,
    trusted_packs: tuple[str, ...] = (),
    strict_defaults: bool = False,
) -> list[Finding]:
    """Derive the baselineable findings for ``root`` and write them to
    ``.weft/wardline/baseline.yaml``. Returns the findings that were baselined.

    Captures current stable DEFECTs, EXCLUDING preview findings that never gate
    and any with an active waiver (else the baseline swallows them and their
    expiry never resurfaces — spec §8).
    Honors ``config_path`` exactly as ``scan`` does, so the baseline is built
    from the same waiver set the scans will consume.

    Raises ``FileExistsError`` (with the baseline path as its message) if a
    baseline already exists and ``overwrite`` is False; the existence check
    runs *before* config load so a stale-but-present baseline is reported as
    such even when the config is broken.
    """
    baseline_path = baseline_file(root)
    if baseline_path.exists() and not overwrite:
        raise FileExistsError(str(baseline_path))
    result = run_scan(
        root,
        config_path=config_path,
        cache_dir=cache_dir,
        confine_to_root=confine_to_root,
        trust_local_packs=trust_local_packs,
        trusted_packs=trusted_packs,
        strict_defaults=strict_defaults,
    )
    to_baseline = [
        f for f in result.findings if _is_baselineable_finding(f) and f.suppressed is not SuppressionState.WAIVED
    ]
    # baseline_path is root-PREFIXED (weft_state_dir(root)/baseline.yaml). Pass it to the
    # root-confined writer as an ABSOLUTE path: a relative `root` (e.g. `wardline baseline
    # create pkg`) makes baseline_path `pkg/.weft/.../baseline.yaml`, which safe_write_text
    # would resolve under `pkg` AGAIN (`pkg/pkg/.weft/...`) — writing a baseline the next
    # scan of `pkg` never loads. .resolve() is idempotent for the absolute store_dir-override
    # form. run_scan still gets the original `root`, so finding paths are unchanged.
    write_baseline(baseline_path.resolve(), to_baseline, root=root)
    return to_baseline


def generate_baseline(
    root: Path,
    *,
    overwrite: bool,
    config_path: Path | None = None,
    cache_dir: Path | None = None,
    confine_to_root: bool = True,
    trust_local_packs: bool = False,
    trusted_packs: tuple[str, ...] = (),
    strict_defaults: bool = False,
) -> int:
    """Derive a baseline from current findings and write it. Returns the number
    of fingerprints baselined. Raises ``FileExistsError`` if a baseline already
    exists and ``overwrite`` is False (shared by the CLI and MCP baseline
    surfaces)."""
    return len(
        collect_and_write_baseline(
            root,
            overwrite=overwrite,
            config_path=config_path,
            cache_dir=cache_dir,
            confine_to_root=confine_to_root,
            trust_local_packs=trust_local_packs,
            trusted_packs=trusted_packs,
            strict_defaults=strict_defaults,
        )
    )
