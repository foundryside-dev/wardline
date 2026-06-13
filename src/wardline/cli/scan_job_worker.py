"""Subprocess entrypoint for file-backed scan jobs."""

from __future__ import annotations

import sys
from pathlib import Path

from wardline.core.errors import WardlineError
from wardline.core.scan_jobs import run_scan_job_worker


def main() -> None:
    if len(sys.argv) != 3:
        print("usage: python -m wardline.cli.scan_job_worker ROOT JOB_ID", file=sys.stderr)
        raise SystemExit(2)
    try:
        run_scan_job_worker(Path(sys.argv[1]), sys.argv[2])
    except WardlineError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc


if __name__ == "__main__":
    main()
