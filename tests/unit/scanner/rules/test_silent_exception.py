from __future__ import annotations

import textwrap
from pathlib import Path

from wardline.core.config import WardlineConfig
from wardline.core.finding import Severity
from wardline.scanner.analyzer import WardlineAnalyzer
from wardline.scanner.rules.silent_exception import SilentException


def _analyze(tmp_path: Path, files: dict[str, str]):
    paths = []
    for rel, src in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(src), encoding="utf-8")
        paths.append(p)
    analyzer = WardlineAnalyzer()
    findings = analyzer.analyze(sorted(paths), WardlineConfig(), root=tmp_path)
    assert analyzer.last_context is not None
    return analyzer.last_context, findings


def _run(ctx):
    return SilentException().check(ctx)


def test_silent_handler_in_trusted_fires(tmp_path) -> None:
    ctx, _ = _analyze(
        tmp_path,
        {
            "m.py": "from wardline.decorators import trusted\n"
            "@trusted\ndef f():\n    try:\n        g()\n    except ValueError:\n        pass\n",
        },
    )
    findings = _run(ctx)
    assert [(f.rule_id, f.qualname) for f in findings] == [("PY-WL-104", "m.f")]
    assert findings[0].severity == Severity.WARN  # base, trusted tier unchanged


def test_except_star_silent_handler_in_trusted_fires(tmp_path) -> None:
    ctx, _ = _analyze(
        tmp_path,
        {
            "m.py": "from wardline.decorators import trusted\n"
            "@trusted\ndef f():\n    try:\n        g()\n    except* ValueError:\n        pass\n",
        },
    )
    assert [(f.rule_id, f.qualname) for f in _run(ctx)] == [("PY-WL-104", "m.f")]


def test_silent_handler_in_undecorated_is_suppressed(tmp_path) -> None:
    ctx, _ = _analyze(
        tmp_path,
        {
            "m.py": "def f():\n    try:\n        g()\n    except ValueError:\n        pass\n",
        },
    )
    assert _run(ctx) == []


def test_handled_exception_is_clean(tmp_path) -> None:
    ctx, _ = _analyze(
        tmp_path,
        {
            "m.py": "from wardline.decorators import trusted\n"
            "@trusted\ndef f():\n    try:\n        g()\n    except ValueError:\n        log()\n",
        },
    )
    assert _run(ctx) == []


def test_reraise_is_clean(tmp_path) -> None:
    ctx, _ = _analyze(
        tmp_path,
        {
            "m.py": "from wardline.decorators import trusted\n"
            "@trusted\ndef f():\n    try:\n        g()\n    except ValueError:\n        raise\n",
        },
    )
    assert _run(ctx) == []
