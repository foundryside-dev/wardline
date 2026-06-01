from __future__ import annotations

import textwrap
from pathlib import Path

from wardline.core.config import WardlineConfig
from wardline.core.finding import Kind, Severity
from wardline.scanner.analyzer import WardlineAnalyzer
from wardline.scanner.rules.broad_exception import BroadException


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
    return BroadException().check(ctx)


def test_broad_except_in_trusted_fires_at_base(tmp_path) -> None:
    ctx, _ = _analyze(
        tmp_path,
        {
            "m.py": "from wardline.decorators import trusted\n"
            "@trusted\ndef f():\n    try:\n        g()\n    except Exception:\n        h()\n",
        },
    )
    findings = _run(ctx)
    assert [(f.rule_id, f.qualname) for f in findings] == [("PY-WL-103", "m.f")]
    assert findings[0].kind == Kind.DEFECT
    assert findings[0].severity == Severity.WARN  # base for PY-WL-103, trusted tier -> unchanged


def test_broad_except_in_undecorated_is_suppressed(tmp_path) -> None:
    # Undecorated -> UNKNOWN_RAW (freedom zone) -> modulate to NONE -> no finding.
    ctx, _ = _analyze(
        tmp_path,
        {
            "m.py": "def f():\n    try:\n        g()\n    except Exception:\n        h()\n",
        },
    )
    assert _run(ctx) == []


def test_bare_except_fires(tmp_path) -> None:
    ctx, _ = _analyze(
        tmp_path,
        {
            "m.py": "from wardline.decorators import trusted\n"
            "@trusted\ndef f():\n    try:\n        g()\n    except:\n        h()\n",
        },
    )
    assert [f.rule_id for f in _run(ctx)] == ["PY-WL-103"]


def test_specific_except_is_clean(tmp_path) -> None:
    ctx, _ = _analyze(
        tmp_path,
        {
            "m.py": "from wardline.decorators import trusted\n"
            "@trusted\ndef f():\n    try:\n        g()\n    except ValueError:\n        h()\n",
        },
    )
    assert _run(ctx) == []


def test_tuple_containing_broad_name_fires(tmp_path) -> None:
    # `except (Exception, OSError)` is just as broad as `except Exception`.
    ctx, _ = _analyze(
        tmp_path,
        {
            "m.py": "from wardline.decorators import trusted\n"
            "@trusted\ndef f():\n    try:\n        g()\n"
            "    except (Exception, OSError):\n        h()\n",
        },
    )
    assert [f.rule_id for f in _run(ctx)] == ["PY-WL-103"]


def test_specific_tuple_is_clean(tmp_path) -> None:
    ctx, _ = _analyze(
        tmp_path,
        {
            "m.py": "from wardline.decorators import trusted\n"
            "@trusted\ndef f():\n    try:\n        g()\n"
            "    except (KeyError, IndexError):\n        h()\n",
        },
    )
    assert _run(ctx) == []
