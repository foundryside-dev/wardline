from __future__ import annotations

import textwrap
from pathlib import Path

from wardline.core.config import WardlineConfig
from wardline.core.finding import Kind
from wardline.scanner.analyzer import WardlineAnalyzer
from wardline.scanner.rules.boundary_without_rejection import BoundaryWithoutRejection


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
    return BoundaryWithoutRejection().check(ctx)


def test_boundary_without_rejection_fires(tmp_path) -> None:
    # @trust_boundary that launders its input through a local — cannot reject -> DEFECT.
    # (The bare single-statement `return p` shape is PY-WL-119's domain now; 102 owns
    # every OTHER no-rejection shape.)
    ctx, _ = _analyze(
        tmp_path,
        {
            "m.py": "from wardline.decorators import trust_boundary\n"
            "@trust_boundary(to_level='ASSURED')\ndef v(p):\n    x = p\n    return x\n",
        },
    )
    findings = _run(ctx)
    assert [(f.rule_id, f.qualname) for f in findings] == [("PY-WL-102", "m.v")]
    assert findings[0].kind == Kind.DEFECT


def test_degenerate_shape_is_119s_domain_102_suppressed(tmp_path) -> None:
    # Suppress-and-delegate: the bare degenerate boundary (`return p`) is PY-WL-119's
    # finding; 102 must NOT double-fire on it (wardline-718048a518 four-way partition).
    ctx, findings = _analyze(
        tmp_path,
        {
            "m.py": "from wardline.decorators import trust_boundary\n"
            "@trust_boundary(to_level='ASSURED')\ndef v(p):\n    return p\n",
        },
    )
    assert _run(ctx) == []
    assert [(f.rule_id, f.qualname) for f in findings if f.rule_id == "PY-WL-119"] == [("PY-WL-119", "m.v")]


def test_boundary_with_raise_is_clean(tmp_path) -> None:
    ctx, _ = _analyze(
        tmp_path,
        {
            "m.py": "from wardline.decorators import trust_boundary\n"
            "@trust_boundary(to_level='ASSURED')\n"
            "def v(p):\n    if not p:\n        raise ValueError\n    return p\n",
        },
    )
    assert _run(ctx) == []


def test_unreachable_raise_does_not_rescue_boundary(tmp_path) -> None:
    ctx, _ = _analyze(
        tmp_path,
        {
            "m.py": "from wardline.decorators import trust_boundary\n"
            "@trust_boundary(to_level='ASSURED')\n"
            "def v(p):\n    x = p\n    return x\n    raise ValueError\n",
        },
    )
    assert [(f.rule_id, f.qualname) for f in _run(ctx)] == [("PY-WL-102", "m.v")]


def test_boundary_with_falsy_return_is_clean(tmp_path) -> None:
    ctx, _ = _analyze(
        tmp_path,
        {
            "m.py": "from wardline.decorators import trust_boundary\n"
            "@trust_boundary(to_level='GUARDED')\n"
            "def v(p):\n    if not p:\n        return None\n    return p\n",
        },
    )
    assert _run(ctx) == []


def test_non_boundary_decorators_are_ignored(tmp_path) -> None:
    # @trusted (body == return, not a trust-raising transition) and @external_boundary
    # are NOT trust boundaries -> never flagged by PY-WL-102.
    ctx, _ = _analyze(
        tmp_path,
        {
            "m.py": "from wardline.decorators import trusted, external_boundary\n"
            "@trusted\ndef a():\n    return 1\n"
            "@external_boundary\ndef b(p):\n    return p\n",
        },
    )
    assert _run(ctx) == []


def test_undecorated_is_silent(tmp_path) -> None:
    ctx, _ = _analyze(tmp_path, {"m.py": "def v(p):\n    return p\n"})
    assert _run(ctx) == []


# ── One-hop same-module helper rejection (boundary.json FP 1) ────────────────


def test_boundary_rejecting_via_same_module_raising_helper_is_clean(tmp_path) -> None:
    ctx, _ = _analyze(
        tmp_path,
        {
            "m.py": "from wardline.decorators import trust_boundary\n"
            "def _require_nonempty(p):\n    if not p:\n        raise ValueError('empty')\n"
            "@trust_boundary(to_level='ASSURED')\ndef v(p):\n    _require_nonempty(p)\n    return p\n",
        },
    )
    assert _run(ctx) == []


def test_unreachable_rejecting_helper_does_not_rescue_boundary(tmp_path) -> None:
    ctx, _ = _analyze(
        tmp_path,
        {
            "m.py": "from wardline.decorators import trust_boundary\n"
            "def _require_nonempty(p):\n    if not p:\n        raise ValueError('empty')\n"
            "@trust_boundary(to_level='ASSURED')\n"
            "def v(p):\n    x = p\n    return x\n    _require_nonempty(p)\n",
        },
    )
    assert [(f.rule_id, f.qualname) for f in _run(ctx)] == [("PY-WL-102", "m.v")]


def test_boundary_rejecting_via_staticmethod_helper_is_clean(tmp_path) -> None:
    ctx, _ = _analyze(
        tmp_path,
        {
            "m.py": "from wardline.decorators import trust_boundary\n"
            "class Validators:\n"
            "    @staticmethod\n"
            "    def require(p):\n        if not p:\n            raise ValueError('empty')\n"
            "@trust_boundary(to_level='ASSURED')\ndef v(p):\n    Validators.require(p)\n    return p\n",
        },
    )
    assert _run(ctx) == []


def test_boundary_delegating_to_raising_boundary_is_clean(tmp_path) -> None:
    # Wholesale delegation to another declared boundary that itself raises.
    ctx, _ = _analyze(
        tmp_path,
        {
            "m.py": "from wardline.decorators import trust_boundary\n"
            "@trust_boundary(to_level='ASSURED')\n"
            "def inner(p):\n    if not p:\n        raise ValueError\n    return p\n"
            "@trust_boundary(to_level='ASSURED')\ndef v(p):\n    return inner(p)\n",
        },
    )
    assert _run(ctx) == []


def test_non_raising_helper_does_not_count_as_rejection(tmp_path) -> None:
    # SOUNDNESS GUARD: a helper that logs and returns cannot reject — 102 still fires.
    ctx, _ = _analyze(
        tmp_path,
        {
            "m.py": "from wardline.decorators import trust_boundary\n"
            "def _log(p):\n    print(p)\n    return p\n"
            "@trust_boundary(to_level='ASSURED')\ndef v(p):\n    _log(p)\n    return p\n",
        },
    )
    assert [(f.rule_id, f.qualname) for f in _run(ctx)] == [("PY-WL-102", "m.v")]


def test_cross_module_raising_helper_does_not_count(tmp_path) -> None:
    # One-hop is SAME-MODULE only (cheap + conservative): a cross-module raising
    # helper does not silence the rule.
    ctx, _ = _analyze(
        tmp_path,
        {
            "helpers.py": "def require(p):\n    if not p:\n        raise ValueError\n",
            "m.py": "from wardline.decorators import trust_boundary\n"
            "from helpers import require\n"
            "@trust_boundary(to_level='ASSURED')\ndef v(p):\n    require(p)\n    return p\n",
        },
    )
    assert [(f.rule_id, f.qualname) for f in _run(ctx)] == [("PY-WL-102", "m.v")]


def test_unresolvable_call_does_not_count_as_rejection(tmp_path) -> None:
    ctx, _ = _analyze(
        tmp_path,
        {
            "m.py": "from wardline.decorators import trust_boundary\n"
            "@trust_boundary(to_level='ASSURED')\ndef v(p):\n    frobnicate(p)\n    return p\n",
        },
    )
    assert [(f.rule_id, f.qualname) for f in _run(ctx)] == [("PY-WL-102", "m.v")]


# ── Conditional-expression and raising-conversion returns (FPs 3 + 4) ───────


def test_ternary_falsy_return_is_clean(tmp_path) -> None:
    ctx, _ = _analyze(
        tmp_path,
        {
            "m.py": "import re\nfrom wardline.decorators import trust_boundary\n"
            "@trust_boundary(to_level='ASSURED')\ndef v(p):\n"
            "    m = re.fullmatch(r'[a-z]+', p)\n    return m.group(0) if m else None\n",
        },
    )
    assert _run(ctx) == []


def test_raising_conversion_returns_are_clean(tmp_path) -> None:
    ctx, _ = _analyze(
        tmp_path,
        {
            "m.py": "import enum\nfrom wardline.decorators import trust_boundary\n"
            "class Color(enum.Enum):\n    RED = 'red'\n"
            "ALLOWED = {'a': 1}\n"
            "@trust_boundary(to_level='ASSURED')\ndef to_port(p):\n    return int(p)\n"
            "@trust_boundary(to_level='ASSURED')\ndef to_color(p):\n    return Color[p]\n"
            "@trust_boundary(to_level='ASSURED')\ndef to_allowed(p):\n    return ALLOWED[p]\n",
        },
    )
    assert _run(ctx) == []


def test_arbitrary_call_return_still_fires(tmp_path) -> None:
    # SOUNDNESS GUARD: the raising-conversion set is curated — `return helper_obj(p)`
    # for an unknown callee is NOT a rejection.
    ctx, _ = _analyze(
        tmp_path,
        {
            "m.py": "from wardline.decorators import trust_boundary\n"
            "@trust_boundary(to_level='ASSURED')\ndef v(p):\n    x = str(p)\n    return str(x)\n",
        },
    )
    assert [(f.rule_id, f.qualname) for f in _run(ctx)] == [("PY-WL-102", "m.v")]
