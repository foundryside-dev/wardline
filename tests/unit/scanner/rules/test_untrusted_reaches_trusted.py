from __future__ import annotations

import textwrap
from pathlib import Path

from wardline.core.config import WardlineConfig
from wardline.core.finding import Kind
from wardline.scanner.analyzer import WardlineAnalyzer
from wardline.scanner.rules.untrusted_reaches_trusted import UntrustedReachesTrusted


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


def _run(ctx) -> list:
    return UntrustedReachesTrusted().check(ctx)


def test_trusted_returning_raw_fires(tmp_path) -> None:
    ctx, _ = _analyze(tmp_path, {
        "io.py": "from wardline.decorators import external_boundary\n"
                 "@external_boundary\ndef read_raw(p):\n    return p\n",
        "svc.py": "from wardline.decorators import trusted\n"
                  "from io import read_raw\n"
                  "@trusted\ndef leaky(p):\n    return read_raw(p)\n",
    })
    findings = _run(ctx)
    ids = {(f.rule_id, f.qualname) for f in findings}
    assert ("PY-WL-101", "svc.leaky") in ids
    assert all(f.kind == Kind.DEFECT for f in findings)


def test_trusted_returning_validated_is_clean(tmp_path) -> None:
    # @trusted(ASSURED) returning a @trust_boundary(ASSURED) result == declared; no fire.
    ctx, _ = _analyze(tmp_path, {
        "io.py": "from wardline.decorators import external_boundary, trust_boundary\n"
                 "@external_boundary\ndef read_raw(p):\n    return p\n"
                 "@trust_boundary(to_level='ASSURED')\n"
                 "def validate(p):\n    if not p:\n        raise ValueError\n    return p\n",
        "svc.py": "from wardline.decorators import trusted\n"
                  "from io import read_raw, validate\n"
                  "@trusted(level='ASSURED')\ndef safe(p):\n    return validate(read_raw(p))\n",
    })
    assert _run(ctx) == []


def test_external_boundary_returning_raw_is_gated_out(tmp_path) -> None:
    # @external_boundary's declared return is EXTERNAL_RAW (raw zone) -> trust-claim
    # gate excludes it even though it returns raw data. (Idiomatic boundary code.)
    ctx, _ = _analyze(tmp_path, {
        "io.py": "from wardline.decorators import external_boundary\n"
                 "@external_boundary\ndef handler(p):\n    return p\n",
    })
    assert _run(ctx) == []


def test_undecorated_is_silent(tmp_path) -> None:
    ctx, _ = _analyze(tmp_path, {"m.py": "def f(p):\n    return p\n"})
    assert _run(ctx) == []


def test_trusted_returning_constant_is_clean(tmp_path) -> None:
    ctx, _ = _analyze(tmp_path, {
        "m.py": "from wardline.decorators import trusted\n@trusted\ndef f():\n    return 1\n",
    })
    assert _run(ctx) == []


def test_trusted_leaking_raw_via_except_handler_fires(tmp_path) -> None:
    # Regression (under-taint): a @trusted function that leaks raw only through an
    # except handler. The handler's return must be collected, or PY-WL-101 stays
    # silent on a real leak.
    ctx, _ = _analyze(tmp_path, {
        "io.py": "from wardline.decorators import external_boundary\n"
                 "@external_boundary\ndef read_raw(p):\n    return p\n",
        "svc.py": "from wardline.decorators import trusted\nfrom io import read_raw\n"
                  "@trusted\ndef leaky(p):\n    try:\n        return 1\n"
                  "    except ValueError:\n        return read_raw(p)\n",
    })
    assert ("PY-WL-101", "svc.leaky") in {(f.rule_id, f.qualname) for f in _run(ctx)}


def test_trusted_leaking_raw_via_match_arm_fires(tmp_path) -> None:
    # Regression (under-taint): leak reachable only through a match arm.
    ctx, _ = _analyze(tmp_path, {
        "io.py": "from wardline.decorators import external_boundary\n"
                 "@external_boundary\ndef read_raw(p):\n    return p\n",
        "svc.py": "from wardline.decorators import trusted\nfrom io import read_raw\n"
                  "@trusted\ndef leaky(p):\n    match p:\n        case 1:\n"
                  "            return read_raw(p)\n        case _:\n            return 1\n",
    })
    assert ("PY-WL-101", "svc.leaky") in {(f.rule_id, f.qualname) for f in _run(ctx)}


def test_correct_trust_boundary_does_not_fire_101(tmp_path) -> None:
    # Regression pin for the @trust_boundary exemption: a CORRECT validator (raise
    # guard + return) seeds its params at the raw body taint and the engine cannot
    # narrow taint after the raise, so its actual L2 return is EXTERNAL_RAW < its
    # declared ASSURED. WITHOUT the trust-raising-transition exemption this would
    # false-positive PY-WL-101 on every @trust_boundary. It must fire NEITHER
    # PY-WL-101 (exempt -> 102's domain) NOR PY-WL-102 (it HAS a rejection path).
    from wardline.scanner.rules.boundary_without_rejection import BoundaryWithoutRejection

    ctx, _ = _analyze(tmp_path, {
        "m.py": "from wardline.decorators import trust_boundary\n"
                "@trust_boundary(to_level='ASSURED')\n"
                "def validate(p):\n    if not p:\n        raise ValueError\n    return p\n",
    })
    # Sanity: the engine produces the shape that WOULD trip an unexempted PY-WL-101.
    from wardline.core.taints import TRUST_RANK
    body = ctx.project_taints["m.validate"]
    declared = ctx.project_return_taints["m.validate"]
    actual = ctx.function_return_taints["m.validate"]
    assert TRUST_RANK[actual] > TRUST_RANK[declared]      # would-fire condition holds
    assert TRUST_RANK[body] > TRUST_RANK[declared]        # ...but it's a trust-raising transition
    # Exemption holds: no PY-WL-101, and 102 is satisfied by the raise guard.
    assert _run(ctx) == []
    assert BoundaryWithoutRejection().check(ctx) == []
