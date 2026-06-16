from __future__ import annotations

import textwrap
from pathlib import Path

from wardline.core.config import WardlineConfig
from wardline.core.finding import Kind, Severity
from wardline.scanner.analyzer import WardlineAnalyzer
from wardline.scanner.rules.untrusted_to_trusted_callee import UntrustedReachesTrustedCallee

_HEADER = (
    "from wardline.decorators import external_boundary, trusted\n"
    "@external_boundary\ndef read_raw(p):\n    return p\n"
    "@trusted(level='ASSURED')\ndef store(x):\n    return 1\n"
)


def _analyze(tmp_path: Path, src: str):
    p = tmp_path / "m.py"
    p.write_text(_HEADER + textwrap.dedent(src), encoding="utf-8")
    analyzer = WardlineAnalyzer()
    analyzer.analyze([p], WardlineConfig(), root=tmp_path)
    assert analyzer.last_context is not None
    return analyzer.last_context


def _ids(ctx):
    return [(f.rule_id, f.qualname) for f in UntrustedReachesTrustedCallee().check(ctx)]


def test_external_raw_arg_to_trusted_callee_fires(tmp_path) -> None:
    ctx = _analyze(
        tmp_path,
        """
        def h(p):
            store(read_raw(p))
        """,
    )
    findings = UntrustedReachesTrustedCallee().check(ctx)
    assert [(f.rule_id, f.qualname) for f in findings] == [("PY-WL-105", "m.h")]
    assert findings[0].kind == Kind.DEFECT
    assert findings[0].severity == Severity.ERROR
    assert findings[0].properties["callee"] == "m.store"


def test_unknown_raw_arg_does_not_fire(tmp_path) -> None:
    # An undecorated param (UNKNOWN_RAW) is merely unprovable, not provably untrusted.
    ctx = _analyze(
        tmp_path,
        """
        def h(p):
            store(p)
        """,
    )
    assert _ids(ctx) == []


def test_validated_through_undecorated_does_not_fire(tmp_path) -> None:
    ctx = _analyze(
        tmp_path,
        """
        def validate(x):
            return x
        def h(p):
            store(validate(read_raw(p)))
        """,
    )
    assert _ids(ctx) == []


def test_untrusted_to_undecorated_callee_does_not_fire(tmp_path) -> None:
    # Callee is not a trust-declared producer -> no opt-in -> no finding.
    ctx = _analyze(
        tmp_path,
        """
        def plain(x):
            return x
        def h(p):
            plain(read_raw(p))
        """,
    )
    assert _ids(ctx) == []


def test_external_boundary_callee_is_not_a_sink(tmp_path) -> None:
    # Passing raw to an @external_boundary (a source, raw body) is expected -> no fire.
    ctx = _analyze(
        tmp_path,
        """
        def h(p):
            read_raw(read_raw(p))
        """,
    )
    assert _ids(ctx) == []


def test_self_method_call_fires(tmp_path) -> None:
    # Sibling method call (self.store) should resolve and trigger PY-WL-105.
    ctx = _analyze(
        tmp_path,
        """
        class Service:
            @trusted(level='ASSURED')
            def store(self, x):
                return 1
            
            def run(self, p):
                self.store(read_raw(p))
        """,
    )
    findings = UntrustedReachesTrustedCallee().check(ctx)
    assert [(f.rule_id, f.qualname) for f in findings] == [("PY-WL-105", "m.Service.run")]
    assert findings[0].properties["callee"] == "m.Service.store"


def test_args_unpacking_fires(tmp_path) -> None:
    ctx = _analyze(
        tmp_path,
        """
        def h(p):
            args = [read_raw(p)]
            store(*args)
        """,
    )
    assert _ids(ctx) == [("PY-WL-105", "m.h")]


def test_kwargs_unpacking_fires(tmp_path) -> None:
    ctx = _analyze(
        tmp_path,
        """
        def h(p):
            kwargs = {"x": read_raw(p)}
            store(**kwargs)
        """,
    )
    assert _ids(ctx) == [("PY-WL-105", "m.h")]


def test_provably_untrusted_arg_not_masked_by_unknown_co_arg(tmp_path) -> None:
    # A provably-untrusted arg (EXTERNAL_RAW, rank 5) must fire even when an
    # UNKNOWN_RAW co-arg (rank 6) bumps worst_arg_taint into the predicate's hole.
    # _PROVABLY_UNTRUSTED = {EXTERNAL_RAW=5, MIXED_RAW=7} is NOT upward-closed.
    ctx = _analyze(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def store2(meta, payload):
            return 1
        def h(meta, p):
            store2(meta, read_raw(p))
        """,
    )
    assert _ids(ctx) == [("PY-WL-105", "m.h")]


def test_multiple_kwargs_unpacking_combines_raw_before_clean(tmp_path) -> None:
    ctx = _analyze(
        tmp_path,
        """
        def h(p):
            raw_kwargs = {"x": read_raw(p)}
            clean_kwargs = {"x": 1}
            store(**raw_kwargs, **clean_kwargs)
        """,
    )
    assert _ids(ctx) == [("PY-WL-105", "m.h")]


def _branch_dispatch(first: str, second: str, arg: str = "raw") -> str:
    classes = (
        "class Plain:\n    def take(self, x):\n        return 1\n"
        "class TrustedSink:\n    @trusted(level='ASSURED')\n    def take(self, x):\n        return 1\n"
    )
    return classes + textwrap.dedent(
        f"""
        def dispatch(flag, p):
            raw = read_raw(p)
            if flag:
                o = {first}
            else:
                o = {second}
            o.take({arg})
        """
    )


def test_branch_conditional_trusted_receiver_fires_regardless_of_ast_order(tmp_path) -> None:
    # wardline-499c22bbdd: o is assigned a trusted-sink class in one branch and a plain
    # class in the other; PY-WL-105 must fire on the trusted-sink candidate regardless of
    # which branch is textually LAST (root cause: local_var_types last-write-wins dropped
    # the non-last candidate).
    ctx1 = _analyze(tmp_path, _branch_dispatch("TrustedSink()", "Plain()"))  # trusted FIRST (regressed FN)
    assert _ids(ctx1) == [("PY-WL-105", "m.dispatch")]
    ctx2 = _analyze(tmp_path, _branch_dispatch("Plain()", "TrustedSink()"))  # trusted LAST (already fired)
    assert _ids(ctx2) == [("PY-WL-105", "m.dispatch")]


def test_branch_conditional_neither_trusted_stays_silent(tmp_path) -> None:
    # CONTROL: two candidate receivers, neither a trusted sink -> must stay silent.
    ctx = _analyze(
        tmp_path,
        """
        class Plain:
            def take(self, x):
                return 1
        class Plain2:
            def take(self, x):
                return 1
        def dispatch(flag, p):
            raw = read_raw(p)
            if flag:
                o = Plain()
            else:
                o = Plain2()
            o.take(raw)
        """,
    )
    assert _ids(ctx) == []


def test_branch_conditional_trusted_receiver_non_raw_arg_stays_silent(tmp_path) -> None:
    # CONTROL (arg gate): a real trusted candidate, but the arg is a non-raw literal ->
    # the candidate-set widening must still respect the _PROVABLY_UNTRUSTED arg gate.
    ctx = _analyze(tmp_path, _branch_dispatch("TrustedSink()", "Plain()", arg="'literal'"))
    assert _ids(ctx) == []


def test_branch_conditional_linear_reassignment_stays_silent(tmp_path) -> None:
    # CONTROL (panel FP, wardline-499c22bbdd): a straight-line reassignment o=TS(); o=Plain()
    # is NOT a branch fork — o is provably Plain at the call. Flow-sensitive resolution must
    # NOT widen to the killed TrustedSink binding, so PY-WL-105 stays silent.
    ctx = _analyze(
        tmp_path,
        """
        class Plain:
            def take(self, x):
                return 1
        class TrustedSink:
            @trusted(level='ASSURED')
            def take(self, x):
                return 1
        def f(p):
            raw = read_raw(p)
            o = TrustedSink()
            o = Plain()
            o.take(raw)
        """,
    )
    assert _ids(ctx) == []


def test_branch_conditional_in_arm_call_uses_arm_local_type(tmp_path) -> None:
    # CONTROL (panel FP): a call INSIDE the arm where o is assigned Plain sees only Plain —
    # the other arm's TrustedSink does not reach this call site. Must stay silent.
    ctx = _analyze(
        tmp_path,
        """
        class Plain:
            def take(self, x):
                return 1
        class TrustedSink:
            @trusted(level='ASSURED')
            def take(self, x):
                return 1
        def f(flag, p):
            raw = read_raw(p)
            if flag:
                o = Plain()
                o.take(raw)
            else:
                o = TrustedSink()
                o.take(0)
        """,
    )
    assert _ids(ctx) == []


def test_branch_conditional_two_trusted_candidates_emits_one_finding(tmp_path) -> None:
    # panel (double-emit): when BOTH arms are trusted sinks, one taint flow at one call
    # site is ONE defect — emit a single finding (deterministic representative), not one
    # per candidate.
    ctx = _analyze(
        tmp_path,
        """
        class A:
            @trusted(level='ASSURED')
            def take(self, x):
                return 1
        class B:
            @trusted(level='ASSURED')
            def take(self, x):
                return 1
        def f(flag, p):
            raw = read_raw(p)
            if flag:
                o = A()
            else:
                o = B()
            o.take(raw)
        """,
    )
    findings = UntrustedReachesTrustedCallee().check(ctx)
    assert [(f.rule_id, f.qualname) for f in findings] == [("PY-WL-105", "m.f")]
    assert "also reaches" in findings[0].message


def test_branch_conditional_loop_carried_receiver_rebind_fires(tmp_path) -> None:
    # panel-2 (wardline-499c22bbdd): a receiver rebound at the END of a loop body is the
    # runtime dispatch target for the call at the TOP of the body from iteration 2 on. The
    # candidate pass's loop fixpoint must surface the rebound TrustedSink so the call fires.
    ctx = _analyze(
        tmp_path,
        """
        class Plain:
            def take(self, x):
                return 1
        class TrustedSink:
            @trusted(level='ASSURED')
            def take(self, x):
                return 1
        def f(items, p):
            raw = read_raw(p)
            o = Plain()
            for it in items:
                o.take(raw)
                o = TrustedSink()
        """,
    )
    assert _ids(ctx) == [("PY-WL-105", "m.f")]


def test_branch_conditional_walrus_rebind_kills_stale_candidate(tmp_path) -> None:
    # panel-2 (wardline-499c22bbdd): a walrus rebind (o := Plain()) must REPLACE the prior
    # TrustedSink binding — o is provably Plain at the call, so PY-WL-105 must stay silent.
    ctx = _analyze(
        tmp_path,
        """
        class Plain:
            def take(self, x):
                return 1
        class TrustedSink:
            @trusted(level='ASSURED')
            def take(self, x):
                return 1
        def f(p):
            raw = read_raw(p)
            o = TrustedSink()
            if (o := Plain()):
                pass
            o.take(raw)
        """,
    )
    assert _ids(ctx) == []


def test_branch_conditional_loop_carried_deep_chain_fires(tmp_path) -> None:
    # panel-3 (wardline-499c22bbdd): the candidate-pass loop fixpoint backstop must be keyed
    # to COPY-CHAIN DEPTH (names assigned in the body), not the class count. A depth-3
    # rebind chain (d<-c<-b<-a=TrustedSink) carried across loop iterations must still surface
    # TrustedSink at the top-of-body d.take(raw) call. A class-count-keyed bound truncated
    # here (chain_depth >= class_count + 2) and silently dropped the sink — a fail-open FN.
    ctx = _analyze(
        tmp_path,
        """
        class Plain:
            def take(self, x):
                return 1
        class TrustedSink:
            @trusted(level='ASSURED')
            def take(self, x):
                return 1
        def f(items, p):
            raw = read_raw(p)
            a = TrustedSink()
            d = Plain()
            for x in items:
                d.take(raw)
                d = c
                c = b
                b = a
        """,
    )
    assert _ids(ctx) == [("PY-WL-105", "m.f")]


def test_branch_conditional_walrus_same_expression_eval_order(tmp_path) -> None:
    # panel-3 (wardline-499c22bbdd): a walrus rebind and a dispatch in the SAME expression —
    # `sink((o := Plain()), o.take(raw))`. Python evaluates left-to-right, so o is Plain by
    # the time o.take runs; the candidate pass must process the walrus bind before recording
    # the dispatch (traversal order matches eval order) — must stay silent.
    ctx = _analyze(
        tmp_path,
        """
        class Plain:
            def take(self, x):
                return 1
        class TrustedSink:
            @trusted(level='ASSURED')
            def take(self, x):
                return 1
        def sink(*a):
            return 1
        def f(p):
            raw = read_raw(p)
            o = TrustedSink()
            sink((o := Plain()), o.take(raw))
        """,
    )
    assert _ids(ctx) == []
