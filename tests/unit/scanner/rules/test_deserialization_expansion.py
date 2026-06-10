"""PY-WL-106 deserialization sink-family expansion (ticket wardline-4299f07bb4).

Covers the three expansion axes plus the declared-sink test gap:
  * OO streaming-unpickle API: ``pickle.Unpickler(raw).load()`` — chained AND
    stored-instance form, resolved through the shared sink-binding machinery;
    the dangerous data is the stream handed to the CONSTRUCTOR, so taint is
    read from the constructor call's arguments.
  * ``shelve.open`` — pickle-backed; the taint is on the PATH argument
    (ArgSpec ``positions=(0,)`` / ``keywords=("filename",)``), so a tainted
    non-path slot does not fire.
  * Curated third-party CWE-502 table (name-matched at AST level — the modules
    are never imported by the analyzer): dill.load/loads, jsonpickle.decode,
    joblib.load, torch.load, numpy.load. numpy.load fires ONLY with a literal
    ``allow_pickle=True`` (safe-by-default since numpy 1.16.3); torch.load is
    suppressed by a literal ``weights_only=True`` (the modern safe spelling).
  * Every entry in the rule's ``_SINKS`` gets at least one positive test
    (closes the yaml/marshal/pickle.load mutation-survival gap), with a
    completeness pin so a future sink addition forces a test.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from wardline.core.config import WardlineConfig
from wardline.core.finding import Kind, Severity
from wardline.scanner.analyzer import WardlineAnalyzer
from wardline.scanner.rules.untrusted_to_deserialization import _SINKS, UntrustedToDeserialization

# The analyzed module is parsed, never executed — third-party imports need not be installed.
_HEADER = (
    "import pickle, marshal, shelve, yaml\n"
    "import dill, jsonpickle, joblib, torch, numpy\n"
    "from wardline.decorators import external_boundary, trusted\n"
    "@external_boundary\n"
    "def read_raw(p):\n"
    "    return p\n"
)


def _analyze(tmp_path: Path, src: str):
    p = tmp_path / "m.py"
    p.write_text(_HEADER + textwrap.dedent(src), encoding="utf-8")
    analyzer = WardlineAnalyzer()
    analyzer.analyze([p], WardlineConfig(), root=tmp_path)
    assert analyzer.last_context is not None
    return analyzer.last_context


def _findings(tmp_path: Path, src: str):
    return UntrustedToDeserialization().check(_analyze(tmp_path, src))


# ── every declared sink has a positive (mutation-survival gap closure) ──────────────

# (canonical sink fqn, the tainted sink expression using raw var ``b``)
_POSITIVE_SINK_CALLS = [
    ("pickle.loads", "pickle.loads(b)"),
    ("pickle.load", "pickle.load(b)"),
    ("marshal.loads", "marshal.loads(b)"),
    ("marshal.load", "marshal.load(b)"),
    ("yaml.load", "yaml.load(b)"),
    ("yaml.load_all", "yaml.load_all(b)"),
    ("yaml.unsafe_load", "yaml.unsafe_load(b)"),
    ("yaml.full_load", "yaml.full_load(b)"),
    ("pickle.Unpickler.load", "pickle.Unpickler(b).load()"),
    ("shelve.open", "shelve.open(b)"),
    ("dill.load", "dill.load(b)"),
    ("dill.loads", "dill.loads(b)"),
    ("jsonpickle.decode", "jsonpickle.decode(b)"),
    ("joblib.load", "joblib.load(b)"),
    ("torch.load", "torch.load(b)"),
    ("numpy.load", "numpy.load(b, allow_pickle=True)"),
]


@pytest.mark.parametrize(("sink", "call"), _POSITIVE_SINK_CALLS, ids=[s for s, _ in _POSITIVE_SINK_CALLS])
def test_every_declared_sink_fires_on_raw(tmp_path: Path, sink: str, call: str) -> None:
    findings = _findings(
        tmp_path,
        f"""
        @trusted(level='ASSURED')
        def f(p):
            b = read_raw(p)
            {call}
        """,
    )
    assert [(x.rule_id, x.qualname, x.properties["sink"]) for x in findings] == [("PY-WL-106", "m.f", sink)]
    # RCE-equivalent sinks carry the rule family's base severity (tier-modulated).
    assert findings[0].severity == Severity.WARN
    assert findings[0].kind == Kind.DEFECT


def test_positive_table_covers_every_declared_sink() -> None:
    # Completeness pin: adding a sink to _SINKS without a positive test fails here.
    assert {sink for sink, _ in _POSITIVE_SINK_CALLS} == set(_SINKS)


# ── OO streaming-unpickle API (pickle.Unpickler) ─────────────────────────────────────


def test_unpickler_stored_instance_fires(tmp_path: Path) -> None:
    findings = _findings(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p):
            b = read_raw(p)
            u = pickle.Unpickler(b)
            return u.load()
        """,
    )
    assert [(x.rule_id, x.qualname, x.properties["sink"]) for x in findings] == [
        ("PY-WL-106", "m.f", "pickle.Unpickler.load")
    ]
    assert findings[0].properties["arg_taint"] == "EXTERNAL_RAW"


def test_unpickler_finding_anchors_on_the_load_call(tmp_path: Path) -> None:
    findings = _findings(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p):
            b = read_raw(p)
            u = pickle.Unpickler(b)
            return u.load()
        """,
    )
    # _HEADER is 6 lines + the snippet's leading blank line → u.load() is line 12,
    # NOT the constructor's line 11: the finding anchors on the sink METHOD call.
    assert [x.location.line_start for x in findings] == [12]


def test_unpickler_clean_literal_stream_is_silent(tmp_path: Path) -> None:
    findings = _findings(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p):
            return pickle.Unpickler('model.bin').load()
        """,
    )
    assert findings == []


def test_unpickler_import_alias_resolves(tmp_path: Path) -> None:
    findings = _findings(
        tmp_path,
        """
        import pickle as pk
        @trusted(level='ASSURED')
        def f(p):
            return pk.Unpickler(read_raw(p)).load()
        """,
    )
    assert [x.properties["sink"] for x in findings] == ["pickle.Unpickler.load"]


def test_unpickler_annotation_only_binding_is_a_bounded_fn(tmp_path: Path) -> None:
    # An annotation binds the class but carries no constructor call, so there is no
    # stream argument to read taint from — documented bounded false negative.
    findings = _findings(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(u: pickle.Unpickler):
            x: pickle.Unpickler = u
            return x.load()
        """,
    )
    assert findings == []


# ── shelve.open (taint on the path argument) ─────────────────────────────────────────


def test_shelve_open_tainted_path_fires(tmp_path: Path) -> None:
    findings = _findings(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(x):
            raw = read_raw(x)
            shelve.open(raw)
        """,
    )
    assert [(x.rule_id, x.properties["sink"]) for x in findings] == [("PY-WL-106", "shelve.open")]


def test_shelve_open_tainted_filename_keyword_fires(tmp_path: Path) -> None:
    findings = _findings(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(x):
            shelve.open(filename=read_raw(x))
        """,
    )
    assert [x.properties["sink"] for x in findings] == ["shelve.open"]


def test_shelve_open_tainted_non_path_slot_is_silent(tmp_path: Path) -> None:
    # ArgSpec precision: only the path slot is dangerous — a tainted flag is not.
    findings = _findings(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(x):
            shelve.open('app.db', read_raw(x))
        """,
    )
    assert findings == []


def test_shelve_open_as_context_manager_fires(tmp_path: Path) -> None:
    findings = _findings(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(x):
            with shelve.open(read_raw(x)) as db:
                return db['k']
        """,
    )
    assert [x.properties["sink"] for x in findings] == ["shelve.open"]


# ── curated third-party table ────────────────────────────────────────────────────────


def test_numpy_load_without_allow_pickle_is_silent(tmp_path: Path) -> None:
    # allow_pickle defaults to False (safe) in modern numpy — absent means safe.
    findings = _findings(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(x):
            numpy.load(read_raw(x))
        """,
    )
    assert findings == []


def test_numpy_load_allow_pickle_false_is_silent(tmp_path: Path) -> None:
    findings = _findings(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(x):
            numpy.load(read_raw(x), allow_pickle=False)
        """,
    )
    assert findings == []


def test_numpy_load_dynamic_allow_pickle_is_silent(tmp_path: Path) -> None:
    # Only the statically-visible literal True fires — a dynamic flag is a bounded FN.
    findings = _findings(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(x, flag):
            numpy.load(read_raw(x), allow_pickle=flag)
        """,
    )
    assert findings == []


def test_numpy_load_alias_with_allow_pickle_fires(tmp_path: Path) -> None:
    findings = _findings(
        tmp_path,
        """
        import numpy as np
        @trusted(level='ASSURED')
        def f(x):
            np.load(read_raw(x), allow_pickle=True)
        """,
    )
    assert [x.properties["sink"] for x in findings] == ["numpy.load"]


def test_torch_load_literal_weights_only_true_is_silent(tmp_path: Path) -> None:
    # The modern safe spelling: weights_only=True restricts the unpickler.
    findings = _findings(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(x):
            torch.load(read_raw(x), weights_only=True)
        """,
    )
    assert findings == []


def test_torch_load_weights_only_false_fires(tmp_path: Path) -> None:
    findings = _findings(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(x):
            torch.load(read_raw(x), weights_only=False)
        """,
    )
    assert [x.properties["sink"] for x in findings] == ["torch.load"]


def test_third_party_from_import_alias_resolves(tmp_path: Path) -> None:
    findings = _findings(
        tmp_path,
        """
        from dill import loads as dloads
        @trusted(level='ASSURED')
        def f(x):
            dloads(read_raw(x))
        """,
    )
    assert [x.properties["sink"] for x in findings] == ["dill.loads"]


def test_third_party_tainted_non_dangerous_slot_is_silent(tmp_path: Path) -> None:
    # ArgSpec precision: torch.load's map_location is not the dangerous slot.
    findings = _findings(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(x):
            torch.load('model.pt', map_location=read_raw(x))
        """,
    )
    assert findings == []


# ── tier discipline + multi-emit identity ────────────────────────────────────────────


def test_new_sinks_stay_silent_in_freedom_zone(tmp_path: Path) -> None:
    # Undecorated → UNKNOWN_RAW tier → modulate → NONE (opt-in preserved).
    findings = _findings(
        tmp_path,
        """
        def f(x):
            b = read_raw(x)
            torch.load(b)
            shelve.open(b)
            pickle.Unpickler(b).load()
        """,
    )
    assert findings == []


def test_co_located_sinks_get_distinct_fingerprints(tmp_path: Path) -> None:
    findings = _findings(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(x):
            b = read_raw(x)
            shelve.open(b); dill.loads(b)
        """,
    )
    assert sorted(x.properties["sink"] for x in findings) == ["dill.loads", "shelve.open"]
    assert len({x.fingerprint for x in findings}) == 2
