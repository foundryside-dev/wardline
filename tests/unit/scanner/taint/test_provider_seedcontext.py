# tests/unit/scanner/taint/test_provider_seedcontext.py
from __future__ import annotations

import pytest

from wardline.core.run import run_scan
from wardline.scanner.marker_reader import ModuleCensus
from wardline.scanner.taint.provider import SeedContext


def test_seedcontext_defaults_to_empty_alias_map() -> None:
    ctx = SeedContext(module="m")
    assert ctx.module == "m"
    assert dict(ctx.alias_map) == {}


def test_seedcontext_carries_alias_map() -> None:
    ctx = SeedContext(module="m", alias_map={"t": "wardline.decorators.trusted"})
    assert ctx.alias_map["t"] == "wardline.decorators.trusted"


def test_seedcontext_is_frozen() -> None:
    ctx = SeedContext(module="m")
    with pytest.raises(AttributeError):
        ctx.module = "other"  # type: ignore[misc]


def test_seed_context_census_defaults_to_the_absent_sentinel() -> None:
    # The default MUST be ``None`` — the ABSENT sentinel — and NOT an empty
    # ``ModuleCensus``. Spec §4.2.1 forbids the defaulted-empty census precisely
    # because it converts a plumbing hole into an ordinary unreadable, silently, on
    # every module: asked to resolve a bare ``Name`` in a builtin LEVEL slot, the
    # shared reader RAISES on an absent census (loud, gate-eligible) and returns a
    # quiet ``None`` on an empty one.
    ctx = SeedContext(module="m")
    assert ctx.census is None
    assert not isinstance(ctx.census, ModuleCensus)


_POISON_SRC = (
    "from unknown_pkg import *\n"
    "from wardline.decorators import trusted\n"
    "_LEVEL = 'ASURED'\n"
    "@trusted(level=_LEVEL)\n"
    "def f(p):\n"
    "    return p\n"
)


def test_both_readers_see_the_same_star_import_poison(tmp_path) -> None:
    # THE CROSS-READER POISON ASSERTION. A module whose top-level star import cannot
    # be materialised is form-5 poisoned: ``build_import_alias_map`` skipped that
    # import, so the star may silently supply a ``_LEVEL`` the census cannot see.
    # ONE census carries the predicate to both readers; neither RE-DERIVES it.
    #
    # The discriminating half at this commit is the RULE side. ``_LEVEL`` resolves to
    # the invalid token ``'ASURED'`` — so without the poison PY-WL-114 fires (pinned
    # by the contrast scan below), and with it the rule must go silent. Read the
    # ``declared_qualnames`` line for what it is: the provider does not resolve form 5
    # until the seeding task, so today it is a NO-REGRESSION assertion rather than
    # evidence of provider-side poison handling. Both readers are asserted together on
    # one scan by ``test_form5_agreement`` in the task that owns it.
    (tmp_path / "svc.py").write_text(_POISON_SRC, encoding="utf-8")
    result = run_scan(tmp_path)
    assert result.context is not None
    census = result.context.module_censuses["svc"]
    assert census.poisoned is True
    assert [f.rule_id for f in result.findings if f.rule_id == "PY-WL-114"] == []
    assert "svc.f" not in result.context.declared_qualnames


def test_the_same_module_without_the_star_import_does_fire(tmp_path) -> None:
    # THE CONTRAST that makes the poison assertion above discriminating: the identical
    # module minus the unresolvable star import is NOT poisoned, form 5 resolves, and
    # the invalid token reaches PY-WL-114.
    (tmp_path / "svc.py").write_text(_POISON_SRC.replace("from unknown_pkg import *\n", ""), encoding="utf-8")
    result = run_scan(tmp_path)
    assert result.context is not None
    assert result.context.module_censuses["svc"].poisoned is False
    assert [f.qualname for f in result.findings if f.rule_id == "PY-WL-114"] == ["svc.f"]
