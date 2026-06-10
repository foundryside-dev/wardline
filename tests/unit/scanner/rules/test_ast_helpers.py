from __future__ import annotations

import ast
import textwrap

from wardline.scanner.index import discover_file_entities
from wardline.scanner.rules._ast_helpers import (
    asserts_are_sole_rejection,
    block_has_real_rejection,
    has_real_rejection,
    has_rejection_path,
    is_broad_except,
    is_degenerate_boundary,
    is_silent_handler,
    own_except_handlers,
    rejecting_helper_calls,
)


def _fn(src: str) -> ast.FunctionDef:
    return ast.parse(textwrap.dedent(src)).body[0]  # type: ignore[return-value]


def test_has_rejection_path_detects_raise_and_falsy_returns() -> None:
    assert has_rejection_path(_fn("def f(p):\n if not p:\n  raise ValueError\n return p\n"))
    assert has_rejection_path(_fn("def f(p):\n if not p:\n  return None\n return p\n"))
    assert has_rejection_path(_fn("def f(p):\n if not p:\n  return False\n return p\n"))
    assert has_rejection_path(_fn("def f(p):\n if not p:\n  return\n return p\n"))
    assert has_rejection_path(_fn("def f(p):\n if not p:\n  return []\n return p\n"))
    # assert counts as a rejection path (it DOES reject at runtime) — so PY-WL-102
    # does not fire on an assert-only boundary; PY-WL-111 owns that case instead.
    assert has_rejection_path(_fn("def f(p):\n assert p\n return p\n"))
    # no rejection: always returns the (possibly raw) input
    assert not has_rejection_path(_fn("def f(p):\n return p\n"))
    assert not has_rejection_path(_fn("def f(p):\n x = p\n return x\n"))


def test_asserts_are_sole_rejection() -> None:
    # only an assert -> True (PY-WL-111's case)
    assert asserts_are_sole_rejection(_fn("def f(p):\n assert p\n return p\n"))
    # a real raise present -> False (a real reject exists)
    assert not asserts_are_sole_rejection(_fn("def f(p):\n assert p\n if not p:\n  raise ValueError\n return p\n"))
    # a falsy-constant return present -> False
    assert not asserts_are_sole_rejection(_fn("def f(p):\n assert p\n if not p:\n  return None\n return p\n"))
    # no assert at all -> False
    assert not asserts_are_sole_rejection(_fn("def f(p):\n return p\n"))


def test_has_rejection_path_sees_conditional_expression_falsy_branch() -> None:
    # `return m.group(0) if m else None` is the ternary form of the recognised
    # `if not m: return None` rejection — semantically identical, must count.
    assert has_rejection_path(_fn("def f(p):\n m = check(p)\n return m.group(0) if m else None\n"))
    assert has_rejection_path(_fn("def f(p):\n return p if ok(p) else False\n"))
    # nested ternary: a falsy branch anywhere in the conditional tree counts
    assert has_rejection_path(_fn("def f(p):\n return (a if x else None) if c else b\n"))
    # a ternary with NO falsy branch is not a rejection
    assert not has_rejection_path(_fn("def f(p):\n return a if c else b\n"))


def test_has_rejection_path_curated_raising_conversion_returns() -> None:
    # Curated validate-by-construction shapes: the conversion/lookup raises on
    # every invalid input (ValueError / KeyError), so the boundary CAN reject.
    assert has_rejection_path(_fn("def f(p):\n return int(p)\n"))
    assert has_rejection_path(_fn("def f(p):\n return float(p)\n"))
    assert has_rejection_path(_fn("def f(p):\n return Decimal(p)\n"))
    assert has_rejection_path(_fn("def f(p):\n return decimal.Decimal(p)\n"))
    assert has_rejection_path(_fn("def f(p):\n return uuid.UUID(p)\n"))
    # Enum subscript and mapping/allowlist subscript lookup raise KeyError
    assert has_rejection_path(_fn("def f(p):\n return Color[p]\n"))
    assert has_rejection_path(_fn("def f(p):\n return ALLOWED[p]\n"))


def test_raising_conversion_set_is_curated_not_arbitrary() -> None:
    # SOUNDNESS: an arbitrary call is NOT a rejection (that would be an FN hole).
    assert not has_rejection_path(_fn("def f(p):\n return frobnicate(p)\n"))
    # str()/bool() never reject; not in the curated set
    assert not has_rejection_path(_fn("def f(p):\n return str(p)\n"))
    # a conversion of nothing / of a constant validates nothing
    assert not has_rejection_path(_fn("def f(p):\n return int()\n"))
    assert not has_rejection_path(_fn("def f(p):\n return int('5')\n"))
    # a constant subscript is positional access, not a validating lookup
    assert not has_rejection_path(_fn("def f(p):\n return parts[0]\n"))


def test_asserts_are_sole_rejection_sees_extended_rejection_returns() -> None:
    # A raising-conversion or ternary-falsy return is a REAL (non-assert) rejection,
    # so the assert is not the sole rejection -> PY-WL-111 stays silent.
    assert not asserts_are_sole_rejection(_fn("def f(p):\n assert p\n return int(p)\n"))
    assert not asserts_are_sole_rejection(_fn("def f(p):\n assert p\n m = c(p)\n return m.g() if m else None\n"))


def test_has_real_rejection_excludes_assert() -> None:
    # has_real_rejection is the production-surviving predicate: assert alone is NOT real.
    assert not has_real_rejection(_fn("def f(p):\n assert p\n return p\n"))
    assert has_real_rejection(_fn("def f(p):\n if not p:\n  raise ValueError\n return p\n"))
    assert has_real_rejection(_fn("def f(p):\n if not p:\n  return None\n return p\n"))
    assert not has_real_rejection(_fn("def f(p):\n return p\n"))


def _entities(src: str):
    tree = ast.parse(textwrap.dedent(src))
    ents = discover_file_entities(tree, module="m", path="m.py")
    return {e.qualname: e for e in ents}


def test_rejecting_helper_calls_one_hop_lexical_fallback() -> None:
    ents = _entities(
        """
        def _require_nonempty(p):
            if not p:
                raise ValueError("empty")
        def v(p):
            _require_nonempty(p)
            return p
        """
    )
    calls = rejecting_helper_calls(ents["m.v"], ents, {})
    assert len(calls) == 1


def test_rejecting_helper_calls_staticmethod_helper() -> None:
    ents = _entities(
        """
        class Validators:
            @staticmethod
            def require(p):
                if not p:
                    raise ValueError("empty")
        def v(p):
            Validators.require(p)
            return p
        """
    )
    assert len(rejecting_helper_calls(ents["m.v"], ents, {})) == 1


def test_rejecting_helper_calls_rejects_non_raising_helper() -> None:
    # SOUNDNESS GUARD: a helper that cannot raise (logs and returns) is NOT a rejection.
    ents = _entities(
        """
        def _log(p):
            print(p)
            return p
        def v(p):
            _log(p)
            return p
        """
    )
    assert rejecting_helper_calls(ents["m.v"], ents, {}) == frozenset()


def test_rejecting_helper_calls_assert_only_helper_does_not_count() -> None:
    # A helper whose only rejection is assert vanishes under -O just like an inline
    # assert; it is not a REAL one-hop rejection (keeps the 102/111 partition honest).
    ents = _entities(
        """
        def _check(p):
            assert p
        def v(p):
            _check(p)
            return p
        """
    )
    assert rejecting_helper_calls(ents["m.v"], ents, {}) == frozenset()


def test_rejecting_helper_calls_is_same_module_only() -> None:
    # One-hop SAME-MODULE only: a resolved cross-module callee does not count.
    ents_m = _entities("def v(p):\n    helper(p)\n    return p\n")
    other = _entities("def helper(p):\n    if not p:\n        raise ValueError\n")
    # graft the foreign entity (different path) into the lookup table under the
    # qualname the resolver would report
    tree = ast.parse("def helper(p):\n    if not p:\n        raise ValueError\n")
    foreign = discover_file_entities(tree, module="n", path="n.py")[0]
    entities = {**ents_m, foreign.qualname: foreign}
    call = next(n for n in ast.walk(ents_m["m.v"].node) if isinstance(n, ast.Call))
    assert rejecting_helper_calls(ents_m["m.v"], entities, {id(call): "n.helper"}) == frozenset()
    assert other  # silence unused warning


def test_block_has_real_rejection_scans_statement_lists() -> None:
    fn = _fn(
        """
        def f(p):
            try:
                if not p:
                    raise ValueError
            except ValueError:
                return p
        """
    )
    try_stmt = fn.body[0]
    assert isinstance(try_stmt, ast.Try)
    assert block_has_real_rejection(try_stmt.body)
    assert not block_has_real_rejection(try_stmt.handlers[0].body)


def test_is_degenerate_boundary_shapes() -> None:
    assert is_degenerate_boundary(_fn("def f(p):\n return p\n"))
    assert is_degenerate_boundary(_fn("def f(p):\n 'doc'\n return p\n"))
    assert not is_degenerate_boundary(_fn("def f(p):\n x = p\n return x\n"))
    assert not is_degenerate_boundary(_fn("def f(p):\n return g(p)\n"))


def test_own_except_handlers_skips_nested_functions() -> None:
    fn = _fn(
        "def f():\n"
        "    try:\n        a()\n    except ValueError:\n        pass\n"
        "    def g():\n"
        "        try:\n            b()\n        except KeyError:\n            pass\n"
    )
    handlers = list(own_except_handlers(fn))
    assert len(handlers) == 1
    assert isinstance(handlers[0].type, ast.Name) and handlers[0].type.id == "ValueError"


def test_is_broad_except() -> None:
    def handler(src: str) -> ast.ExceptHandler:
        fn = _fn("def f():\n try:\n  a()\n" + src)
        return next(own_except_handlers(fn))

    assert is_broad_except(handler(" except:\n  pass\n"))  # bare
    assert is_broad_except(handler(" except Exception:\n  pass\n"))
    assert is_broad_except(handler(" except BaseException:\n  pass\n"))
    assert not is_broad_except(handler(" except ValueError:\n  pass\n"))
    assert not is_broad_except(handler(" except (KeyError, IndexError):\n  pass\n"))
    # a tuple CONTAINING a broad name is just as broad as `except Exception`
    assert is_broad_except(handler(" except (Exception, OSError):\n  pass\n"))
    assert is_broad_except(handler(" except (ValueError, BaseException):\n  pass\n"))


def test_is_silent_handler() -> None:
    def handler(body: str) -> ast.ExceptHandler:
        fn = _fn("def f():\n try:\n  a()\n except Exception:\n" + body)
        return next(own_except_handlers(fn))

    assert is_silent_handler(handler("  pass\n"))
    assert is_silent_handler(handler("  ...\n"))
    assert is_silent_handler(handler("  continue\n"))
    assert is_silent_handler(handler("  'ignored'\n"))
    assert is_silent_handler(handler("  123\n"))
    assert not is_silent_handler(handler("  raise\n"))
    assert not is_silent_handler(handler("  log(e)\n"))
    assert not is_silent_handler(handler("  return None\n"))
