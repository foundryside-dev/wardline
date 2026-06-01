from __future__ import annotations

import ast
import textwrap

from wardline.scanner.rules._ast_helpers import (
    has_rejection_path,
    is_broad_except,
    is_silent_handler,
    own_except_handlers,
)


def _fn(src: str) -> ast.FunctionDef:
    return ast.parse(textwrap.dedent(src)).body[0]  # type: ignore[return-value]


def test_has_rejection_path_detects_raise_and_falsy_returns() -> None:
    assert has_rejection_path(_fn("def f(p):\n if not p:\n  raise ValueError\n return p\n"))
    assert has_rejection_path(_fn("def f(p):\n if not p:\n  return None\n return p\n"))
    assert has_rejection_path(_fn("def f(p):\n if not p:\n  return False\n return p\n"))
    assert has_rejection_path(_fn("def f(p):\n if not p:\n  return\n return p\n"))
    assert has_rejection_path(_fn("def f(p):\n if not p:\n  return []\n return p\n"))
    # no rejection: always returns the (possibly raw) input
    assert not has_rejection_path(_fn("def f(p):\n return p\n"))
    assert not has_rejection_path(_fn("def f(p):\n x = p\n return x\n"))


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
    assert not is_silent_handler(handler("  raise\n"))
    assert not is_silent_handler(handler("  log(e)\n"))
    assert not is_silent_handler(handler("  return None\n"))
