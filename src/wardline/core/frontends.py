# src/wardline/core/frontends.py
"""Language frontend registry for ``run_scan``.

A ``LanguageFrontend`` encapsulates every language-specific concern that
``run_scan`` previously hardcoded inline:

- which file suffixes to discover (``.py`` / ``.rs`` / …)
- how to construct the language-specific ``Analyzer``

Adding a third language requires only:

1. Write a class implementing ``LanguageFrontend``.
2. Add it to ``FRONTENDS``.

``run_scan`` itself never changes.

Lazy imports
------------
Neither ``PythonFrontend`` nor ``RustFrontend`` import their analyzer packages
at module load time.  All heavyweight imports happen inside ``build_analyzer``
so that ``import wardline.core.frontends`` remains cheap and does not pull in
``wardline.scanner`` or ``wardline.rust`` eagerly.  This preserves the layering
posture that ``run.py`` already had (function-local lazy imports).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from wardline.core.config import WardlineConfig
    from wardline.core.protocols import Analyzer
    from wardline.scanner.taint.summary_cache import SummaryCache


@runtime_checkable
class LanguageFrontend(Protocol):
    """Plug-point for a language-specific scan frontend.

    ``name`` is the canonical key in ``FRONTENDS`` and the value callers
    pass as ``run_scan(lang=...)``.

    ``suffixes`` is the set of file extensions (including the leading dot,
    e.g. ``".py"``) that ``discover`` should collect for this language.

    ``build_analyzer`` constructs a fresh ``Analyzer`` instance.  The two
    parameters are those that vary per scan and are meaningful for the
    language; implementors may safely ignore parameters they do not need
    (e.g. ``RustFrontend`` ignores both since ``RustAnalyzer()`` is
    zero-configuration).
    """

    name: str
    suffixes: frozenset[str]

    def build_analyzer(
        self,
        *,
        config: WardlineConfig,
        summary_cache: SummaryCache | None,
    ) -> Analyzer: ...


class PythonFrontend:
    """The released Python frontend — grammar + build_analyzer encapsulated."""

    name = "python"
    suffixes: frozenset[str] = frozenset({".py"})

    def build_analyzer(
        self,
        *,
        config: WardlineConfig,
        summary_cache: SummaryCache | None,
    ) -> Analyzer:
        from wardline.core.errors import ConfigError
        from wardline.scanner.analyzer import build_analyzer
        from wardline.scanner.grammar import TrustGrammar, default_grammar

        grammar = default_grammar()
        for pack_name, pkg in config.pack_modules.items():
            pack_grammar = getattr(pkg, "grammar", None)
            if pack_grammar is not None:
                if not isinstance(pack_grammar, TrustGrammar):
                    raise ConfigError(f"pack {pack_name!r} attribute 'grammar' must be a TrustGrammar instance")
                grammar = grammar.extend(
                    boundary_types=pack_grammar.boundary_types,
                    rules=pack_grammar.rules,
                )
        return build_analyzer(grammar=grammar, summary_cache=summary_cache)


class RustFrontend:
    """The preview Rust frontend — routes to ``RustAnalyzer``."""

    name = "rust"
    suffixes: frozenset[str] = frozenset({".rs"})

    def build_analyzer(
        self,
        *,
        config: WardlineConfig,
        summary_cache: SummaryCache | None,
    ) -> Analyzer:
        from wardline.rust.analyzer import RustAnalyzer

        return RustAnalyzer()


#: Registry of supported language frontends, keyed by ``lang`` name.
#:
#: To register a third language::
#:
#:     from wardline.core.frontends import FRONTENDS, LanguageFrontend
#:
#:     class GoFrontend:
#:         name = "go"
#:         suffixes: frozenset[str] = frozenset({".go"})
#:
#:         def build_analyzer(self, *, config, summary_cache):
#:             from wardline.go.analyzer import GoAnalyzer
#:             return GoAnalyzer()
#:
#:     FRONTENDS["go"] = GoFrontend()
FRONTENDS: dict[str, LanguageFrontend] = {
    "python": PythonFrontend(),
    "rust": RustFrontend(),
}
