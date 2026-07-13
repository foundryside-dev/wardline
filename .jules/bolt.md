## 2024-06-12 - Explicit Stack Traversals Avoid Recursion Overheads

**Learning:** `yield from` recursion incurs high frame overhead for deep or voluminous AST traversals, typically seen in hot-path static analysis functions. Iterative logic maintaining an explicit stack drastically cuts execution time by saving stack frame creations while preserving order through reversed child appending.
**Action:** When implementing new or refactoring existing AST traversal rules in generic semantic-tainting static analyzers like Wardline, prefer a `while stack:` construct combined with direct `yield` for memory and speed efficiency.
