## 2025-02-23 - Explicit Stack AST Traversal
**Learning:** Recursive `yield from` in hot-path AST traversals introduces significant overhead. Precomputing reversed children via `node._fields` and using an explicit stack preserves traversal order and lazy evaluation while being faster.
**Action:** Use an explicit stack combined with `yield` and `reversed()` children list instead of `yield from` recursion for hot-path AST traversal.
