## 2026-06-11 - AST Traversal Recursion Overhead
**Learning:** `yield from` recursion over AST nodes (`ast.iter_child_nodes`) adds significant generator delegation overhead on deep trees in this codebase, increasing runtime significantly.
**Action:** Use an explicit stack populated via `node._fields` (pushed in reverse order) combined with `yield` instead of `yield from`. This maintains the exact execution order and lazy evaluation while removing the deep call stack and generator proxy overhead.
