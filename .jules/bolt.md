## 2025-02-15 - Fast AST Call Traversal in Wardline
**Learning:** In highly recursive AST functions like `iter_calls_in_function_body`, avoiding `yield from` chains in favor of a flat list-based stack approach and direct `yield` yields significant speed-ups (up to 15% in deep trees) while maintaining exact iteration order via reversed pushes.
**Action:** Use list-based stack iteration instead of recursive `yield from` when implementing AST node generators to minimize frame and dispatch overhead in hot paths.
