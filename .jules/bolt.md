## 2026-06-04 - [AST Traversal Optimization]
**Learning:** [For hot-path AST traversal, using eager list-appending (`list.append()`) and `type() is` checks is significantly faster than using `yield from` recursion and `isinstance()`, providing a ~1.4x speedup.]
**Action:** [Use `type() is ast.NodeType` (and `# type: ignore[attr-defined]` where needed) instead of `isinstance()` for hot-path AST nodes, and return an iterator from a pre-allocated list rather than building a deep generator stack with `yield from`.]
