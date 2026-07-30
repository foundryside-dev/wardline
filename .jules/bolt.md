## 2025-03-01 - Avoid eagerly materializing AST iterators in AST traversal functions
**Learning:** AST traversal functions that materialise iterators eagerly into lists increase memory usage unnecessarily in the analysis process.
**Action:** When working on AST traversal code, pass iterators directly to `Iterable` typing parameters, and use `ast.iter_child_nodes` directly instead of `list(ast.iter_child_nodes)`.
