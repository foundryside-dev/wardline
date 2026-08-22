## 2026-08-22 - Lazy Iterator Consumption in AST Traversal
**Learning:** Passing `ast.iter_child_nodes()` directly into generic AST traversal functions that accept `Iterable[ast.AST]` (instead of eagerly materializing them with `list(ast.iter_child_nodes())`) eliminates unnecessary memory allocations per AST node and speeds up recursive walks.
**Action:** When implementing or modifying AST traversal functions, ensure they accept `Iterable[ast.AST]` rather than `list[ast.AST]`, and avoid wrapping generators in `list()` unless multi-pass traversal or length checks are strictly required.
