## 2024-06-05 - Avoid Eager List Materialization in AST Traversals
**Learning:** The AST traversal functions in `wardline` (like `_assignment_callee` and `_collect_return_paths`) were eagerly materializing generator outputs (`ast.iter_child_nodes()`) into lists. This causes unnecessary memory allocations and overhead, especially on deep or large ASTs.
**Action:** When implementing or modifying AST traversal functions, accept `Iterable[ast.AST]` and pass generators directly instead of eagerly materializing them into lists to prevent unnecessary memory allocations.
