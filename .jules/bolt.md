## 2025-01-01 - Avoid Eager Materialization of AST Generators
**Learning:** Eagerly materializing AST node generators like `ast.iter_child_nodes()` into lists before passing them to recursive traversal functions (like `_collect_return_paths`) causes unnecessary memory allocations and overhead, especially in deep AST trees.
**Action:** When implementing or modifying AST traversal functions, accept `Iterable[ast.AST]` and pass generators directly to avoid creating temporary lists.
