## 2024-05-24 - Initial
## 2024-05-24 - Removing Eager `list()` Materializations in AST Traversals
**Learning:** Eagerly materializing generators like `ast.iter_child_nodes()` or node lists like `func_node.body` into a new `list()` before passing them to traversal functions causes unnecessary memory allocations and overhead, especially in deep ASTs.
**Action:** When implementing or modifying AST traversal functions, type the parameter to accept `Iterable[ast.AST]` (or similar) instead of `list`, and pass the generators directly. This avoids the materialization cost while maintaining the exact same traversal behavior.
