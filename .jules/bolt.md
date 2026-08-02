## 2026-08-02 - Prevent Unnecessary Memory Allocation in AST Traversals
**Learning:** Eagerly materializing generators into lists (e.g., `list(ast.iter_child_nodes(node))`) before passing them to traversal functions causes unnecessary memory allocation overhead, especially in deep or wide AST trees where generators would suffice.
**Action:** When implementing or modifying AST traversal functions, accept `Iterable[ast.AST]` and pass generators directly to avoid memory overhead.
