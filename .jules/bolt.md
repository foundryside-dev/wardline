## 2024-05-18 - Avoid eager materialization of AST child nodes
**Learning:** Eagerly materializing iterators like `ast.iter_child_nodes()` into lists (e.g., `list(ast.iter_child_nodes(node))`) during recursive AST traversal causes unnecessary memory allocations and performance overhead, especially in deep or complex ASTs.
**Action:** When implementing or modifying AST traversal functions, type them to accept `collections.abc.Iterable[ast.AST]` and pass generators directly to avoid unnecessary list creation.
