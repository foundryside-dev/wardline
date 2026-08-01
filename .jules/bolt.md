## 2024-05-24 - AST Traversal Memory Overhead
**Learning:** Eagerly materializing lists during AST traversal (e.g., `list(ast.iter_child_nodes(node))`) causes significant memory overhead and unnecessary allocations for every visited node.
**Action:** Always accept `Iterable[ast.AST]` in AST traversal functions and pass generators (like `ast.iter_child_nodes()`) directly to avoid creating shallow copies.
