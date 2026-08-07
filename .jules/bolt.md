## 2024-05-24 - Avoid eager materialization of AST nodes
**Learning:** When implementing or modifying AST traversal functions, eager materialization of generators (like `ast.iter_child_nodes()`) into lists causes unnecessary memory allocations and overhead.
**Action:** Accept `Iterable[ast.AST]` in traversal function signatures and pass generators directly instead of eagerly materializing them into lists to prevent unnecessary memory allocations.
