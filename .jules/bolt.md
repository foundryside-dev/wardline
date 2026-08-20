## 2024-08-20 - Avoid eagerly materializing generators in AST traversal
**Learning:** In AST traversal functions, accepting `list[ast.AST]` and passing materialized generators (e.g. `list(ast.iter_child_nodes(node))`) forces unnecessary list allocations and iterations, which causes a performance bottleneck and wastes memory, especially on deep or large ASTs.
**Action:** Change the signature of AST traversal functions to accept `Iterable[ast.AST]` and pass the generators directly (e.g. `ast.iter_child_nodes(node)`) without eagerly materializing them.
