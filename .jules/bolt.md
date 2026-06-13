## 2026-06-13 - Fast AST Traversal
**Learning:** In hot-path AST traversal, deep `yield from` recursion and repeated `isinstance()` checks create measurable overhead (especially generator frame creation). AST node classes are final (not subclassed), meaning `type(node) is ast.X` is perfectly safe and much faster.
**Action:** When writing utilities that traverse the entire AST (like `iter_calls_in_function_body`), use `type() is` checks and eager list-appending (`out.append`) instead of `yield from`. Cast the result to an iterator if needed to maintain API compatibility.
