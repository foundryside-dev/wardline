## 2026-06-11 - [Fast AST Iteration]
**Learning:** `ast.iter_child_nodes` is a major performance bottleneck for AST walking in Python because it relies on `ast.iter_fields`, which uses relatively slow string-based `getattr()` calls dynamically for every field.
**Action:** When walking massive AST trees, use a custom inline `fast_iter_child_nodes` generator that loops over `node._fields` directly, handling `AttributeError` instead of using the slower `iter_fields`.
