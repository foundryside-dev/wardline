## 2024-08-08 - Optimized ast traversal in taint tracker
**Learning:** In ast traversal functions within the taint tracker (e.g. `variable_level.py`), converting generator yields like `ast.iter_child_nodes` to lists eagerly uses unnecessary memory allocations, which can add up significantly during large ast analysis passes.
**Action:** Always accept `Iterable[ast.AST]` instead of `list[ast.AST]` in AST traversal helper functions and pass generators directly to avoid eager materialization.
