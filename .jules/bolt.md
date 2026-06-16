## 2024-06-16 - Replace yield from with iterative append in hot-path AST traversals
**Learning:** In heavily used AST traversal functions like `iter_calls_in_function_body` and `_own_statements`, using `yield from` recursively and `isinstance()` checks creates measurable overhead.
**Action:** For hot-path AST traversals, use an internal walk function that builds a `list` with `.append()`, and replace `isinstance(child, ast.X)` with `type(child) is ast.X` (using `# type: ignore` where required). Convert the final list to an iterator if the API expects one.
