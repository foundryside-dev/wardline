## 2024-06-18 - AST Traversal Performance
**Learning:** For hot-path AST traversal, eager list-appending (`list.append()`) is consistently faster than `yield from` recursion.
**Action:** Use list-appending instead of `yield from` for AST traversal to improve performance.
