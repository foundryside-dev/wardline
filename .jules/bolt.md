## 2024-06-27 - AST Traversal Overhead
**Learning:** In deep/recursive AST traversal functions like `own_nodes`, standard `ast.iter_child_nodes` and `yield from` recursion introduces significant function-call overhead on the hot path.
**Action:** Use an explicit stack and iterate over `reversed(node._fields)` to maintain the exact `ast.iter_child_nodes` traversal order without the recursive overhead for performance-critical paths.
