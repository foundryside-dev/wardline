## 2024-06-13 - Explicit Stack AST Traversal
**Learning:** Re-writing recursive generator-based AST traversal (`yield from walk_node`) to use an explicit iterative stack avoids Python function call overhead and generator delegation costs, resulting in ~25% speedup on hot-path operations like `iter_calls_in_function_body`.
**Action:** When working on hot-path AST parsers, replace `yield from` recursion with an explicit stack, reversing child nodes before extending the stack to preserve correct traversal order.
