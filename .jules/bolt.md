## 2025-02-18 - Avoid yield from for AST traversal
**Learning:** `yield from` recursion is very slow in Python and becomes a bottleneck in hot paths (like walking an AST to find nodes). Generator state machine overhead adds up. Using an iterative stack-based approach with an eagerly populated list is over 20-30% faster for AST tree traversal.
**Action:** Use list accumulation or stack-based iteration (reversing children before pushing) instead of recursive `yield from` when scanning ASTs in `wardline`.
