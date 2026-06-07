## 2026-06-07 - Python loop overhead in graph traversal
**Learning:** In highly connected graphs within a static analysis engine, looping over sets in Python (`for mod in callers: if mod not in closure: ...`) can introduce significant bytecode execution overhead.
**Action:** Replace Python loops checking membership with fast C-level set operations (e.g., `callers - closure`) and use list-based stacks instead of intermediate set constructions for graph frontiers. This avoids O(N) Python iteration in hot paths.
