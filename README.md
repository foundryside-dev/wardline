# Wardline

Wardline is a generic, lightweight semantic-tainting static analyzer for Python. It tracks the flow of untrusted data through a codebase, identifies trust-boundary violations, and emits structured findings — without requiring runtime instrumentation. Wardline is part of the Loom suite alongside Clarion (code intelligence) and Filigree (issue tracking). To use the scanner CLI, install the extra dependencies with `pip install wardline[scanner]`.
