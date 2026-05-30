# Wardline

Wardline is a generic, lightweight semantic-tainting static analyzer for Python. It tracks the flow of untrusted data through a codebase, identifies trust-boundary violations, and emits structured findings — without requiring runtime instrumentation. Wardline is part of the Loom suite alongside Clarion (code intelligence) and Filigree (issue tracking). To use the scanner CLI, install the extra dependencies with `pip install wardline[scanner]`.

## Documentation

Full documentation — getting started, concepts, configuration, the LLM triage
judge, Loom integration, and using Wardline with your coding agent — lives at
**<https://foundryside-dev.github.io/wardline/>**.
