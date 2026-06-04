"""sampleapp — a tiny in-memory library catalog.

Deliberately small, with cross-module structure (models <- repository <- service
<- cli) so it works as a corpus for Clarion's entity/edge extraction and has a
single untrusted-input boundary in cli for Wardline.
"""

__all__ = ["models", "repository", "service", "cli"]
