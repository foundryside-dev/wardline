def merge_configs(trusted, untrusted):
    """Merging trusted and untrusted dicts contaminates the result."""
    merged = {**trusted, **untrusted}
    timeout = merged.get("timeout", 60)
    return timeout
