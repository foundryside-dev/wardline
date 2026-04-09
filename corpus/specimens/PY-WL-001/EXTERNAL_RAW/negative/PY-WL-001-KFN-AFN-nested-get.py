def extract_config(raw_input):
    """Default hidden in chained call — scanner must still detect .get(k, default)."""
    config = raw_input.get("settings", {}).get("timeout", 30)
    return config
