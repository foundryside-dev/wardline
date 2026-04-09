from wardline import schema_default

def apply_default(data):
    """schema_default without any overlay or boundary declaration."""
    return schema_default(data.get("region", "us-east-1"))
