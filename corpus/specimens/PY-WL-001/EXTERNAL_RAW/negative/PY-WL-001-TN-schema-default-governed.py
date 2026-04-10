from wardline import schema_default


def governed_schema_default(data):
    return schema_default(data.get("key", ""))
