from wardline import schema_default


def ungoverned_schema_default(data):
    return schema_default(data.get("key", ""))
