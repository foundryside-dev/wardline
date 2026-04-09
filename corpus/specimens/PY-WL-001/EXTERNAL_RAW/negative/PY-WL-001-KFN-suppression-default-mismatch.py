from wardline import schema_default

def process(data):
    return schema_default(data.get("key", "UNKNOWN"))
