def process(data):
    result = validate(data)
    if not result:
        raise ValueError("invalid")
