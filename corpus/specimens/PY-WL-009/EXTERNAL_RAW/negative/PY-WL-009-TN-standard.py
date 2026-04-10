from wardline.decorators import validates_semantic

@validates_semantic
def validate_order(data):
    if not isinstance(data, dict):
        raise TypeError("expected dict")
    if data["amount"] > 1000:
        raise ValueError("amount exceeds limit")
    return data
