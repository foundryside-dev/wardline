from wardline.decorators import validates_shape

@validates_shape
def validate(data):
    if not isinstance(data, dict):
        raise TypeError("expected dict")
