from wardline.decorators import not_reentrant

@not_reentrant
def process(data):
    return data.upper()
