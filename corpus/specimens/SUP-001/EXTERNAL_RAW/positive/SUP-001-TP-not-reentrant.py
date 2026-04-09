from wardline.decorators import not_reentrant

@not_reentrant
def process(data):
    if data:
        process(data[1:])
