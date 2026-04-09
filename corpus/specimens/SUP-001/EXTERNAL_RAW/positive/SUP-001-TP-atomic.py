from wardline.decorators import atomic

@atomic
def batch_update(items):
    db.save(items[0])
    db.delete(items[1])
