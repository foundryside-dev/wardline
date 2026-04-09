from wardline.decorators import atomic

@atomic
def safe_update(item):
    db.save(item)
