def process():
    try:
        risky()
    except Exception:
        audit.record("failed")
