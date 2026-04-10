def process():
    try:
        risky()
    except Exception:
        logger.error("failed")
