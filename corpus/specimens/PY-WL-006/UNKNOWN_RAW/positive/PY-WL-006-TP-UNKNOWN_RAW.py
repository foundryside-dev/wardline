def audit_broad_unknown_input():
    try:
        risky()
    except Exception:
        logger.error("failed")
