def audit_broad_mixed_source():
    try:
        risky()
    except Exception:
        logger.error("failed")
