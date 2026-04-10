def audit_broad_cached_profile():
    try:
        risky()
    except Exception:
        logger.error("failed")
