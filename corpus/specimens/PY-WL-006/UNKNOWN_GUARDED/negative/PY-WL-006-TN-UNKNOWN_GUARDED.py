def audit_specific_cached_profile():
    try:
        risky()
    except ValueError:
        logger.error("failed")
