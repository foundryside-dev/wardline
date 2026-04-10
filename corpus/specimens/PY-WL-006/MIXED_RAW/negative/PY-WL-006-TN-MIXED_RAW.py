def audit_specific_mixed_source():
    try:
        risky()
    except ValueError:
        logger.error("failed")
