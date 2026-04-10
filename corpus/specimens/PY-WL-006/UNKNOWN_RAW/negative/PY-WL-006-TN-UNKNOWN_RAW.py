def audit_specific_unknown_input():
    try:
        risky()
    except ValueError:
        logger.error("failed")
