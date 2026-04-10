def audit_specific_claimed_token():
    try:
        risky()
    except ValueError:
        logger.error("failed")
