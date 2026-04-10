def audit_specific_verified_payload():
    try:
        risky()
    except ValueError:
        logger.error("failed")
