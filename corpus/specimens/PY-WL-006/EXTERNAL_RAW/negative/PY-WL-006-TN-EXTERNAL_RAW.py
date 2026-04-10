def audit_specific_request_param():
    try:
        risky()
    except ValueError:
        logger.error("failed")
