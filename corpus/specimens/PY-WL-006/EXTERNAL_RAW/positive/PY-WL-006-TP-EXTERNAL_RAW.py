def audit_broad_request_param():
    try:
        risky()
    except Exception:
        logger.error("failed")
