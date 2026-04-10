def audit_broad_claimed_token():
    try:
        risky()
    except Exception:
        logger.error("failed")
