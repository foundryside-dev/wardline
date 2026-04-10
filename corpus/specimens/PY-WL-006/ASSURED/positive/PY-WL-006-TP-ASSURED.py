def audit_broad_verified_payload():
    try:
        risky()
    except Exception:
        logger.error("failed")
