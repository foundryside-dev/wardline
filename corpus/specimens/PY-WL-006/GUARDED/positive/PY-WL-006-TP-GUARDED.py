def audit_broad_session_data():
    try:
        risky()
    except Exception:
        logger.error("failed")
