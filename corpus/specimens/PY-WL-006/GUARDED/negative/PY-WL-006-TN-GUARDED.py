def audit_specific_session_data():
    try:
        risky()
    except ValueError:
        logger.error("failed")
