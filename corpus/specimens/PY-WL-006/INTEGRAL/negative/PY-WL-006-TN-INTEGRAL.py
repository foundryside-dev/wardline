def audit_specific_system_config():
    try:
        risky()
    except ValueError:
        logger.error("failed")
