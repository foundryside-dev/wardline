def audit_broad_system_config():
    try:
        risky()
    except Exception:
        logger.error("failed")
