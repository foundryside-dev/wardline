def process():
    try:
        risky()
    except Exception:
        try:
            audit_ledger.record("failed")
        finally:
            pass
