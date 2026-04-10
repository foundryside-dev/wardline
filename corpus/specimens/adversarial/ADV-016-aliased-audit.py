def process():
    writer = audit_ledger.record
    try:
        risky()
    except Exception:
        writer(event)
