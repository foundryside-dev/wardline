from wardline.decorators import requires_identity

@requires_identity
def audit_action(data):
    return data
