def getattr_no_default_claimed_token(claimed_token):
    x = getattr(claimed_token, "name")
