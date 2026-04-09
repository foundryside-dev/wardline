from wardline.decorators import handles_secrets

@handles_secrets
def store_credential(password, target):
    hashed = hashlib.sha256(password.encode()).hexdigest()
    db.save(target, hashed)
