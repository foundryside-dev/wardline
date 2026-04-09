from wardline.decorators import handles_secrets

@handles_secrets
def store_credential(password, target):
    print(password)
