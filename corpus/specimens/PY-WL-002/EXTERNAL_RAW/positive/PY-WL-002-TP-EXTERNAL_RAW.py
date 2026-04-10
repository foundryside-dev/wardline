def getattr_default_request_param(request_param):
    x = getattr(request_param, "name", None)
