def kfn_dict_default_get_default(request_param):
    x = request_param.get("key", "default")
