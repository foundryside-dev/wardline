def specific_convert_request_param(request_param):
    try:
        x = int(request_param)
    except ValueError:
        x = 0
