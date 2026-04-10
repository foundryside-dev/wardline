def specific_convert_unknown_input(unknown_input):
    try:
        x = int(unknown_input)
    except ValueError:
        x = 0
