# Corpus fixtures for PY-WL-109 (None leaks from a trusted producer).
from wardline.decorators import trusted


@trusted(level="ASSURED")
def maybe_none(flag):  # TP: value path + bare return -> None leaks from a trusted producer
    if flag:
        return 1
    return


@trusted(level="ASSURED")
def always_value(flag):  # clean: every path returns a value (no None leak)
    if flag:
        return 1
    return 2
