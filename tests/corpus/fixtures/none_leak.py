# Corpus fixtures for PY-WL-109 (None leaks from a trusted producer).
from wardline.decorators import trusted


@trusted(level="ASSURED")
def maybe_none(flag) -> int:  # TP: -> int promises non-None, but a path returns None
    if flag:
        return 1
    return


@trusted(level="ASSURED")
def declared_optional(flag) -> int | None:  # clean: nullable contract is declared
    if flag:
        return 1
    return None


@trusted(level="ASSURED")
def always_value(flag) -> int:  # clean: every path returns a value
    if flag:
        return 1
    return 2
