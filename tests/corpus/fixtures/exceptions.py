"""Broad and silent exception handlers in trusted-tier functions. A broad `except
Exception` fires PY-WL-103; a silently-swallowed exception fires PY-WL-104. A
narrow, re-raising handler is clean."""

from wardline.decorators import trusted


def work():
    return 1


@trusted(level="INTEGRAL")
def broad_handler():  # TP: PY-WL-103 broad except in trusted tier
    try:
        return work()
    except Exception:
        return None


@trusted(level="INTEGRAL")
def silent_handler():  # TP: PY-WL-104 silently swallowed
    try:
        return work()
    except ValueError:
        pass
    return None


@trusted(level="INTEGRAL")
def narrow_logged():  # 103/104 CLEAN (narrow + re-raised); fires 101 (work() is UNKNOWN_RAW < INTEGRAL)
    try:
        return work()
    except ValueError as e:
        raise RuntimeError("wrapped") from e
