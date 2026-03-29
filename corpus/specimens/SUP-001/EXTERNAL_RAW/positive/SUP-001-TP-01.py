"""SUP-001 true positive: @deterministic function calls random.random()."""
import random

from wardline.decorators import deterministic


@deterministic
def pick_value() -> float:
    return random.random()
