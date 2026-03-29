"""SUP-001 true negative: @deterministic on a pure function with no non-deterministic calls."""
from wardline.decorators import deterministic


@deterministic
def add(x: int, y: int) -> int:
    return x + y
