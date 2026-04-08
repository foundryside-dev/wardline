"""SUP-001 adversarial false negative: uuid call hidden in nested expression."""
import uuid

from wardline.decorators import deterministic


@deterministic
def generate_key(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"
