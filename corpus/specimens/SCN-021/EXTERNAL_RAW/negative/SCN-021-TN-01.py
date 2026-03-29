"""SCN-021 true negative: @not_reentrant + @idempotent is a valid combination."""
from wardline.decorators import idempotent, not_reentrant


@not_reentrant
@idempotent
def publish_event(event_type: str) -> None:
    pass
