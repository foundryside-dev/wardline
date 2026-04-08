def validate_and_transform(data):
    """@idempotent + @deterministic looks contradictory but is valid."""
    from wardline.decorators import deterministic, idempotent

    @idempotent
    @deterministic
    def normalize(value: str) -> str:
        return value.strip().lower()

    return normalize(data)
