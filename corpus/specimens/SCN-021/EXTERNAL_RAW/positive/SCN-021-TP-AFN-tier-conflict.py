"""SCN-021 adversarial false negative: contradictory pair via star import aliasing."""
from wardline.decorators import external_boundary, integral_read


@external_boundary
@integral_read
def fetch_record(record_id: str) -> dict:
    return {"id": record_id}
