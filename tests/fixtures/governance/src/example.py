# schema_version: 1.0
from wardline.decorators import external_boundary, integral_read, validates_shape


@external_boundary
def fetch_data(url: str) -> dict:
    return {}


@validates_shape
def check_schema(data: dict) -> bool:
    if not isinstance(data, dict):
        raise ValueError("not a dict")
    return True


@integral_read
def get_config() -> dict:
    return {"key": "value"}
