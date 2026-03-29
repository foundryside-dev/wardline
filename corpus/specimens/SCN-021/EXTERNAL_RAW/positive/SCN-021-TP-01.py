"""SCN-021 true positive: @fail_open + @fail_closed is contradictory."""
from wardline.decorators import fail_closed, fail_open


@fail_open
@fail_closed
def fetch_config(key: str) -> str:
    return key
