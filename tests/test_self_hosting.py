import pytest


@pytest.mark.xfail(reason="no rules until SP2; Wardline cannot yet scan itself", strict=True)
def test_wardline_scans_itself_clean() -> None:
    # SP2 flips this on: run wardline's own rules over src/wardline and assert 0 findings.
    raise AssertionError("self-hosting not implemented until SP2")
