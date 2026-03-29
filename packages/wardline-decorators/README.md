# wardline-decorators

Decorator library for [wardline](https://wardline.dev) semantic boundary annotations.

## Installation

```bash
pip install wardline-decorators
```

This package provides the `wardline.decorators` module. It requires `wardline` as a dependency for core type definitions.

## Usage

```python
from wardline.decorators import audit, validates_shape, external_boundary

@audit
def log_event(event_type: str) -> None:
    ...

@validates_shape
def check_input(data: dict) -> None:
    if not isinstance(data, dict):
        raise TypeError("Expected dict")
```

See the [wardline documentation](https://wardline.dev) for the full decorator vocabulary.
