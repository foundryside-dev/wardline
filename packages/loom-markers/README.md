# loom-markers

Tiny runtime marker decorators for Loom/Wardline trust annotations.

Application code can depend on this package instead of the full Wardline
scanner package:

```python
from loom_markers import external_boundary, trust_boundary, trusted
```

The decorators validate their string levels, stamp `_wardline_*` marker
attributes, and return the decorated object unchanged.
