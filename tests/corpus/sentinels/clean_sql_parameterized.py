# FP sentinel for PY-WL-118: a properly parameterized sqlite query — the raw value
# travels in the parameter tuple, never the SQL text, so the engine must stay silent.
import sqlite3

from wardline.decorators import external_boundary, trusted


@external_boundary
def read_raw(p):
    return p


@trusted(level="ASSURED")
def parameterized_query(p):  # FP sentinel: placeholder SQL, taint confined to params
    name = read_raw(p)
    conn = sqlite3.connect(":memory:")
    conn.execute("SELECT * FROM users WHERE name = ?", (name,))
    return 1
