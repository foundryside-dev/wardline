import blake3

from wardline.clarion.client import TaintFactView
from wardline.core.explain import explain_chain

# A 3-hop leaky chain: leaky -> mid -> read_raw (boundary leaf).
_CHAIN = (
    "from wardline.decorators import external_boundary, trusted\n"
    "@external_boundary\ndef read_raw(p):\n    return p\n"
    "def mid(p):\n    return read_raw(p)\n"
    "@trusted\ndef leaky(p):\n    return mid(p)\n"
)


def _proj(tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "svc.py").write_text(_CHAIN, encoding="utf-8")
    return proj


def _fresh_view(proj, qualname, callee_qualname):
    h = blake3.blake3((proj / "svc.py").read_bytes()).hexdigest()
    blob = {
        "schema_version": "wardline-taint-1", "qualname": qualname,
        "content_hash_at_compute": h,
        "taint": {"declared_return": "INTEGRAL", "actual_return": "EXTERNAL_RAW",
                  "source": "anchored", "contributing_callee_qualname": callee_qualname,
                  "resolved_call_count": 1, "unresolved_call_count": 0},
        "findings": [],
    }
    return TaintFactView(qualname=qualname, exists=True, wardline_json=blob,
                         current_content_hash=h)


class MapClient:
    def __init__(self, by_qualname):
        self._by = by_qualname

    def batch_get(self, qualnames):
        return [self._by.get(q, TaintFactView(qualname=q, exists=False)) for q in qualnames]


def test_chain_walks_to_the_boundary(tmp_path):
    proj = _proj(tmp_path)
    client = MapClient({
        "svc.leaky": _fresh_view(proj, "svc.leaky", "svc.mid"),
        "svc.mid": _fresh_view(proj, "svc.mid", "svc.read_raw"),
        "svc.read_raw": _fresh_view(proj, "svc.read_raw", None),  # boundary leaf
    })
    chain = explain_chain(proj, sink_qualname="svc.leaky", clarion=client, max_hops=10)
    assert [hop.qualname for hop in chain.hops] == ["svc.leaky", "svc.mid", "svc.read_raw"]
    assert chain.truncated_at is None  # reached the leaf cleanly


def test_chain_truncates_explicitly_on_stale_hop(tmp_path):
    proj = _proj(tmp_path)
    stale = _fresh_view(proj, "svc.mid", "svc.read_raw")
    stale.wardline_json["content_hash_at_compute"] = "0" * 64  # stamp != live hash
    client = MapClient({
        "svc.leaky": _fresh_view(proj, "svc.leaky", "svc.mid"),
        "svc.mid": stale,
    })
    chain = explain_chain(proj, sink_qualname="svc.leaky", clarion=client, max_hops=10)
    assert [hop.qualname for hop in chain.hops] == ["svc.leaky"]
    assert chain.truncated_at == "svc.mid"  # explicit, never a silent stop


def test_chain_respects_max_hops(tmp_path):
    proj = _proj(tmp_path)
    client = MapClient({
        "svc.leaky": _fresh_view(proj, "svc.leaky", "svc.mid"),
        "svc.mid": _fresh_view(proj, "svc.mid", "svc.read_raw"),
        "svc.read_raw": _fresh_view(proj, "svc.read_raw", None),
    })
    chain = explain_chain(proj, sink_qualname="svc.leaky", clarion=client, max_hops=2)
    assert len(chain.hops) == 2
    assert chain.truncated_at == "svc.read_raw"  # the unwalked next hop
