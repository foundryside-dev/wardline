# Loomweave taint store

The Loomweave taint store is an **opt-in** persistent back-end for taint facts.
When configured, each `wardline scan` writes per-entity taint facts to Loomweave;
the MCP `explain_taint` tool then queries those facts directly instead of
re-scanning the file, and can walk the full N-hop taint chain back to the
originating boundary.

!!! info "Never required"
    There is **no Loomweave dependency by default**. `wardline scan` boots,
    analyzes, writes findings, and gates without Loomweave present. The store is
    pure enrichment — additive, never load-bearing.

## The opt-in

Install the extra to add the `blake3` dependency:

```console
$ pip install 'wardline[loomweave]'
```

Then pass `--loomweave-url` to point at your Loomweave instance:

```console
$ wardline scan src/ --loomweave-url http://localhost:9100
```

The same flag works for the MCP server:

```console
$ wardline mcp --root . --loomweave-url http://localhost:9100
```

Without the extra installed, `--loomweave-url` is a hard error (exit `2` on the
CLI; a `not-reachable` result block in the MCP response so the scan payload
survives).

## Authentication

Wardline reads an auth token from `WARDLINE_LOOMWEAVE_TOKEN` — set it in your
environment or place a `WARDLINE_LOOMWEAVE_TOKEN=...` line in a `.env` file at
the scan root. An already-set environment value always wins; the `.env` read
never silently overrides it.

The token value must match the one the Loomweave operator configured in
`serve.http.identity_token_env` on the Loomweave side. Wardline never reads
that variable directly — it only reads the token and sends it.

## What it enables: `explain_taint` as a query

Without a store, `explain_taint` re-scans the file on every call to produce a
single-hop explanation. With a store:

- Pass the finding's `qualname` as `sink_qualname` and a fresh fact is served
  from Loomweave without re-scanning the file at all.
- Pass `chain: true` (with an optional `max_hops`) — alongside `sink_qualname`
  — to walk the full N-hop taint chain back to the originating boundary:
  call-graph depth that a single-hop re-scan cannot provide. `chain` needs both
  a configured store and `sink_qualname`; without them it is ignored and you get
  the single-hop explanation.

A fact is "fresh" when the blake3 hash of the source file at read time matches
the hash Wardline stamped when it wrote the fact. Wardline owns this verdict;
Loomweave only reports the live hash. If the file has changed since the last
scan, the fact is stale and Wardline falls back to a local re-scan
transparently.

## The project guard

Each fact is scoped to a **project guard** — the project-root directory name
(for example, `wardline` if the root is `/home/you/wardline`). Facts written
under a different project guard are ignored on read. An empty string is
accepted and treated as a valid guard.

## Fail-soft guarantee

Loomweave is never on the critical path. The full degradation matrix:

| Condition | Behavior |
|---|---|
| Loomweave absent or unreachable | warn and continue; scan exits normally |
| Loomweave responds `WRITE_DISABLED` | skip write silently; scan continues |
| Project guard mismatch (`PROJECT_MISMATCH`) | skip silently; scan continues |
| Stale fact (blake3 mismatch) | fall back to local re-scan |
| Hard error (missing extra, bad URL scheme, 4xx) | CLI exits `2`; MCP returns scan with `not-reachable` Loomweave block |

The CLI-vs-MCP distinction matters for hard errors: a hard `LoomweaveError` on
the CLI is a configuration mistake the developer must fix, so it fails loud
(exit `2`). Inside the MCP loop the agent's scan payload is more valuable than
the error, so the scan result is returned with a `loomweave` block indicating the
store is not reachable — the agent can act on the findings immediately and fix
the store configuration separately.

## Known cost

With a store configured, each `scan` additionally builds taint facts (a blake3
hash per file) and POSTs them to Loomweave. This is fail-soft, but it is a real
per-scan cost in a tight agent loop — if Loomweave is slow or distant, factor
that into your loop design.

## See also

- [Using Wardline with your coding agent](agents.md) — the MCP tool
  surface, including `explain_taint`.
- [Weft integration](weft.md) — the other Weft output paths (SARIF, native
  Filigree emitter, Loomweave producer conformance).
- [Configuration](configuration.md) — `weft.toml` `[wardline]` keys.
