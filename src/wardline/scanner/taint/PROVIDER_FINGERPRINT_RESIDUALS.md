# Provider-fingerprint residuals

Known, measured limitations of `_grammar_digest` in `decorator_provider.py` — the cache
key over a project's custom trust grammar.

**Anything not on this list is not claimed closed.** This document records what is known
to be wrong, not what has been proven right. It was produced by a thirteen-round
adversarial hardening programme; the reasoning behind each entry is in
`.superpowers/sdd/2026-08-09-s0-hardening-and-consumer-prep/task-13-report.md`, but this
file is the durable artifact and is meant to be actionable without it.

## How to read an entry

**Failure direction** is the first thing to check, because the two are not comparable:

| direction | meaning | severity |
|---|---|---|
| **UNDER-DISCRIMINATION** | two behaviourally different grammars share a cache key, so a warm cache serves verdicts computed under the wrong rules | **a false green** — the class this whole component exists to prevent |
| **OVER-INVALIDATION** | a cache goes cold when it need not | a cost, never a correctness bug |
| **OPERATIONAL** | neither; resource or lifecycle behaviour | |

**Blast radius for every under-discrimination entry:** the stale-verdict hop requires
`--cache-dir` **and** `WARDLINE_SUMMARY_CACHE_KEY` (`core/run.py:387-389`). Summary
caching is opt-in, so none of these is a live default-path false green.

**Freshness.** Entries are marked *fresh* (re-measured in the final round) or *inherited*
(measured when first found, carried forward without re-measurement). An inherited entry
is not less true, but it is less recently checked — do not trust the list uniformly.

---

## D1 — computed dispatch makes a pack permanently uncacheable

* **Direction:** OVER-INVALIDATION. **Reach:** widest of anything here. **Freshness:** inherited.
* Any of `getattr` / `__getattribute__` / `vars` / `globals` / `attrgetter` /
  `methodcaller` / `getattr_static` / `import_module` / `__import__` / `reload` / `eval` /
  `exec` appearing in **grammar-surface code** marks the grammar uncacheable — a fresh
  random fingerprint every scan.
* A *literal* attribute name gets no exemption: the digest cannot distinguish
  `getattr(x, "literal")` from `getattr(x, computed)` without dataflow.
* **Cheaper than the defect?** Yes, and deliberately so. This is the fail-closed half of
  the design: an unprovable input yields an honest unknown rather than a false green.
  Reducing it means proving the name is constant, which is a dataflow problem.

## D2 — an uncacheable grammar writes an orphan cache entry per scan

* **Direction:** OPERATIONAL. **Freshness:** inherited (not re-measured since it was found).
* Every scan of a D1-affected pack writes a summary-cache entry under a key nothing will
  ever read. Unbounded disk growth.
* **Fix cheaper than the defect?** Yes — suppress the write on the uncacheable path, or
  sweep. Not done here because it lives outside the two files this work could touch.

## D3 — the object graph re-keys itself

* **Direction:** OVER-INVALIDATION. **Reach:** the primary agent surface. **Freshness:** inherited (rode a passing suite in the final round).
* `cached_property`, memo dicts, PEP-562 lazy imports, `WeakSet` — and the digest's own
  traversal — mutate the graph when the grammar is *used*, so a long-lived `wardline mcp`
  never warms the cache for a pack that memoises anything.
* Measured: `rich` and `jsonschema` produce **five distinct digests across five fresh
  processes**. The **first** `fingerprint()` call in a process also differs from every
  later one, so each process's first scan is orphaned on top of D2.
* **Fix cheaper than the defect?** No. Freezing the graph before hashing is not possible
  from outside it.

## D4 — the distribution gate

* **Direction:** BOTH. **Freshness:** fresh (re-measured, both directions, in the final round).
* `_is_foreign_distribution` uses `importlib.metadata.packages_distributions()` to decide
  whether a top-level package is the pack's own or a third-party library. Nothing
  structural separates `import otherpkg.mod as sibling` from `import yaml as Y`; the
  packaging metadata is the only available signal.
* **Under-discriminates** when a pack ships its own second package as a *separate*
  distribution (measured: 8/8 collide), and when the grammar itself is not installed while
  the second package is. `core/config.py` constrains neither layout.
* **Over-invalidates** for a library with no metadata — vendored, zip-imported, or a local
  source tree. Measured: with the grammar installed and the library root carrying no
  metadata, `click.Command`, `rich.console.Console`, `requests.Session` and
  `jsonschema.Draft7Validator` class-references **all four go uncacheable**.
* **Now load-bearing for every library case.** Since the surface is grown from the full
  traversal, a library root is offered at every grammar-surface function. Measured: gate
  live → `surface_roots == []`; gate neutered → `['charset_normalizer', 'requests',
  'urllib3']`, `['attr', 'attrs', 'idna', 'jsonschema', 'referencing', 'rpds']`, and all
  four go uncacheable. The correctness of the library cases rests entirely here.
* **Fix cheaper than the defect?** Unknown. A location-based test was built and measured
  working in an earlier round and deliberately not retained.

## A1 — reach: modules bound where there is no demand information

* **Direction:** UNDER-DISCRIMINATION. **Reach:** live but uncommon. **Freshness:** fresh.
* **Covered:** a module reached through any function's or module's **globals/namespace**,
  at any depth, bound either as a module or as one of its members.
* **Not covered:** a module reached *only* through a **closure cell, a plain list, or a
  class attribute**. Measured: 18 of 30 cells collide, pinned as known-collide in
  `test_seed_reach_axis_behaves_as_classified`.
* **Why:** for these bindings the module is never *visited* — the name is not in
  `co_names`, so `_module_identity` never runs and there is no demand set to drive it.
* **Fix cheaper than the defect?** **No, for these cells specifically.** Expanding a
  demand-free module's full member set is the namespace walk that measured **207 MB**.
  ⚠️ **Do not generalise this sentence.** It is true of the closure/container family only.
  The *module-hop* family — a pack module binding the second package — has demand
  information and was closed by one call with zero blast radius.

## A2 — trigger names: an allow-list of spellings, not a closed category

* **Direction:** UNDER-DISCRIMINATION. **Freshness:** fresh.
* The trigger set is intersected against `co_names`, which carries the **local binding**,
  so **any rebinding defeats every entry at once**. Measured, all COLLIDE:
  `from inspect import getattr_static as _gs`, `from operator import attrgetter as _ag`,
  `from importlib import import_module as _imp`, and even `_g = getattr`.
* This is structural. No traversal enumerates "every way to resolve a name at run time",
  so the set can only ever be an allow-list of spellings.
* **Measured colliding, deliberately NOT added:**
  | shape | commonness | why not added |
  |---|---|---|
  | `H.__dict__["for_" + n]` | ordinary | adding `__dict__` would fire on any surface function touching `self.__dict__` and brick real packs permanently |
  | `sys.modules["pkg." + n]` | ordinary | `modules` is too generic a name to trigger on |
  | `operator.getitem(H.__dict__, …)` | uncommon | over-invalidation cost unmeasured |
  | `pkgutil.resolve_name("pkg:" + n)` | uncommon | over-invalidation cost unmeasured |
* **Measured and excluded for the opposite reason** — they already discriminate
  structurally, so a trigger would be pure over-invalidation: `locals()[computed]`,
  `operator.itemgetter`. `setattr`/`delattr` mutate rather than resolve.
* **Fix cheaper than the defect?** No. Closing this properly needs dataflow on the callee
  expression, not more names. Widening the list further is measurably capable of bricking
  ordinary packs (see the `__dict__` row).

## A3 — the fence: stdlib detection is name-shaped · ⚠️ DO NOT FIX

* **Direction:** UNDER-DISCRIMINATION in the digest. **Reachability: measured UNREACHABLE through the loader.** **Freshness:** inherited.
* `_OPAQUE_PACKAGES` fences any root appearing in `sys.stdlib_module_names` (289 entries,
  including ordinary words like `code`, `copy`, `types`, `email`, `secrets`, `queue`).
  A pack under `email.grammar` measurably collides where `mypack.grammar` discriminates.
* **But it cannot be reached through the product.** `core/config.py:194` loads packs with
  `sys.path.append` then `import_module`, and stdlib entries precede appended ones, so
  `import_module("email.grammar")` raises `ModuleNotFoundError`. The loader's docstring
  states the non-shadowing intent deliberately. Remaining triggers are environmental
  (cwd preceding stdlib on `sys.path`; a name that is stdlib on one OS only).
* **⚠️ DO NOT FIX.** The fix lands in `_is_structurally_opaque`, whose only prior
  modification shipped a fail-open. A risky edit against an unreachable defect is a bad
  trade. A location-based fence was built and measured working and deliberately dropped.
* Second sub-part, also open: a **fenced class's** namespace is keyed by name only.

## A4 — silent degradation markers

* **Direction:** UNDER-DISCRIMINATION under hostile input. **Freshness:** inherited.
* Nine distinct tags — `budget-exhausted`, `depth-capped`, `unreadable-reduce`,
  `undrainable-items`, `unreadable-contents`, `unreadable-element`, `unreadable-slot`,
  `items-already-keyed`, `<unreprable>`. Each is distinguishable in a preimage, but none
  is surfaced to an operator.
* Bounds: node budget 50 000, measured ~530 B/node ⇒ a ~25 MiB preimage ceiling. A single
  container's **width** remains unbounded.
* Sub-entry: `_subclass_state` records an unset slot as `unreadable-element`, where
  `_instance_identity` distinguishes `unset-slot` (normal) from `unreadable-slot`
  (hostile). Two conditions share one marker.
* **Fix cheaper than the defect?** Yes for the reporting half — emit a diagnostic when a
  marker fires. Not done here.

## A5 — a record built inside a reference cycle is memoized

* **Direction:** UNDER-DISCRIMINATION. **Reach:** exotic; not measured to collide. **Freshness:** inherited.
* `{"t": "cycle"}` is emitted relative to the path that first reached the cycle, and that
  record is then memoized and back-referenced from elsewhere. Deterministic, but
  potentially under-discriminating for mutually-recursive groups.

## A6 — a dict built from a set re-keys between processes

* **Direction:** OVER-INVALIDATION. **Reach:** live. **Freshness:** inherited (not re-measured in the final round).
* Dict key **order** is behaviourally load-bearing in a first-match-wins table, so the
  digest observes it. A dict built from a set (`{n: LEVEL for n in NAMES}`) therefore
  inherits that set's iteration order, which varies with hash randomisation. Measured:
  three fresh processes, three digests.
* The ordering is baked in at pack *import* time, before the digest runs, so the digest
  can only observe it — not repair it. Accepted cost of making order observable.

## A7 — `_TRANSPARENT_TYPES` advertises coverage the arms do not provide

* **Direction:** UNDER-DISCRIMINATION. **Reach:** exotic. **Freshness:** inherited.
* The set names `str`/`bytes`/`bytearray`/`int`/`float`/`complex` alongside the
  containers, but per-instance state (`extra=`) is wired on only the three container
  arms. A `str` subclass carrying per-instance config collides; the ordinary
  `class Lvl(str, Enum)` control discriminates.
* **Fix cheaper than the defect?** Yes — wire the remaining arms. Not done because the
  digest-moving blast radius exceeds the defect's measured reach.

## A8 — a C-extension object with unreadable configuration

* **Direction:** UNDER-DISCRIMINATION. **Reach:** exotic; **not reproduced in five attempts.** **Freshness:** inherited.
* An object with no `__dict__`, no `__slots__`, no usable `__reduce_ex__` and a default
  `repr` is keyed by type plus normalised repr only. Listed rather than claimed closed,
  because it could not be constructed — not because it was shown impossible.

## A9 — behaviour keyed outside the object graph · unfixable by design

* **Direction:** UNDER-DISCRIMINATION. **Freshness:** inherited.
* A helper that reads an environment variable, a file, or a clock cannot enter a static
  preimage. This also covers a grammar assembled by computed dispatch at *import* time:
  the lookup resolves before wardline sees the object graph.
* **Fix cheaper than the defect?** No — this is a property of static analysis, not a gap.

## A10 — a seed `exec`'d with no `__name__` · UNREACHABLE

* **Direction:** UNDER-DISCRIMINATION. **Freshness:** inherited.
* Collides, but `core/config.py:198` always `import_module`s a pack, so a loaded grammar
  always has a module. Recorded for completeness.

---

## Retired

* **Statement reordering over-invalidates** — retired once order-sensitivity became the
  intended semantics: reordering an ordered mapping *is* a behaviour change.
* **Hand-rolled `type(m).__getattribute__(m, computed)`** — closed by adding
  `__getattribute__` to the trigger set, measured. Note this does *not* close A2, which is
  about rebinding, not about this one spelling.
