# Wardline → Loomweave: Rust qualname dialect — two ADR-049 amendment requests + one closed tail

**From:** Wardline engineering (Rust tree-sitter frontend, second ADR-049 producer)
**To:** Loomweave maintainers (Rust plugin)
**Date:** 2026-06-10
**Re:** Two un-decided dialect gaps both producers share — (1) reserved-colon path-typed generic args, (2) const-generic-arg spacing — plus the record of the amend-3 corpus tail your `rc4` now carries.
**Status:** **SIGNED OFF — Wardline owner (john@foundryside.dev), 2026-06-10. ADR-049 amended same day (loomweave `rc4`, amendment 4: one shared `escape_reserved(strip_ws(arg))` pipeline for every concrete generic argument, type or const). Implementation + the three corpus rows land next sprint; both producers conform in lockstep once the rows exist (`wardline-be5ee9cc34`, const-spacing half of `wardline-e8f7c0508f`, blocker `wardline-e3e9e109ba`).**

---

## 0. Why this letter

Your Phase 1b change-set (`docs/integration/2026-06-09-loomweave-rust-qualname-phase1b-changeset.md`) and the corpus rows landed since put both producers byte-for-byte on every *decided* surface. Two surfaces remain **undecided** — not "Wardline diverges from the oracle" but "the oracle has no good output either." Per ADR-049's authority model, the decision is yours; per the second-producer discipline, we will not normalize unilaterally. This letter proposes the decision, names the alternatives we rejected, and requests the corpus rows that would gate both producers' conformance.

Nothing here is implemented on the Wardline side, and nothing should be implemented on the Loomweave side, until (a) the Wardline owner signs this off, (b) ADR-049 §2 is amended, and (c) the corpus rows exist. Tracked Wardline-side as `wardline-be5ee9cc34` (§1) and the const-spacing half of `wardline-e8f7c0508f` (§2), both blocked on this decision.

---

## 1. Reserved-colon path-typed generic args — the decision request

### The shared defect (both endpoints are bad)

A trait or self-type concrete generic argument that is itself a `::`-path mints a locator segment containing the dialect's one reserved character:

```rust
impl From<std::io::Error> for Foo { fn from(e: std::io::Error) -> Self { … } }
```

- **Loomweave:** `trait_generic_args` → `type_textual` → `strip_ws` (qualname.rs:158-172, :258-269) renders the arg as `std::io::Error`, so the assembled locator is `…Foo.impl[From<std::io::Error>]` — colon-bearing. `entity_id()` then rejects it (`validate_no_colon`, entity_id.rs:140-148, invoked at :102), `build_id` maps the `EntityIdError` into a `syn::Error` (extract.rs:861-865), and `degraded_aware` (extract.rs:232-274) collapses the **whole cleanly-parsed file** to a single `syntax_error` module plus one Warning finding. One ubiquitous impl erases every entity in its file.
- **Wardline:** our tree-sitter frontend renders the byte-identical `From<std::io::Error>` segment and emits it **un-gated** — a locator that violates the dialect's own reserved-separator invariant and that your host would refuse.

So today the dialect has *no canonical colon-free form* for this construct, and the construct is everywhere in real Rust (`From<io::Error>`, `TryFrom<crate::Config>`, `From<std::path::PathBuf>`, `AsRef<std::path::Path>`). The vendored corpus only exercises single-segment generic args (`From<i32>`, `From<u32>`), so neither producer's conformance gate can see the gap.

### The proposal: extend `escape_reserved` to generic-arg rendering

ADR-049 already owns an injective reserved-char escape — `escape_reserved` (qualname.rs:314-317): `%` → `%25` **first**, then `:` → `%3A` — applied today to cfg predicates inside `normalise_pred` (qualname.rs:319-336), and now corpus-pinned by `cfg_escape_reserved_char`. We propose applying **the same function** to the **full `type_textual` rendering of each concrete generic argument**, in **both** places that rendering reaches the locator:

| construct | today (rejected / un-gated) | proposed canonical form |
|---|---|---|
| trait fragment | `Foo.impl[From<std::io::Error>]` | `Foo.impl[From<std%3A%3Aio%3A%3AError>]` |
| self-type prefix | `Foo<std::io::Error>.impl#<>` | `Foo<std%3A%3Aio%3A%3AError>.impl#<>` |
| composed | `Foo<crate::X>.impl[From<std::io::Error>].from` | `Foo<crate%3A%3AX>.impl[From<std%3A%3Aio%3A%3AError>].from` |

Precisely: wherever a concrete generic argument is rendered for the locator — the `GenericArgument::Type` arms of `trait_generic_args` (qualname.rs:165) and `self_ty_locator`/`self_ty_arg` (qualname.rs:222, :250) — the rendered string becomes `escape_reserved(type_textual(ty))`. Nested args are covered for free because the escape runs over the full rendered text (`Vec<std::io::Error>` → `Vec<std%3A%3Aio%3A%3AError>`), as are qself paths (`<T as Trait>::Item`). The dialect's structural characters `[ ] # < > @ $ , &` are untouched — they are already legal id bytes; only `%` and `:` rewrite.

Properties:

- **Collision-free.** Unlike last-segment truncation, distinct paths stay distinct: `From<std::io::Error>` ≠ `From<std::fmt::Error>` (`…io%3A%3AError` vs `…fmt%3A%3AError`).
- **Injective, hence reversible.** Because `%` is escaped before `:` (the same ordering argument documented at qualname.rs:308-313), a literal `%3A` in source type text cannot alias an escaped `::`; the original rendering is recoverable byte-for-byte.
- **One normalizer, already shared.** It is the SAME `escape_reserved` both engines already mirror for cfg predicates (Wardline's copy is gated by your `cfg_escape_reserved_char` row as of rc4 `a209fc7`). No new escape grammar enters the dialect.
- **Rename-stability unchanged.** Positional params (`$0`) never carry `:`; only concrete instantiations are affected, and they were already churn-on-edit by design.
- **`implements`-edge resolution unaffected.** Trait lookup strips generic args before resolving (extract.rs:788-794), so the escape never reaches the resolver.

### Rejected alternatives (so the ADR can record them)

1. **Last-segment truncation** (`From<std::io::Error>` → `From<Error>`): collides `io::Error` with `fmt::Error` — re-opening exactly the silent-data-loss family (writer `ON CONFLICT(id) DO UPDATE` overwrite) that the self-type-args amendment just closed. Rejected.
2. **Keep the degrade-whole-file behavior as canonical:** one `impl From<std::io::Error>` erases every entity in an otherwise clean file — and Wardline mirroring it would mean a single-file frontend discarding a whole file's findings surface over one impl. Disproportionate, and it leaves the dialect with no rendering at all for a ubiquitous construct. Rejected.
3. **Wardline-only normalization:** breaks the byte-for-byte parity that is the second-producer arrangement's entire reason to exist. Rejected without discussion.

### Requested artifacts

- **ADR-049 §2 amendment** specifying `escape_reserved` over the `type_textual` rendering of concrete generic args in both the trait fragment and the self-type prefix.
- **Two corpus rows** (extractor-generated as always; suggested sources):
  - **`path_typed_generic_arg_inherent`** — `struct Foo<T>(T); impl Foo<std::io::Error> { pub fn get(&self) {} }` → self-type prefix escape: `demo.m.Foo<std%3A%3Aio%3A%3AError>.impl#<>` (+ `.get`).
  - **`path_typed_generic_arg_trait`** — `struct Foo; impl From<std::io::Error> for Foo { fn from(_: std::io::Error) -> Self { Foo } }` → trait-fragment escape: `demo.m.Foo.impl[From<std%3A%3Aio%3A%3AError>]` (+ `.from`).

Both producers then conform in lockstep against the rows; Wardline re-vendors and implements only after they land.

---

## 2. Const-generic-arg spacing — converge on `strip_ws`

### The divergence

Const generic arguments are the one place the oracle's rendering is **not** whitespace-free: both `trait_generic_args` (qualname.rs:166-168) and `self_ty_locator` (qualname.rs:223-225) render `GenericArgument::Const` via `to_token_stream().to_string()` — proc-macro2 canonical spacing — **without** the `strip_ws` pass every `Type` arg gets. So a multi-token const arg renders spaced:

| source | oracle today | Wardline today |
|---|---|---|
| `Foo<{ N + 1 }>` | `Foo<{ N + 1 }>` | `Foo<{N+1}>` |
| `Foo<-1>` | `Foo<- 1>` | `Foo<-1>` |
| `Foo<3>` | `Foo<3>` | `Foo<3>` (already matches) |

Wardline cannot faithfully match the spaced form without reimplementing proc-macro2's token-spacing algorithm inside a tree-sitter frontend — the same impossibility class as the SEI token. And the spaced form is the odd one out in a dialect whose own normalizer comment calls `strip_ws` "the crate's one path/type normaliser" (qualname.rs:253-257).

### The proposal

Route `Const` args through the same `strip_ws` as `Type` args (in both call sites), converging the dialect on the whitespace-free form — which is also embedded whitespace's only sane treatment in a locator. Plain const args (`Foo<3>`, `Foo<i32>`, bare const-param idents) are byte-identical under both renderings, so the blast radius is multi-token const expressions only — currently un-oracled, so no corpus row churns.

Note the composition with §1: a const expression can also carry `::` (`Foo<{ usize::MAX }>`), so the §1 escape should apply to the const rendering after `strip_ws` — i.e. one shared pipeline `escape_reserved(strip_ws(arg))` for every concrete generic argument, type or const.

### Requested artifact

- **One corpus row** (suggested name **`const_generic_arg_spacing`**), e.g. `struct Foo<const N: usize>; impl Foo<{ 1 + 2 }> { pub fn get(&self) {} }` → `demo.m.Foo<{1+2}>.impl#<>` (+ `.get`) — pinning the stripped form in the self-type prefix. (If you prefer, a trait twin `impl From<Foo<{ 1 + 2 }>> …` would pin the trait fragment too; one row is enough to gate the normalizer.)

---

## 3. Record: the amend-3 corpus tail is CLOSED (no action needed)

For completeness against the open list in `wardline-e8f7c0508f` / the amendment-3 fidelity review — these are **done**, landed on your `rc4` and already vendored + conformed on our side:

- **Loomweave rc4 commit `a209fc7603b09bb06564e09c8c99390d410ea5b2`** ("test(plugin-rust): pin leaf kinds, stacked-cfg fold, cfg reserved-char escape, leaf-kind cfg twin with corpus rows", fixture blob `56cba0fe2d6c449ebc841c52a2800368b2e389e4`) added four extractor-verified rows to `fixtures/qualnames_rust.json`:
  - **`leaf_item_kinds`** — the five previously un-oracled free-item kinds (`enum`/`trait`/`type_alias`/`const`/`static`);
  - **`stacked_cfg_twin`** — the all-cfg fold (`impl#<>@cfg(feature="a"&unix)`), pinning `cfg_discriminant`'s sort-and-join over EVERY stacked predicate;
  - **`cfg_escape_reserved_char`** — `feature="a:b"` → `f@cfg(feature="a%3Ab")`, pinning `escape_reserved` on the cfg path (the precedent §1 extends);
  - **`leaf_kind_cfg_twin`** — per-(kind, name) twin counting on a leaf kind (`LIMIT@cfg(unix)` / `LIMIT@cfg(windows)`).
- The owed **nested-param row** (`generic_self_nested_param`, the F2 follow-up from the Phase 1b change-set) was already present upstream before that commit and is likewise vendored.

That closes every item of the amend-3 tail except the two decisions requested above. Once ADR-049 is amended and the §1/§2 rows land, ping us; Wardline re-vendors, conforms byte-for-byte, and `wardline-be5ee9cc34` / the spacing half of `wardline-e8f7c0508f` close in lockstep.
