## Part II — Language Binding Reference

This part provides compressed binding references for each language the Wardline framework currently targets. Each binding maps the framework's 17 abstract annotation groups (Part I §7) to concrete language mechanisms, defines the interface contract for conformant scanners, and documents language-specific residual risks.

**Normative status.** This part uses per-section normative markers. Interface contract sections (A.3, B.3) are normative — they define the boundary between the specification and any implementation. All other sections (mapping tables, regime matrices, worked examples, design rationale, residual risks) are non-normative — they provide implementation guidance and assessment material.

**Relationship to Part I.** Part I defines the framework: tier model, taint algebra, pattern rules, governance model, conformance criteria, and manifest format. This part translates those framework requirements into language-specific enforcement. Where a binding-level statement conflicts with Part I, Part I governs.

**Current bindings:**

- **A. Python** — targets Python 3.12+. Uses decorator-based annotation, `typing.Annotated` for type-system enforcement, and descriptors for runtime structural enforcement. *Updated to framework v0.3.0.*
- **B. Java** — targets Java 17+. Uses annotation-based vocabulary with meta-annotation composition, Checker Framework pluggable types for type-system enforcement, and sealed classes with records for runtime structural enforcement. *Not yet updated to framework v0.3.0 — see binding version notice in B.1.*

**Future bindings** (not yet specified): C#, Go, Rust. The candidate language list and per-language evaluation rationale are in Part I §1. The evaluation criteria in Part I §12 define how to assess a new target language.

**Companion documents** (not part of this specification):

- **Implementer's Guide: Scanner Architecture** — reference scanner design, call-graph analysis, taint model implementation, static analysis limitations. For tool authors building Wardline-Core scanners. *(Deferred to post-v1.0 — content from the prior Parts II/IV scanner architecture sections is available in version control history.)*
- **Agent Guidance: Generating Wardline-Compliant Code** — context-window payloads and system prompt guidance for AI agents generating code within wardline-annotated codebases. *(Deferred to post-v1.0 — evolved from the prior Parts III/V agent guidance sections; publication deferred until reference implementation reaches production maturity.)*

---
