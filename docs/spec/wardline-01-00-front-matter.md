## Wardline Framework Specification
### Semantic Boundary Classification and Enforcement

**Date:** 9 April 2026
**Status:** Design — DRAFT v0.3.0
**Document type:** Conformity assessment scheme comprising a data classification model, enforcement rules, governance requirements, and conformance criteria
**Language bindings:** Python (Part II-A), Java (Part II-B)

---

### How to read this document

This document comprises two parts: Part I (the framework specification) and Part II (language binding references for Python and Java). Not all readers need all sections. The paths below route to the most relevant content for each audience.

**Tool implementers** (building a Wardline-Core scanner, linter plugin, or type checker plugin):
→ Part I: §2–4 (concepts), §5 (tier model), §6 (enforcement specification), §7–8 (annotations, pattern rules), §9 (enforcement layers), §15 (conformance) → Part II: A.3/B.3 (interface contract — read first), then A.4/B.4 (annotation vocabulary)

**Security assessors** (IRAP or equivalent, evaluating a wardline deployment):
→ Part I: §2–4 (scope), §5 (tier model), §11 (verification properties and golden corpus), §15 (conformance criteria and profiles)
→ Part II: A.3/B.3 (interface contract), A.6/B.6 (regime composition), A.7/B.7 (residual risks)

**Adopters** (deploying wardline on a project):
→ Part I: §2–5 (what it is, why, tier model), §10 (governance model) → Part II: A.9/B.9 (adoption strategy), A.4/B.4 (annotation vocabulary)

**Governance leads** (managing wardline policy and exceptions):
→ Part I: §10 (governance model), §14 (manifest and exception register), §15.1 (conformance model)
→ Part II: A.7/B.7 (residual risks), A.10/B.10 (error handling and control law)

**Citizen programmers** (reviewing or writing code in a wardline-annotated codebase, without developer tooling):
→ Wardline Lite practical guide (`wardline-lite.md`, separate companion document): five review questions, worked code examples, hot-path identification. This guide is not part of the formal specification — it translates the annotation vocabulary (§7) and pattern rules (§8) into questions a non-specialist can apply during code review.

---

### Contents

**Part I — Wardline Framework Specification** (this document)

1. [Document scope](#1-document-scope)
2. [What a Wardline is](#2-what-a-wardline-is)
3. [The problem a Wardline solves](#3-the-problem-a-wardline-solves)
4. [Non-goals](#4-non-goals)
5. [Authority tier model](#5-authority-tier-model)
    - 5.1 Four tiers
6. [Authority tier model: enforcement specification](#6-authority-tier-model-enforcement-specification)
    - 6.1 Trust classification and validation status — 6.2 Transition semantics — 6.3 Trusted restoration boundaries — 6.4 Cross-language taint propagation — 6.5 Third-party in-process dependency taint
7. [Annotation vocabulary](#7-annotation-vocabulary)
8. [Pattern rules](#8-pattern-rules)
    - 8.1 The rules — 8.2 Structural verification — 8.2.1 Structural-guarantee defaults and WL-001 — 8.3 Severity matrix — 8.4 Worked examples — 8.5 Derivation principles — 8.6 Taint analysis scope
9. [Enforcement layers](#9-enforcement-layers)
    - 9.1 Static analysis — 9.2 Type system — 9.3 Runtime structural — 9.4 Orthogonality principle — 9.5 Pre-generation context projection (advisory)
10. [Governance model](#10-governance-model)
    - 10.1 Exceptionability classes — 10.2 Governance mechanisms — 10.3 Scope of governance — 10.3.1 Artefact classification: policy and enforcement — 10.3.2 Manifest threat model — 10.4 Governance capacity — 10.5 Enforcement availability (control law)
11. [Verification properties](#11-verification-properties)
    - 11.1 Findings interchange format — 11.2 Finding presentation guidance
12. [Language evaluation criteria](#12-language-evaluation-criteria)
13. [Residual risks](#13-residual-risks)
14. [Portability and manifest format](#14-portability-and-manifest-format)
    - 14.1 Wardline manifest format — 14.2 Scanner operational configuration (wardline.toml)
15. [Conformance](#15-conformance)
    - 15.1 Conformance model — 15.2 Conformance criteria — 15.3 Conformance profiles (15.3.1 Enforcement profiles, 15.3.2 Governance profiles, 15.3.3 Graduation) — 15.4 Enforcement regimes — 15.5 Supplementary group enforcement scope — 15.6 Assessment procedure (15.6.1 Worked example: Phase 3 deployment, 15.6.2 Worked example: Lite governance deployment) — 15.7 Partial conformance

**Part II — Language Binding Reference**

A. [Python Language Binding Reference](#part-ii-a-python-language-binding-reference)
    - A.1 Design history — A.2 Python language evaluation — A.3 Interface contract (normative) — A.4 Annotation vocabulary — A.5 Type system and runtime enforcement — A.6 Regime composition matrix — A.7 Residual risks — A.8 Worked example — A.9 Adoption strategy — A.10 Error handling and control law
B. [Java Language Binding Reference](#part-ii-b-java-language-binding-reference)
    - B.1 Design history — B.2 Java language evaluation — B.3 Interface contract (normative) — B.4 Annotation vocabulary — B.5 Type system and runtime enforcement — B.6 Regime composition matrix — B.7 Residual risks — B.8 Worked example — B.9 Adoption strategy — B.10 Error handling and control law

**Companion Documents**

- Wardline Lite practical guide (`wardline-lite.md`) — five review questions for non-specialist code reviewers
- Implementation design: Wardline for Python (`../2026-03-21-wardline-python-design.md`) — reference implementation work packages and build order

**Planned Companion Documents** (deferred to post-v1.0)

- Implementer's Guide: Scanner Architecture — detailed guidance for building a Wardline-Core scanner. Content from prior specification drafts is available in version control history.
- Agent Guidance — constraints and patterns for AI agents working in wardline-annotated codebases. Evolved from prior agent guidance sections; publication deferred until reference implementation reaches production maturity.

---
