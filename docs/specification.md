---
hide:
  - toc
---

<div class="wl-spec-header" markdown>

# Wardline Framework Specification

The normative reference for all wardline language bindings.

<div class="wl-spec-meta" markdown>
**Version:** 0.3.0 Release Candidate &nbsp;|&nbsp; **Date:** 9 April 2026 &nbsp;|&nbsp; **Status:** Release Candidate
</div>

[Download PDF](assets/wardline-specification.pdf){ .md-button .md-button--primary }
[View Source on GitHub](https://github.com/tachyon-beep/wardline/tree/main/docs/spec){ .md-button }

</div>

---

## Part I — Language-Independent Framework

The core specification defines the authority tier model, enforcement rules, governance,
and conformance requirements that all language bindings must implement.

<div class="wl-chapter-grid" markdown>

<span class="wl-chapter-num">§ 1</span> <span class="wl-chapter-title">[Document Scope](spec/wardline-01-01-document-scope.md) — What the specification covers and its intended audience</span>

<span class="wl-chapter-num">§ 2</span> <span class="wl-chapter-title">[What a Wardline Is](spec/wardline-01-02-what-a-wardline-is.md) — Core concept: a declared trust boundary in code</span>

<span class="wl-chapter-num">§ 3</span> <span class="wl-chapter-title">[The Problem a Wardline Solves](spec/wardline-01-03-the-problem-a-wardline-solves.md) — Untrusted data reaching privileged code without validation</span>

<span class="wl-chapter-num">§ 4</span> <span class="wl-chapter-title">[Non-Goals](spec/wardline-01-04-non-goals.md) — What wardline intentionally does not address</span>

<span class="wl-chapter-num">§ 5</span> <span class="wl-chapter-title">[Authority Tier Model](spec/wardline-01-05-authority-tier-model.md) — The four-tier trust hierarchy and taint classification</span>

<span class="wl-chapter-num">§ 6</span> <span class="wl-chapter-title">[Authority Tier Enforcement](spec/wardline-01-06-authority-tier-enforcement-spec.md) — Taint joins, restoration evidence, and tier transition rules</span>

<span class="wl-chapter-num">§ 7</span> <span class="wl-chapter-title">[Annotation Vocabulary](spec/wardline-01-07-annotation-vocabulary.md) — Decorators and annotations that mark trust boundaries</span>

<span class="wl-chapter-num">§ 8</span> <span class="wl-chapter-title">[Pattern Rules](spec/wardline-01-08-pattern-rules.md) — WL-001 through WL-009: the detection rule catalogue</span>

<span class="wl-chapter-num">§ 9</span> <span class="wl-chapter-title">[Enforcement Layers](spec/wardline-01-09-enforcement-layers.md) — Static, type-system, runtime, and structural enforcement</span>

<span class="wl-chapter-num">§ 10</span> <span class="wl-chapter-title">[Governance Model](spec/wardline-01-10-governance-model.md) — Exception register, control-law state machine, retention</span>

<span class="wl-chapter-num">§ 11</span> <span class="wl-chapter-title">[Verification Properties](spec/wardline-01-11-verification-properties.md) — Golden corpus, formal properties, testing requirements</span>

<span class="wl-chapter-num">§ 12</span> <span class="wl-chapter-title">[Language Evaluation Criteria](spec/wardline-01-12-language-evaluation-criteria.md) — Criteria for adding new language bindings</span>

<span class="wl-chapter-num">§ 13</span> <span class="wl-chapter-title">[Residual Risks](spec/wardline-01-13-residual-risks.md) — Known limitations and compensating controls</span>

<span class="wl-chapter-num">§ 14</span> <span class="wl-chapter-title">[Portability & Manifest Format](spec/wardline-01-14-portability-and-manifest-format.md) — wardline.yaml schema, overlays, and cross-platform format</span>

<span class="wl-chapter-num">§ 15</span> <span class="wl-chapter-title">[Conformance](spec/wardline-01-15-conformance.md) — Profiles, adoption phases, and compliance requirements</span>

</div>

---

## Part II — Language Bindings

Language-specific implementation contracts. Each binding maps the abstract framework
to concrete language constructs.

<div class="wl-chapter-grid" markdown>

<span class="wl-chapter-num">§ A</span> <span class="wl-chapter-title">[Python Language Binding](spec/wardline-02-A-python-binding.md) — Decorators, regime composition, error handling, adoption</span>

<span class="wl-chapter-num">§ B</span> <span class="wl-chapter-title">[Java Language Binding](spec/wardline-02-B-java-binding.md) — Annotations, record types, module system, Checker Framework</span>

</div>

---

## Companion Documents

<div class="wl-chapter-grid" markdown>

<span class="wl-chapter-num"></span> <span class="wl-chapter-title">[Wardline Lite](spec/wardline-lite.md) — Five-question practical review guide for non-specialists</span>

</div>

---

## Building the PDF

The specification PDF is built from the markdown source files using Pandoc and Typst:

```bash
tools/pdf/build-spec.sh --pdf
```

This concatenates the spec chapters, applies a Lua filter for table column widths,
renders through the Typst template, and compiles to PDF. Requires Pandoc 3.0+ and
Typst 0.14+.
