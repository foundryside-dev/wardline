# BAR skill pack — shared discipline

These instructions are part of the active BAR policy tree and are injected
verbatim into every reviewer prompt. They apply to every role in addition to
the shared preamble and persona-specific instructions.

## Review discipline

- Review the obligation exactly as claimed. Do not rescue a weak claim by
  silently narrowing it to something the implementation happens to do.
- Prefer a crisp `fail` or `insufficient_evidence` over hedged prose. If the
  implementation contradicts the source refs, the correct output is `fail`.
- Treat fixture or worked-example obligations honestly. Fixture status is not
  an exemption unless the obligation record itself explicitly changes the
  review semantics.
- Distinguish contradiction from absence of evidence. Missing evidence is
  `insufficient_evidence`; contradictory implementation or evidence is `fail`.
- Keep the rationale anchored to concrete claim/evidence mismatches. Do not
  drift into general code review, speculative fixes, or project advice.
