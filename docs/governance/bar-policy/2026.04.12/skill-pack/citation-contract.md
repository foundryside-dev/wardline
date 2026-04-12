# BAR skill pack — citation contract

The `CITATIONS:` section is part of the review contract and is the only
authoritative source of persisted citations.

- Cite only by exact token from the allowed citation token list supplied
  below for this review.
- Put citation tokens in the `CITATIONS:` section, one bullet per token, and
  wrap each token in backticks so it can be extracted without guessing.
- Prefer the smallest stable token that supports the point:
  `source_ref:<selector>` for a normative clause,
  a repository path for implementation or source excerpts,
  or `evidence_class_outputs:<class_name>` / 
  `evidence_class_outputs:<class_name>:<target>` for evidence outputs.
- Do not invent line numbers, ranges, or identifiers that were not supplied
  in the allowed citation token list.
- Do not place long prose fragments or copied code excerpts inside backticks;
  those are not citations.
- Do not rely on citations embedded in the `RATIONALE:` prose. The BAR runner
  persists only the tokens listed in the `CITATIONS:` section.

Allowed citation tokens for this review:
{allowed_citations_content}
