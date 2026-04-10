// Wardline Framework Specification — Typst template for pandoc output
//
// Design: professional technical specification in the style of ISO/NIST publications.
// Fonts: TeX Gyre Heros (headings), Libertinus Serif (body), Liberation Mono (code)
// Colours: deep steel blue #1E3A5F (primary), teal #0D7377 (accent), warm grey for rules
//
// Pandoc variables used:
//   $title$, $subtitle$, $author$, $date$, $version$, $status$

// ─────────────────────────────────────────────────────────────
// COLOUR PALETTE
// ─────────────────────────────────────────────────────────────
#let c-navy    = rgb("#1E3A5F")   // primary — headings, title page, rules
#let c-teal    = rgb("#0A6E72")   // accent — links, code border, highlight
#let c-rule    = rgb("#C8CDD3")   // horizontal rules, table borders
#let c-muted   = rgb("#5A6370")   // secondary text (headers, captions, labels)
#let c-shade   = rgb("#F4F5F6")   // code block and table-header fill
#let c-warning = rgb("#7A3B00")   // DRAFT watermark / status chip

// ─────────────────────────────────────────────────────────────
// DOCUMENT METADATA
// ─────────────────────────────────────────────────────────────
#set document(
  title: "$title$",
  author: "$author$",
)

// ─────────────────────────────────────────────────────────────
// TYPOGRAPHY — BASE
// ─────────────────────────────────────────────────────────────
#set text(
  font: ("Libertinus Serif", "DejaVu Serif"),
  size: 10.5pt,
  lang: "en",
  region: "AU",
  hyphenate: true,
  // Slightly tighter fill than pure black reads better on screen at small sizes
  fill: rgb("#1A1A1A"),
)

#set par(
  justify: true,
  leading: 0.72em,
  spacing: 1.1em,
)

// ─────────────────────────────────────────────────────────────
// PAGE GEOMETRY + HEADER / FOOTER
// ─────────────────────────────────────────────────────────────

// We use a state variable to track whether we are inside front matter
// (title page + ToC) vs body, so the header/footer can differ.
#let body-started = state("body-started", false)

#set page(
  paper: "a4",
  // Wider left margin gives a subtle asymmetry — professional publication feel.
  // Extra bottom room for footer rule + page number.
  margin: (top: 2.6cm, bottom: 2.8cm, left: 2.8cm, right: 2.2cm),

  header: context {
    let pg = counter(page).get().first()
    // Suppress header on the title page (page 1) and the page immediately
    // after (ToC cover), which we handle as page 2.
    if pg > 1 and body-started.get() [
      // Thin rule across the top, then running head
      #line(length: 100%, stroke: 0.5pt + c-rule)
      #v(2pt)
      #set text(7.5pt, font: "TeX Gyre Heros", fill: c-muted, tracking: 0.5pt)
      #upper[Wardline Framework Specification]
      #h(1fr)
      #upper[$status$ v$version$]
    ]
  },

  footer: context {
    let pg = counter(page).get().first()
    if pg > 1 [
      #v(2pt)
      #line(length: 100%, stroke: 0.5pt + c-rule)
      #v(3pt)
      #set text(7.5pt, font: "TeX Gyre Heros", fill: c-muted)
      // Left: document identifier
      WFS-$version$
      #h(1fr)
      // Centre: page number with decorative treatment
      #box(
        fill: c-navy,
        inset: (x: 6pt, y: 2.5pt),
        radius: 2pt,
      )[
        #set text(7pt, fill: white, weight: "bold", tracking: 0.5pt)
        #counter(page).display("1")
      ]
      #h(1fr)
      // Right: status chip
      #box(
        fill: if "$status$" == "DRAFT" { rgb("#FEF3C7") }
             else if "$status$" == "RELEASE CANDIDATE" { rgb("#DBEAFE") }
             else { rgb("#DCFCE7") },
        inset: (x: 5pt, y: 2pt),
        radius: 2pt,
      )[
        #set text(
          6.5pt,
          fill: if "$status$" == "DRAFT" { c-warning }
               else if "$status$" == "RELEASE CANDIDATE" { rgb("#1E40AF") }
               else { rgb("#166534") },
          weight: "bold",
          tracking: 0.8pt,
          font: "TeX Gyre Heros",
        )
        #upper[$status$]
      ]
    ]
  },
)

// ─────────────────────────────────────────────────────────────
// HEADING STYLES
// ─────────────────────────────────────────────────────────────

// Level 1 — Chapter / Part heading
// Left navy accent bar, then heading text, then full-width rule below.
#show heading.where(level: 1): it => {
  pagebreak(weak: true)
  v(0.8cm)
  // Use grid to place the accent bar and heading text side by side
  grid(
    columns: (6pt, 1fr),
    column-gutter: 10pt,
    // Accent bar: full height of the text block
    rect(width: 6pt, height: 1.5em, fill: c-navy, stroke: none),
    // Heading text
    text(
      font: "TeX Gyre Heros",
      size: 17pt,
      weight: "bold",
      fill: c-navy,
    )[#it.body],
  )
  v(0.5em)
  line(length: 100%, stroke: 0.6pt + c-rule)
  v(0.45cm)
}

// Level 2 — Section heading
#show heading.where(level: 2): it => {
  v(0.9em)
  block(width: 100%)[
    #text(
      font: "TeX Gyre Heros",
      size: 13.5pt,
      weight: "bold",
      fill: c-navy,
    )[#it.body]
    #v(-2pt)
    // Short teal underline for visual accent
    #line(length: 40pt, stroke: 2pt + c-teal)
  ]
  v(0.35em)
}

// Level 3 — Sub-section heading
#show heading.where(level: 3): it => {
  v(0.75em)
  text(
    font: "TeX Gyre Heros",
    size: 11.5pt,
    weight: "bold",
    fill: c-navy,
  )[#it.body]
  v(0.25em)
}

// Level 4 — Minor heading (run-in style with small-caps)
#show heading.where(level: 4): it => {
  v(0.5em)
  text(
    font: "TeX Gyre Heros",
    size: 10.5pt,
    weight: "bold",
    fill: c-muted,
  )[#it.body]
  v(0.15em)
}

// ─────────────────────────────────────────────────────────────
// CODE BLOCKS
// ─────────────────────────────────────────────────────────────
#show raw.where(block: true): it => {
  set text(8.5pt, font: ("Liberation Mono", "DejaVu Sans Mono"))
  // Left border strip in teal, body on light grey
  block(
    width: 100%,
    radius: (right: 3pt),
    clip: true,
    fill: c-shade,
    stroke: (left: 3pt + c-teal),
    inset: (left: 12pt, right: 12pt, top: 10pt, bottom: 10pt),
    it,
  )
}

#show raw.where(block: false): it => {
  set text(8pt, font: ("Liberation Mono", "DejaVu Sans Mono"))
  box(
    fill: c-shade,
    stroke: 0.5pt + c-rule,
    inset: (x: 3pt, y: 1.5pt),
    radius: 2pt,
    it,
  )
}

// ─────────────────────────────────────────────────────────────
// TABLES
// ─────────────────────────────────────────────────────────────
//
// Pandoc emits: #figure(align(center)[#table(columns: ..., table.header([...]), table.hline(), [...])])
//
// Strategy:
// - set table() globally: no internal stroke, generous inset, alternating fills
// - table.header row gets navy fill + white bold text via table.cell show rule
// - show table: wraps in a rect for a clean outer border
// - show figure: removes pandoc's centering and lets table span full width

// Global table defaults: alternating row fills, no internal borders, left-aligned cells
#set table(
  stroke: (x, y) => (
    top: if y <= 1 { 0.5pt + c-rule } else { 0pt },
    bottom: 0pt,
    left: 0pt,
    right: 0pt,
  ),
  fill: (col, row) => {
    if row == 0 { c-navy }           // header row: navy
    else if calc.odd(row) { c-shade } // odd rows: light grey
    else { white }                    // even rows: white
  },
  inset: (x: 9pt, y: 7pt),
  align: left,                        // left-align all cells; headers override below
)

// Table cell typography:
//   row 0 (header): Heros bold white
//   other rows: Heros regular, near-black, no justification
#show table.cell: it => {
  if it.y == 0 {
    set text(
      font: "TeX Gyre Heros",
      size: 9pt,
      weight: "bold",
      fill: white,
      tracking: 0.2pt,
    )
    it
  } else {
    set par(justify: false)
    set text(
      font: ("TeX Gyre Heros", "Liberation Sans"),
      size: 8pt,
      fill: rgb("#1A1A1A"),
    )
    it
  }
}

// Ensure tables can break across pages
#show table: set block(breakable: true)

// ─────────────────────────────────────────────────────────────
// FIGURES (wrapping tables from pandoc)
// ─────────────────────────────────────────────────────────────
// Allow figures (pandoc's table wrapper) to break across pages
#set figure(placement: none)
#show figure: set block(breakable: true)
#show figure: it => {
  // Remove the default centering that pandoc wraps tables in — our table
  // show rule handles width already.
  set align(left)
  it.body
}

// ─────────────────────────────────────────────────────────────
// LISTS
// ─────────────────────────────────────────────────────────────
#set list(
  indent: 1.2em,
  body-indent: 0.6em,
  marker: ([#text(fill: c-teal)[▸]], [–], [·]),
)

#set enum(
  indent: 1.2em,
  body-indent: 0.6em,
  numbering: "1.",
)

// ─────────────────────────────────────────────────────────────
// LINKS
// ─────────────────────────────────────────────────────────────
#show link: it => {
  set text(fill: c-teal)
  it
}

// ─────────────────────────────────────────────────────────────
// FOOTNOTES
// ─────────────────────────────────────────────────────────────
#show footnote.entry: it => {
  set text(8pt)
  // Shrink inline code inside footnotes to match surrounding text
  show raw.where(block: false): r => {
    set text(7pt, font: ("Liberation Mono", "DejaVu Sans Mono"))
    box(
      fill: c-shade,
      stroke: 0.5pt + c-rule,
      inset: (x: 2.5pt, y: 1pt),
      radius: 2pt,
      r,
    )
  }
  it
}

// ─────────────────────────────────────────────────────────────
// BLOCK QUOTES (used for normative callouts in spec)
// ─────────────────────────────────────────────────────────────
#show quote.where(block: true): it => {
  pad(left: 0pt)[
    #block(
      stroke: (left: 3pt + c-navy),
      inset: (left: 14pt, right: 8pt, top: 8pt, bottom: 8pt),
      fill: rgb("#EEF2F7"),
      radius: (right: 3pt),
      width: 100%,
    )[
      #set text(size: 10pt, style: "normal")
      #set par(leading: 0.65em, spacing: 0.75em)
      #it.body
    ]
  ]
}

// ─────────────────────────────────────────────────────────────
// OUTLINE (TABLE OF CONTENTS)
// ─────────────────────────────────────────────────────────────
//
// Typst 0.14: outline.entry exposes .element (the heading) and .page
// (the page number content), but not .body directly. We reconstruct
// the heading label from .element.body.
//
#show outline.entry: it => {
  let level = it.level
  let label = it.element.body
  let pg = counter(page).at(it.element.location()).first()

  if level == 1 {
    // Chapter entries: bold, navy, generous top spacing
    v(12pt, weak: true)
    box(width: 100%)[
      #text(
        font: "TeX Gyre Heros",
        size: 10pt,
        weight: "bold",
        fill: c-navy,
      )[#label]
      #h(1fr)
      #text(
        font: "TeX Gyre Heros",
        size: 10pt,
        weight: "bold",
        fill: c-navy,
      )[#str(pg)]
    ]
  } else if level == 2 {
    // Section entries: indented, dot leaders
    v(5pt, weak: true)
    box(width: 100%)[
      #h(1.4em)
      #text(
        font: "TeX Gyre Heros",
        size: 9pt,
        fill: rgb("#2D3748"),
      )[#label]
      #box(width: 1fr)[
        #set text(fill: rgb("#C8CDD3"), size: 9pt)
        #repeat[.]
      ]
      #text(
        font: "TeX Gyre Heros",
        size: 9pt,
        fill: c-muted,
      )[#str(pg)]
    ]
  } else {
    // Deep entries: deeper indent, smaller, muted
    v(4pt, weak: true)
    box(width: 100%)[
      #h(2.8em)
      #text(
        font: "TeX Gyre Heros",
        size: 8.5pt,
        fill: c-muted,
      )[#label]
      #box(width: 1fr)[
        #set text(fill: rgb("#C8CDD3"), size: 8.5pt)
        #repeat[.]
      ]
      #text(
        font: "TeX Gyre Heros",
        size: 8.5pt,
        fill: c-muted,
      )[#str(pg)]
    ]
  }
  linebreak()
}

// ─────────────────────────────────────────────────────────────
// TITLE PAGE
// ─────────────────────────────────────────────────────────────
//
// Design: full-bleed navy header band placed with negative offset to reach
// past the page margins to the physical page edge. Teal accent stripe
// below. Document control metadata table and scope blurb below that.
//
// The page margin is: top=2.6cm, left=2.8cm, right=2.2cm.
// A4 width = 210mm. Content width = 210mm - 2.8cm - 2.2cm = 165mm.
// A4 height = 297mm.
//
// We use place() with dx/dy to position the bleed bands absolutely.

// ── Bleed bands (placed behind content flow) ──────────────────
// Navy header band: full page width, top-aligned, extends from physical
// top edge down 5.5cm.
#place(
  top + left,
  dx: -2.8cm,   // negate left margin to reach physical left edge
  dy: -2.6cm,   // negate top margin to reach physical top edge
  rect(
    width: 21cm,    // A4 full width
    height: 5.5cm,
    fill: c-navy,
  )
)

// Teal accent stripe immediately below navy band
#place(
  top + left,
  dx: -2.8cm,
  dy: -2.6cm + 5.5cm,
  rect(
    width: 21cm,
    height: 6pt,
    fill: c-teal,
  )
)

// ── Title text over the navy band ─────────────────────────────
// Placed absolutely over the navy band. Use a fixed-width block so
// the text doesn't collapse to zero width.
// Band is at content-area y = 0 to 2.9cm (5.5cm - 2.6cm margin).
// We position at y = 0.5cm to give top breathing room.
#place(
  top + left,
  dy: 0.5cm,
  block(width: 16.5cm)[
    #set text(font: "TeX Gyre Heros")
    #text(
      size: 7.5pt,
      fill: rgb("#7FAFD4"),
      tracking: 2.5pt,
      weight: "bold",
    )[#upper[Technical Specification]]
    #linebreak()
    #v(0.25em)
    #text(
      size: 25pt,
      fill: white,
      weight: "bold",
    )[$title$]
  ]
)

// Spacer to push content flow below the navy band + accent stripe + gap
// Band bottom relative to content area: 5.5cm - 2.6cm = 2.9cm
// Add 6pt accent stripe + 1.2cm breathing room
#v(2.9cm + 6pt + 1.2cm)

// ── Subtitle ──────────────────────────────────────────────────
#text(
  font: "TeX Gyre Heros",
  size: 13.5pt,
  fill: c-navy,
  weight: "bold",
)[$subtitle$]

#v(0.5cm)

// Thin separator
#line(length: 100%, stroke: 0.5pt + c-rule)

#v(0.6cm)

// ── Document control table ────────────────────────────────────
// The show table rule will add the outer rect border automatically.
// We override fill/stroke locally to keep the document-control look
// independent of any future changes to the global table defaults.
#table(
  columns: (130pt, 1fr),
  stroke: none,
  inset: (x: 12pt, y: 7pt),
  fill: (col, row) => if row == 0 { c-navy } else if calc.odd(row) { c-shade } else { white },
  // Header row
  table.cell(colspan: 2)[
    #text(
      font: "TeX Gyre Heros",
      size: 7pt,
      fill: rgb("#8BAFD4"),
      weight: "bold",
      tracking: 1.5pt,
    )[#upper[Document Control]]
  ],
  // Data rows — label + value
  [#text(font: "TeX Gyre Heros", size: 9pt, fill: c-muted, weight: "bold")[Status]],
  [#text(font: "TeX Gyre Heros", size: 9pt)[$status$ v$version$]],
  [#text(font: "TeX Gyre Heros", size: 9pt, fill: c-muted, weight: "bold")[Date]],
  [#text(font: "TeX Gyre Heros", size: 9pt)[$date$]],
  [#text(font: "TeX Gyre Heros", size: 9pt, fill: c-muted, weight: "bold")[Document type]],
  [#text(font: "TeX Gyre Heros", size: 9pt)[Conformity assessment scheme]],
  [#text(font: "TeX Gyre Heros", size: 9pt, fill: c-muted, weight: "bold")[Identifier]],
  [#text(font: "TeX Gyre Heros", size: 9pt)[WFS-$version$]],
)

#v(0.8cm)

// ── Scope blurb ───────────────────────────────────────────────
#block(
  stroke: (left: 3pt + c-teal),
  inset: (left: 14pt, right: 8pt, top: 8pt, bottom: 8pt),
  fill: rgb("#EEF2F7"),
  radius: (right: 3pt),
  width: 100%,
)[
  #set text(font: "TeX Gyre Heros", size: 9pt, fill: c-muted)
  This document comprises Part I (framework specification, §§1–15) and Part II (language binding references for Python and Java). It defines the Wardline trust hierarchy, enforcement semantics, annotation vocabulary, governance model, and conformance criteria.
]

#v(1fr)

// ── Bottom metadata row ───────────────────────────────────────
#set text(font: "TeX Gyre Heros", size: 8.5pt, fill: c-muted)
#grid(
  columns: (1fr, 1fr),
  gutter: 1.5em,
  [
    *Part I — Framework Specification* \
    §§1–15: trust model, enforcement rules, \
    governance, conformance criteria
  ],
  [
    *Part II — Language Binding Reference* \
    Appendix A: Python binding \
    Appendix B: Java binding
  ],
)

#pagebreak()

// ─────────────────────────────────────────────────────────────
// TABLE OF CONTENTS PAGE
// ─────────────────────────────────────────────────────────────

// ToC page header — plain block, no running header yet
#block(width: 100%)[
  #text(
    font: "TeX Gyre Heros",
    size: 18pt,
    weight: "bold",
    fill: c-navy,
  )[Contents]
  #v(3pt)
  #line(length: 100%, stroke: 1pt + c-navy)
  #v(4pt)
  #line(length: 100%, stroke: 0.4pt + c-rule)
]

#v(0.6cm)

#outline(
  title: none,   // we rendered the title above
  indent: 0pt,   // we control indent in the show outline.entry rule
  depth: 3,
)

#pagebreak()

// ─────────────────────────────────────────────────────────────
// BODY CONTENT (from pandoc)
// ─────────────────────────────────────────────────────────────

// From this point the running header is visible
#body-started.update(true)

$body$
