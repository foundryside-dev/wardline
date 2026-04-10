// Wardline Framework Specification — Typst template for pandoc output
//
// Produces a formal, understated PDF with:
// - Title page with metadata
// - Auto-generated table of contents
// - Numbered headings
// - Clean table formatting

#set document(
  title: "$title$",
  author: "$author$",
)

#set page(
  paper: "a4",
  margin: (top: 3cm, bottom: 3cm, left: 2.5cm, right: 2.5cm),
  header: context {
    if counter(page).get().first() > 1 [
      #set text(8pt, fill: luma(120))
      #smallcaps[$title$]
      #h(1fr)
      #smallcaps[$status$ v$version$]
    ]
  },
  footer: context {
    if counter(page).get().first() > 1 [
      #set text(8pt, fill: luma(120))
      #h(1fr)
      #counter(page).display("1")
      #h(1fr)
    ]
  },
)

#set text(
  font: "Libertinus Serif",
  size: 10.5pt,
  lang: "en",
  region: "AU",
)

#set par(
  justify: true,
  leading: 0.65em,
)

#set heading(numbering: "1.1")

#show heading.where(level: 1): it => {
  pagebreak(weak: true)
  v(1cm)
  set text(16pt, weight: "bold")
  block(it)
  v(0.5cm)
}

#show heading.where(level: 2): it => {
  v(0.8cm)
  set text(13pt, weight: "bold")
  block(it)
  v(0.3cm)
}

#show heading.where(level: 3): it => {
  v(0.5cm)
  set text(11pt, weight: "bold")
  block(it)
  v(0.2cm)
}

// Code blocks
#show raw.where(block: true): it => {
  set text(9pt, font: "DejaVu Sans Mono")
  block(
    fill: luma(245),
    inset: 12pt,
    radius: 3pt,
    width: 100%,
    it,
  )
}

#show raw.where(block: false): it => {
  set text(9.5pt, font: "DejaVu Sans Mono")
  box(
    fill: luma(240),
    inset: (x: 3pt, y: 1pt),
    radius: 2pt,
    it,
  )
}

// Tables
#show table: set text(9pt)

// Links
#show link: it => {
  set text(fill: rgb("#0891b2"))
  it
}

// --- Title page ---

#v(4cm)

#align(center)[
  #text(28pt, weight: "bold")[$title$]

  #v(0.5cm)

  #text(14pt, fill: luma(80))[$subtitle$]

  #v(2cm)

  #text(11pt)[
    #table(
      columns: (auto, auto),
      stroke: none,
      align: (right, left),
      row-gutter: 6pt,
      [*Status:*], [$status$ v$version$],
      [*Date:*], [$date$],
    )
  ]
]

#v(2cm)

#align(center)[
  #text(9pt, fill: luma(120))[
    This document comprises Part I (framework specification, sections 1–15) \
    and Part II (language binding references for Python and Java).
  ]
]

#pagebreak()

// --- Table of contents ---

#outline(
  title: [Contents],
  indent: 1.5em,
  depth: 3,
)

#pagebreak()

// --- Body ---

$body$
