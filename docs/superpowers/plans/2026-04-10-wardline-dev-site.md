# wardline.dev Documentation Site Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a static documentation site at wardline.dev using MkDocs Material, rendering existing docs from the repository with a dark-default theme, interactive severity matrix, and task-oriented landing page.

**Architecture:** MkDocs Material renders the existing `docs/` markdown into a static site. Custom CSS provides the dark indigo/cyan theme and severity matrix colouring. A small JS file enhances the matrix with tooltips and clickable cells. Built output is copied to `/var/www/wardline.dev` where Caddy already serves it.

**Tech Stack:** MkDocs 1.6.1, mkdocs-material 9.7.4, custom CSS, vanilla JS

---

## File Structure

```
mkdocs.yml                              — CREATE: MkDocs configuration
docs/index.md                           — CREATE: Landing page (task-oriented routing)
docs/stylesheets/custom.css             — CREATE: Theme overrides (dark indigo/cyan palette)
docs/stylesheets/severity-matrix.css    — CREATE: Matrix cell colouring
docs/javascripts/severity-matrix.js     — CREATE: Matrix tooltips + clickable cells
docs/specification.md                   — CREATE: Specification landing page (PDF link + GitHub link)
docs/assets/wardline-specification.pdf  — CREATE: Spec PDF (placeholder, user provides real one)
.gitignore                              — MODIFY: Add .superpowers/ and site/ entries
```

Existing files are NOT modified — MkDocs renders them as-is.

---

### Task 1: Create mkdocs.yml

**Files:**
- Create: `mkdocs.yml`

- [ ] **Step 1: Create the MkDocs configuration file**

```yaml
site_name: Wardline
site_url: https://www.wardline.dev
site_description: Semantic boundary enforcement for Python
repo_url: https://github.com/foundryside/wardline
repo_name: foundryside/wardline

theme:
  name: material
  palette:
    - scheme: slate
      primary: custom
      accent: cyan
      toggle:
        icon: material/brightness-4
        name: Switch to light mode
    - scheme: default
      primary: custom
      accent: cyan
      toggle:
        icon: material/brightness-7
        name: Switch to dark mode
  font:
    code: JetBrains Mono
  features:
    - navigation.sections
    - navigation.expand
    - navigation.indexes
    - navigation.top
    - search.highlight
    - search.suggest
    - content.code.copy
    - toc.follow

extra_css:
  - stylesheets/custom.css
  - stylesheets/severity-matrix.css

extra_javascript:
  - javascripts/severity-matrix.js

markdown_extensions:
  - tables
  - admonition
  - pymdownx.details
  - pymdownx.superfences
  - pymdownx.highlight:
      anchor_linenums: true
  - pymdownx.inlinehilite
  - attr_list
  - toc:
      permalink: true

nav:
  - Home: index.md
  - Getting Started: getting-started.md
  - Reference:
    - reference/index.md
    - Rules: reference/rules.md
    - Severity Matrix: reference/severity-matrix.md
    - Taint States: reference/taint-states.md
    - Decorators: reference/decorators.md
    - Supplementary Groups: reference/supplementary-groups.md
    - CLI: reference/cli.md
    - Manifest: reference/manifest.md
    - SARIF Format: reference/sarif-format.md
    - Error Messages: reference/error-messages.md
    - Governance Retention: reference/governance-retention.md
    - Glossary: reference/glossary.md
  - Guides:
    - Adopting Wardline: guides/adoption.md
    - CI Integration: guides/ci-integration.md
    - Governance: guides/governance.md
    - Analysis Levels: guides/analysis-levels.md
    - Profiles: guides/profiles.md
  - Troubleshooting: guides/troubleshooting.md
  - Specification: specification.md
```

- [ ] **Step 2: Verify the configuration parses**

Run: `cd /home/john/wardline && mkdocs build --strict 2>&1 | head -30`
Expected: Build warnings about missing CSS/JS files (not yet created), but no YAML parse errors. The build should complete.

- [ ] **Step 3: Commit**

```bash
git add mkdocs.yml
git commit -m "feat(site): add mkdocs.yml configuration for wardline.dev"
```

---

### Task 2: Create landing page (docs/index.md)

**Files:**
- Create: `docs/index.md`

- [ ] **Step 1: Create the task-oriented landing page**

```markdown
---
hide:
  - navigation
  - toc
---

# Wardline

Semantic boundary enforcement for Python. Catches untrusted input reaching
privileged code before it ships.

---

## I need to...

| Question | Start here |
|----------|-----------|
| Understand why a rule fired on my code | [Rules](reference/rules.md) then [Severity Matrix](reference/severity-matrix.md) |
| Know what severity or exceptionability applies | [Severity Matrix](reference/severity-matrix.md) |
| Pick the right decorator for a function | [Decorators](reference/decorators.md) |
| Understand a taint state like UNKNOWN_GUARDED | [Taint States](reference/taint-states.md) |
| Fix a scan error or warning | [Error Messages](reference/error-messages.md) |
| Consume wardline output in CI | [SARIF Format](reference/sarif-format.md) then [CLI](reference/cli.md) |
| Configure wardline.yaml or overlays | [Manifest](reference/manifest.md) |
| Set up wardline in my project | [Getting Started](getting-started.md) |
| Integrate with CI/CD | [CI Integration](guides/ci-integration.md) |
| Manage exceptions and governance | [Governance](guides/governance.md) |
| Choose between Lite and Assurance profiles | [Profiles](guides/profiles.md) |
| Look up a term I don't recognise | [Glossary](reference/glossary.md) |

---

[Getting Started](getting-started.md){ .md-button .md-button--primary }
[GitHub](https://github.com/foundryside/wardline){ .md-button }
[Specification (PDF)](assets/wardline-specification.pdf){ .md-button }
```

- [ ] **Step 2: Verify the page renders**

Run: `cd /home/john/wardline && mkdocs build --strict 2>&1 | tail -5`
Expected: Build succeeds. Check `site/index.html` exists.

- [ ] **Step 3: Commit**

```bash
git add docs/index.md
git commit -m "feat(site): add task-oriented landing page"
```

---

### Task 3: Create custom theme CSS

**Files:**
- Create: `docs/stylesheets/custom.css`

- [ ] **Step 1: Create the dark indigo/cyan theme overrides**

```css
/* Dark theme (default) — deep indigo with cyan accent */
[data-md-color-scheme="slate"] {
  --md-default-bg-color: #1a1a2e;
  --md-default-fg-color: #e0e7ff;
  --md-default-fg-color--light: #8b9dc3;
  --md-default-fg-color--lighter: #5a6b8a;
  --md-default-fg-color--lightest: #3d4f6f;
  --md-primary-fg-color: #06b6d4;
  --md-primary-bg-color: #1a1a2e;
  --md-accent-fg-color: #06b6d4;
  --md-typeset-a-color: #06b6d4;
  --md-code-bg-color: #2a2a4a;
  --md-code-fg-color: #e0e7ff;
  --md-footer-bg-color: #141428;
  --md-footer-fg-color: #8b9dc3;
}

/* Light theme overrides */
[data-md-color-scheme="default"] {
  --md-primary-fg-color: #0891b2;
  --md-accent-fg-color: #0891b2;
  --md-typeset-a-color: #0891b2;
}

/* Header bar — match dark background */
[data-md-color-scheme="slate"] .md-header {
  background-color: #141428;
}

/* Navigation sidebar */
[data-md-color-scheme="slate"] .md-sidebar {
  background-color: #1a1a2e;
}

/* Buttons on landing page */
.md-typeset .md-button--primary {
  background-color: #06b6d4;
  border-color: #06b6d4;
  color: #1a1a2e;
}

.md-typeset .md-button--primary:hover {
  background-color: #22d3ee;
  border-color: #22d3ee;
}

.md-typeset .md-button {
  border-color: #334155;
  color: #8b9dc3;
}

[data-md-color-scheme="slate"] .md-typeset .md-button:hover {
  border-color: #06b6d4;
  color: #06b6d4;
}

/* Table styling — tighter for reference tables */
.md-typeset table:not([class]) {
  font-size: 0.8rem;
}

.md-typeset table:not([class]) th {
  white-space: nowrap;
}
```

- [ ] **Step 2: Commit**

```bash
mkdir -p docs/stylesheets
git add docs/stylesheets/custom.css
git commit -m "feat(site): add dark indigo/cyan theme overrides"
```

---

### Task 4: Create severity matrix CSS

**Files:**
- Create: `docs/stylesheets/severity-matrix.css`

- [ ] **Step 1: Create the matrix cell colouring styles**

```css
/* Severity matrix cell colouring — applied by severity-matrix.js */

/* ERROR cells */
.severity-error {
  background-color: rgba(239, 68, 68, 0.15) !important;
  color: #ef4444 !important;
  font-weight: 600;
}

[data-md-color-scheme="default"] .severity-error {
  background-color: rgba(220, 38, 38, 0.1) !important;
  color: #dc2626 !important;
}

/* WARNING cells */
.severity-warning {
  background-color: rgba(245, 158, 11, 0.15) !important;
  color: #f59e0b !important;
  font-weight: 600;
}

[data-md-color-scheme="default"] .severity-warning {
  background-color: rgba(217, 119, 6, 0.1) !important;
  color: #b45309 !important;
}

/* SUPPRESS cells */
.severity-suppress {
  opacity: 0.5;
}

/* Hover tooltip container */
.matrix-cell {
  position: relative;
  cursor: pointer;
  padding: 4px 8px;
  border-radius: 3px;
  transition: opacity 0.15s;
  display: inline-block;
}

.matrix-cell:hover {
  opacity: 0.85;
}

/* Tooltip */
.matrix-cell[data-tooltip]::after {
  content: attr(data-tooltip);
  position: absolute;
  bottom: 100%;
  left: 50%;
  transform: translateX(-50%);
  background: #1e293b;
  color: #e2e8f0;
  padding: 6px 10px;
  border-radius: 4px;
  font-size: 0.7rem;
  white-space: nowrap;
  opacity: 0;
  pointer-events: none;
  transition: opacity 0.15s;
  z-index: 10;
  margin-bottom: 4px;
}

[data-md-color-scheme="default"] .matrix-cell[data-tooltip]::after {
  background: #334155;
  color: #f1f5f9;
}

.matrix-cell:hover[data-tooltip]::after {
  opacity: 1;
}

/* Clickable cell link styling */
.matrix-cell a {
  color: inherit !important;
  text-decoration: none !important;
}
```

- [ ] **Step 2: Commit**

```bash
git add docs/stylesheets/severity-matrix.css
git commit -m "feat(site): add severity matrix cell colouring CSS"
```

---

### Task 5: Create severity matrix JavaScript

**Files:**
- Create: `docs/javascripts/severity-matrix.js`

- [ ] **Step 1: Create the matrix enhancement script**

```javascript
// Severity matrix enhancement — colour-codes cells, adds tooltips,
// makes cells clickable to the relevant rule section.
//
// Targets the first <table> on /reference/severity-matrix/ pages.
// Parses cell text like "E/U" to determine severity and exceptionability.

document.addEventListener("DOMContentLoaded", function () {
  // Only run on the severity matrix page
  if (!window.location.pathname.includes("/severity-matrix")) return;

  var table = document.querySelector(".md-typeset table");
  if (!table) return;

  var SEVERITY = {
    E: { cls: "severity-error", label: "ERROR" },
    W: { cls: "severity-warning", label: "WARNING" },
    S: { cls: "severity-suppress", label: "SUPPRESS" },
  };

  var EXCEPTIONABILITY = {
    U: "UNCONDITIONAL — cannot be excepted",
    St: "STANDARD — requires reviewer approval",
    R: "RELAXED — exception with less scrutiny",
    T: "TRANSPARENT — auto-suppressed",
  };

  var rows = table.querySelectorAll("tbody tr");

  rows.forEach(function (row) {
    var cells = row.querySelectorAll("td");
    if (cells.length < 2) return;

    // First cell contains the rule link — extract the href for clickable cells
    var ruleLink = cells[0].querySelector("a");
    var ruleHref = ruleLink ? ruleLink.getAttribute("href") : null;

    // Process data cells (skip first column which is the rule name)
    for (var i = 1; i < cells.length; i++) {
      var cell = cells[i];
      var text = cell.textContent.trim();

      // Parse "E/U", "W/St", "S/T" etc.
      var parts = text.split("/");
      if (parts.length !== 2) continue;

      var sevKey = parts[0];
      var excKey = parts[1];

      var sev = SEVERITY[sevKey];
      if (!sev) continue;

      var excLabel = EXCEPTIONABILITY[excKey];
      if (!excLabel) continue;

      // Build tooltip text
      var tooltip = sev.label + " / " + excLabel;

      // Create the enhanced cell content
      var span = document.createElement("span");
      span.className = "matrix-cell " + sev.cls;
      span.setAttribute("data-tooltip", tooltip);
      span.textContent = text;

      // Make clickable if we have a rule link
      if (ruleHref) {
        var a = document.createElement("a");
        a.href = ruleHref;
        a.textContent = text;
        span.textContent = "";
        span.appendChild(a);
      }

      cell.textContent = "";
      cell.appendChild(span);
    }
  });
});
```

- [ ] **Step 2: Verify the build succeeds with all assets**

Run: `cd /home/john/wardline && mkdocs build --strict 2>&1 | tail -10`
Expected: Build completes. Verify assets are in place:

Run: `ls -la /home/john/wardline/site/stylesheets/ /home/john/wardline/site/javascripts/ 2>/dev/null`
Expected: `custom.css`, `severity-matrix.css` in stylesheets; `severity-matrix.js` in javascripts.

- [ ] **Step 3: Commit**

```bash
mkdir -p docs/javascripts
git add docs/javascripts/severity-matrix.js
git commit -m "feat(site): add severity matrix tooltips and clickable cells"
```

---

### Task 6: Add .gitignore entries and create spec PDF placeholder

**Files:**
- Modify: `.gitignore`
- Create: `docs/assets/wardline-specification.pdf`

- [ ] **Step 1: Add .superpowers/ and site/ to .gitignore**

Add these lines to the end of `/home/john/wardline/.gitignore`:

```
# MkDocs build output
site/

# Superpowers brainstorming sessions
.superpowers/
```

- [ ] **Step 2: Create the specification landing page**

Create `docs/specification.md`:

```markdown
# Specification

The Wardline Framework Specification is the normative reference for all
language bindings. It defines the authority tier model, pattern rules,
severity matrix, governance model, and conformance requirements.

## Download

[Wardline Framework Specification (PDF)](assets/wardline-specification.pdf){ .md-button .md-button--primary }

## Source

The specification source files are maintained in the repository:

[View on GitHub](https://github.com/foundryside/wardline/tree/main/docs/spec){ .md-button }

## Contents

- **Part I** — Framework specification (sections 1–15)
- **Part II-A** — Python language binding reference
- **Part II-B** — Java language binding reference
```

- [ ] **Step 3: Create the assets directory and a placeholder PDF**

The user will provide the real PDF later. For now, create an empty placeholder so the nav link does not 404.

Run: `mkdir -p /home/john/wardline/docs/assets && echo "Placeholder — replace with real specification PDF" > /home/john/wardline/docs/assets/wardline-specification.pdf`

- [ ] **Step 4: Commit**

```bash
git add .gitignore docs/specification.md docs/assets/wardline-specification.pdf
git commit -m "chore: add specification page, spec PDF placeholder, gitignore updates"
```

---

### Task 7: Build and deploy to /var/www/wardline.dev

**Files:**
- No new files created — this task builds and copies output

- [ ] **Step 1: Run a clean build**

Run: `cd /home/john/wardline && mkdocs build --clean --strict 2>&1`
Expected: Build completes with no errors. May show warnings about the PDF placeholder — that is fine.

- [ ] **Step 2: Verify the built site structure**

Run: `ls /home/john/wardline/site/`
Expected: `index.html`, `getting-started/`, `reference/`, `guides/`, `stylesheets/`, `javascripts/`, `assets/`, `search/`, `sitemap.xml`, etc.

Run: `head -20 /home/john/wardline/site/index.html`
Expected: HTML with "Wardline" in the title, Material theme markup.

- [ ] **Step 3: Deploy to the Caddy serve directory**

Run: `rsync -a --delete /home/john/wardline/site/ /var/www/wardline.dev/`

- [ ] **Step 4: Verify the live site**

Run: `curl -s -o /dev/null -w "%{http_code}" https://www.wardline.dev/`
Expected: `200`

Run: `curl -s https://www.wardline.dev/ | grep -o '<title>[^<]*</title>'`
Expected: `<title>Wardline</title>` (or similar with "Wardline" in the title)

- [ ] **Step 5: Verify the severity matrix page loads with assets**

Run: `curl -s https://www.wardline.dev/reference/severity-matrix/ | grep -c "severity-matrix.js"`
Expected: `1` (the JS file is referenced in the HTML)

Run: `curl -s https://www.wardline.dev/reference/severity-matrix/ | grep -c "severity-matrix.css"`
Expected: `1` (the CSS file is referenced in the HTML)

- [ ] **Step 6: Commit (no changes — build output is gitignored)**

No commit needed. The `site/` directory is in `.gitignore`.

---

### Task 8: Smoke test all pages

**Files:**
- No files — verification only

- [ ] **Step 1: Check all nav pages return 200**

Run the following to verify every page in the navigation:

```bash
for path in \
  "" \
  "getting-started/" \
  "reference/" \
  "reference/rules/" \
  "reference/severity-matrix/" \
  "reference/taint-states/" \
  "reference/decorators/" \
  "reference/supplementary-groups/" \
  "reference/cli/" \
  "reference/manifest/" \
  "reference/sarif-format/" \
  "reference/error-messages/" \
  "reference/governance-retention/" \
  "reference/glossary/" \
  "guides/adoption/" \
  "guides/ci-integration/" \
  "guides/governance/" \
  "guides/analysis-levels/" \
  "guides/profiles/" \
  "guides/troubleshooting/"; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://www.wardline.dev/${path}")
  echo "${code} /${path}"
done
```

Expected: All lines show `200`.

- [ ] **Step 2: Check search index exists**

Run: `curl -s -o /dev/null -w "%{http_code}" https://www.wardline.dev/search/search_index.json`
Expected: `200`

- [ ] **Step 3: Verify no broken internal links on the landing page**

Run: `curl -s https://www.wardline.dev/ | grep -oP 'href="[^"]*"' | grep -v "http" | sort -u`
Expected: All relative hrefs should correspond to pages that exist in the site. Spot-check a few.
