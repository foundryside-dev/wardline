-- fix-tables.lua — Pandoc Lua filter for the Wardline specification PDF pipeline.
--
-- Overrides pandoc-computed table column widths based on header cell content.
-- Replaces the fragile sed-based column-width fixups in build-spec.sh.
--
-- Each profile identifies a table by its header text and column count, then
-- applies hand-tuned column widths optimised for the A4 Typst layout.

local function cell_text(cell)
  return pandoc.utils.stringify(cell.contents):lower():gsub("^%s+", ""):gsub("%s+$", "")
end

local function header_texts(tbl)
  if #tbl.head.rows == 0 then return {} end
  local texts = {}
  for _, cell in ipairs(tbl.head.rows[1].cells) do
    texts[#texts + 1] = cell_text(cell)
  end
  return texts
end

local function starts(s, prefix)
  return s:sub(1, #prefix) == prefix
end

local function has(s, sub)
  return s:find(sub, 1, true) ~= nil
end

-- Column-width profiles.  Order matters: first match wins.
-- widths are fractions of page content width (must sum to ~1.0).
local profiles = {
  -- §5.1  Four tiers (Tier | Classification | Meaning | Verification basis)
  { match = function(h, n)
      return n == 4 and starts(h[1], "tier") and has(h[2], "classification")
    end,
    widths = {0.20, 0.18, 0.34, 0.28} },

  -- §6.1  Taint join (Operand A | Operand B | Result | Examples)
  { match = function(h, n)
      return n == 4 and starts(h[1], "operand")
    end,
    widths = {0.25, 0.25, 0.22, 0.28} },

  -- §6.1  Cross-product (Classification | Not Applicable | Raw | Shape | Sem | Rationale)
  { match = function(h, n)
      return n == 6 and starts(h[1], "classification") and has(h[2], "not applicable")
    end,
    widths = {0.15, 0.15, 0.11, 0.13, 0.13, 0.33} },

  -- §6.3  Restoration evidence (Structural | Semantic | Integrity | Institutional | Restored Tier)
  { match = function(h, n)
      return n == 5 and starts(h[1], "structural") and has(h[5] or "", "restored")
    end,
    widths = {0.12, 0.12, 0.12, 0.14, 0.50} },

  -- §7   Annotation vocabulary (# | Group | Institutional Knowledge | Key Declarations | Enforcement Consequences)
  { match = function(h, n)
      return n == 5 and h[1] == "#" and starts(h[2], "group") and has(h[3] or "", "institutional")
    end,
    widths = {0.03, 0.07, 0.28, 0.22, 0.40} },

  -- §10.2  Governance mechanisms (Mechanism | Lite | Assurance | Enforcement | Reference)
  { match = function(h, n)
      return n == 5 and starts(h[1], "mechanism") and has(h[2], "lite")
    end,
    widths = {0.24, 0.12, 0.24, 0.24, 0.16} },

  -- §11   Adversarial specimen categories (Category | Description | Minimum Count | Target)
  { match = function(h, n)
      return n == 4 and starts(h[1], "category") and has(h[3] or "", "minimum")
    end,
    widths = {0.18, 0.26, 0.18, 0.38} },

  -- §13   Residual risks (# | Risk | Primary Compensating Control)
  { match = function(h, n)
      return n == 3 and h[1] == "#" and has(h[2], "risk") and has(h[3] or "", "compensating")
    end,
    widths = {0.05, 0.25, 0.70} },

  -- §14.1  Manifest files (File | Format | Authored By | Purpose | Artefact class)
  { match = function(h, n)
      return n == 5 and starts(h[1], "file") and has(h[3] or "", "authored")
    end,
    widths = {0.14, 0.10, 0.14, 0.22, 0.40} },

  -- §15.3.2  Governance profiles (Profile | What it covers | Criteria | Typical implementer)
  { match = function(h, n)
      return n == 4 and starts(h[1], "profile") and has(h[2], "what it covers")
    end,
    widths = {0.12, 0.22, 0.36, 0.30} },

  -- §15.3.2  Governance requirements (Requirement | Status | Notes)
  { match = function(h, n)
      return n == 3 and starts(h[1], "requirement") and h[2] == "status" and h[3] == "notes"
    end,
    widths = {0.35, 0.15, 0.50} },

  -- §15.3  Adoption phase (Adoption Phase | Python | Java | Conformance Profile)
  { match = function(h, n)
      return n == 4 and has(h[1], "adoption phase")
    end,
    widths = {0.10, 0.25, 0.35, 0.30} },

  -- A.4.2  Decorator mapping — Python (# | Group | Python Decorator(s) | Signature | Scanner Checks)
  { match = function(h, n)
      return n == 5 and h[1] == "#" and starts(h[2], "group") and has(h[3] or "", "python")
    end,
    widths = {0.04, 0.14, 0.28, 0.28, 0.26} },

  -- A.11  Conformance criteria mapping (# | Criterion | Implementation | Evidence)
  { match = function(h, n)
      return n == 4 and h[1] == "#" and has(h[2], "criterion")
    end,
    widths = {0.05, 0.25, 0.35, 0.35} },

  -- B.2 / A.11 assessment tables (Criterion | Assessment | Detail)
  { match = function(h, n)
      return n == 3 and starts(h[1], "criterion") and has(h[2], "assessment")
    end,
    widths = {0.30, 0.35, 0.35} },

  -- B.4.3  Annotation mapping — Java (Group | Abstract | Java Annotation | Signature | Description)
  { match = function(h, n)
      return n == 5 and starts(h[1], "group") and has(h[2], "abstract") and has(h[3] or "", "java")
    end,
    widths = {0.05, 0.15, 0.20, 0.25, 0.35} },
}

function Table(tbl)
  local h = header_texts(tbl)
  local n = #tbl.colspecs
  if #h == 0 then return nil end

  for _, p in ipairs(profiles) do
    if p.match(h, n) then
      for i, w in ipairs(p.widths) do
        if i <= n then
          tbl.colspecs[i] = {tbl.colspecs[i][1], w}
        end
      end
      return tbl
    end
  end

  return nil
end
