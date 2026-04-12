-- fix-tables.lua — Data-driven table column width overrides for Wardline PDF pipeline.
--
-- Loads table profiles from table-profiles.json and applies column widths based on
-- header text matching. This replaces the previous hard-coded profile approach.
--
-- Profile matching:
--   - col_N: exact match (lowercase, trimmed) against header cell N
--   - col_N_contains: substring match against header cell N
--   - cols: exact column count match (required)

local script_dir = PANDOC_SCRIPT_FILE:match("(.*[/\\])")
local profiles_path = script_dir .. "table-profiles.json"

-- Load and parse the JSON profiles file
local function load_profiles()
  local file = io.open(profiles_path, "r")
  if not file then
    io.stderr:write("[warn] Could not open " .. profiles_path .. "\n")
    return {}
  end
  local content = file:read("*a")
  file:close()

  local ok, data = pcall(function()
    return pandoc.json.decode(content)
  end)

  if not ok or not data or not data.profiles then
    io.stderr:write("[warn] Could not parse " .. profiles_path .. "\n")
    return {}
  end

  return data.profiles
end

local PROFILES = load_profiles()

-- Extract text from a table cell, lowercased and trimmed
local function cell_text(cell)
  return pandoc.utils.stringify(cell.contents):lower():gsub("^%s+", ""):gsub("%s+$", "")
end

-- Get header texts from table's first header row
local function header_texts(tbl)
  if #tbl.head.rows == 0 then return {} end
  local texts = {}
  for _, cell in ipairs(tbl.head.rows[1].cells) do
    texts[#texts + 1] = cell_text(cell)
  end
  return texts
end

-- Check if string starts with prefix
local function starts(s, prefix)
  return s:sub(1, #prefix) == prefix
end

-- Check if string contains substring
local function has(s, sub)
  return s:find(sub, 1, true) ~= nil
end

-- Match a profile against header texts
local function matches_profile(profile, headers, col_count)
  -- Column count must match exactly
  if profile.cols ~= col_count then
    return false
  end

  local match = profile.match
  if not match then
    return false
  end

  -- Check each match criterion
  for key, value in pairs(match) do
    -- Parse the key: col_N or col_N_contains
    local col_num, match_type = key:match("^col_(%d+)(.*)$")
    if col_num then
      col_num = tonumber(col_num)
      local header = headers[col_num]
      if not header then
        return false
      end

      if match_type == "" then
        -- Exact match (starts with)
        if not starts(header, value) then
          return false
        end
      elseif match_type == "_contains" then
        -- Substring match
        if not has(header, value) then
          return false
        end
      else
        -- Unknown match type
        return false
      end
    end
  end

  return true
end

-- Find matching profile for a table
local function find_profile(headers, col_count)
  for _, profile in ipairs(PROFILES) do
    if matches_profile(profile, headers, col_count) then
      return profile
    end
  end
  return nil
end

-- Main table filter function
function Table(tbl)
  local headers = header_texts(tbl)
  local col_count = #tbl.colspecs

  if #headers == 0 then
    return nil
  end

  local profile = find_profile(headers, col_count)
  if not profile then
    return nil
  end

  -- Apply column widths from profile
  for i, width in ipairs(profile.widths) do
    if i <= col_count then
      tbl.colspecs[i] = {tbl.colspecs[i][1], width}
    end
  end

  return tbl
end
