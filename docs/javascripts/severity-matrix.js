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
