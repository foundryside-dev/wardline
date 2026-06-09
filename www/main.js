/* ============================================================================
   WARDLINE — front-door site interactions (progressive enhancement only)
   The page is content-complete without JS. This script only layers in:
     · copy-to-clipboard on the install command strip
     · hover-reveal anchor links on section headings (keyboard accessible)
   ============================================================================ */
(function () {
  "use strict";

  /* ---- Copy to clipboard for the install command strip ---------------- */
  var copyBtn = document.getElementById("install-copy-btn");
  var installText = document.getElementById("install-text");

  if (copyBtn && installText && navigator.clipboard) {
    copyBtn.addEventListener("click", function () {
      var text = installText.textContent.trim();
      navigator.clipboard.writeText(text).then(function () {
        var original = copyBtn.textContent;
        copyBtn.textContent = "copied!";
        copyBtn.setAttribute("aria-label", "Copied!");
        setTimeout(function () {
          copyBtn.textContent = original;
          copyBtn.setAttribute("aria-label", "Copy install command");
        }, 1600);
      }).catch(function () {
        /* clipboard unavailable — button does nothing, page still works */
      });
    });
  }

  /* ---- Hover-reveal anchor links on section headings ------------------ *
   * For each h2/h3 with an id in the page sections, inject a lightweight  *
   * "§" anchor link that appears on hover and is keyboard-reachable.      */
  var headings = Array.prototype.slice.call(
    document.querySelectorAll("main h2[id], main h3[id]")
  );
  headings.forEach(function (h) {
    var id = h.id;
    if (!id) return;
    var a = document.createElement("a");
    a.href = "#" + id;
    a.textContent = " §";
    a.setAttribute("aria-label", "Link to section: " + (h.textContent.replace(/\s§$/, "").trim()));
    a.style.cssText = [
      "font-size: 0.72em",
      "font-weight: 400",
      "color: var(--text-muted)",
      "text-decoration: none",
      "opacity: 0",
      "transition: opacity 0.15s",
      "vertical-align: middle",
      "margin-left: 0.35em"
    ].join(";");
    h.appendChild(a);
    h.style.position = "relative";

    /* show on parent heading hover */
    h.addEventListener("mouseenter", function () { a.style.opacity = "1"; });
    h.addEventListener("mouseleave", function () {
      if (document.activeElement !== a) a.style.opacity = "0";
    });
    /* always visible when focused */
    a.addEventListener("focus", function () { a.style.opacity = "1"; });
    a.addEventListener("blur", function () { a.style.opacity = "0"; });
  });

  /* ---- Sibling member row hover effect -------------------------------- */
  var memberRows = Array.prototype.slice.call(
    document.querySelectorAll(".bindings-member")
  );
  memberRows.forEach(function (row) {
    row.addEventListener("mouseenter", function () {
      row.style.background = "var(--surface-overlay)";
      row.style.textDecoration = "none";
    });
    row.addEventListener("mouseleave", function () {
      row.style.background = "var(--surface-raised)";
    });
    row.addEventListener("focus", function () {
      row.style.outline = "2px solid var(--accent)";
      row.style.outlineOffset = "2px";
    });
    row.addEventListener("blur", function () {
      row.style.outline = "";
    });
  });
})();
