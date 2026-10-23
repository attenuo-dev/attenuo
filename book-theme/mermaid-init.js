// Renders ```mermaid blocks in the book. No mdBook preprocessor needed: mermaid is loaded
// from a pinned jsDelivr URL at view time. If it cannot load, the diagram source stays visible.
(function () {
  var blocks = document.querySelectorAll("pre > code.language-mermaid");
  if (!blocks.length) return;
  var dark = /\b(navy|coal|ayu)\b/.test(document.documentElement.className);
  import("https://cdn.jsdelivr.net/npm/mermaid@11.4.1/dist/mermaid.esm.min.mjs")
    .then(function (m) {
      var mermaid = m.default;
      mermaid.initialize({ startOnLoad: false, theme: dark ? "dark" : "default" });
      blocks.forEach(function (code) {
        var div = document.createElement("div");
        div.className = "mermaid";
        div.textContent = code.textContent;
        code.parentElement.replaceWith(div);
      });
      return mermaid.run({ querySelector: ".mermaid" });
    })
    .catch(function (e) {
      console.warn("mermaid failed to load", e);
    });
})();
