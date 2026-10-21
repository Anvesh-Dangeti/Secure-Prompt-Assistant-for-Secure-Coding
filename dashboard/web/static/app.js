// Secure Prompt Assistant -- the only page script besides the vendored htmx.
// The CSP forbids inline scripts and inline event handlers, so behaviour is attached here, by data attributes
// whose values are our own element ids. Text is moved with textContent / value only, never as HTML.
(function () {
  "use strict";

  function flash(button, text) {
    var original = button.textContent;
    button.textContent = text;
    window.setTimeout(function () { button.textContent = original; }, 1500);
  }

  document.addEventListener("click", function (event) {
    var copy = event.target.closest("[data-copy]");
    if (copy) {
      var source = document.getElementById(copy.getAttribute("data-copy"));
      if (source && navigator.clipboard) {
        navigator.clipboard.writeText(source.textContent).then(function () { flash(copy, "Copied"); });
      }
      return;
    }
    var fill = event.target.closest("[data-fill-from]");
    if (fill) {
      var from = document.getElementById(fill.getAttribute("data-fill-from"));
      var to = document.getElementById(fill.getAttribute("data-fill-to"));
      if (from && to) {
        to.value = from.textContent;
        to.focus();
        to.scrollIntoView({ block: "center" });
      }
    }
  });

  // A <select data-autosubmit> submits its own form when changed (the project switcher, finding pickers).
  document.addEventListener("change", function (event) {
    var select = event.target.closest("select[data-autosubmit]");
    if (select && select.form) {
      if (select.form.requestSubmit) { select.form.requestSubmit(); } else { select.form.submit(); }
    }
  });
})();
