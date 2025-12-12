// Global theme toggle for all pages
(function () {
  const KEY = "site-theme";
  function applyTheme(theme) {
    if (theme === "light") document.body.classList.add("theme-light");
    else document.body.classList.remove("theme-light");
    try { localStorage.setItem(KEY, theme); } catch {}
  }
  function initTheme() {
    let saved = "dark";
    try { saved = localStorage.getItem(KEY) || "dark"; } catch {}
    applyTheme(saved === "light" ? "light" : "dark");
  }
  function toggle() {
    const isLight = document.body.classList.contains("theme-light");
    applyTheme(isLight ? "dark" : "light");
  }
  document.addEventListener("DOMContentLoaded", () => {
    initTheme();
    const btn = document.getElementById("btn-theme-toggle");
    if (btn) btn.addEventListener("click", toggle);
  });
})();
