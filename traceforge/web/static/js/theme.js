/**
 * TraceForge Theme Controller
 * Manages Light, Dark, and System theme preferences.
 */

const THEME_STORAGE_KEY = "traceforge_theme";

export function initTheme() {
  const currentTheme = localStorage.getItem(THEME_STORAGE_KEY) || "system";
  applyTheme(currentTheme);

  document.querySelectorAll(".theme-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      const themeVal = btn.dataset.themeVal;
      setTheme(themeVal);
    });
  });

  // Listen for system appearance changes
  window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => {
    if (localStorage.getItem(THEME_STORAGE_KEY) === "system") {
      applyTheme("system");
    }
  });
}

export function setTheme(theme) {
  localStorage.setItem(THEME_STORAGE_KEY, theme);
  applyTheme(theme);
}

export function applyTheme(theme) {
  document.documentElement.setAttribute("data-theme", theme);
  document.querySelectorAll(".theme-btn").forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.themeVal === theme);
  });
}
