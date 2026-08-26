/**
 * TraceForge Web Application Master Bootstrapper
 * Coordinates navigation routing, theme settings, and workbench views.
 */

import { fetchJson } from "./api.js";
import { renderBatch } from "./batch.js";
import {
  loadActiveCase,
  renderAssets,
  renderCases,
  renderDashboard,
  renderEvidence,
  renderFindings,
  renderIOCs,
  renderTimeline,
} from "./cases.js";
import { renderCatalog } from "./catalog.js";
import { renderInvestigations } from "./investigations.js";
import {
  initNavigation,
  registerRouteHandler,
} from "./navigation.js";
import { renderReports } from "./reports.js";
import { renderDoctor, renderRuntime } from "./runtime.js";
import { initTheme } from "./theme.js";
import { renderTools } from "./tools.js";

async function bootApplication() {
  // 1. Initialize Theme
  initTheme();

  // 2. Register View Route Handlers
  registerRouteHandler("dashboard", renderDashboard);
  registerRouteHandler("cases", renderCases);
  registerRouteHandler("evidence", renderEvidence);
  registerRouteHandler("investigations", renderInvestigations);
  registerRouteHandler("batch", renderBatch);
  registerRouteHandler("tools", renderTools);
  registerRouteHandler("iocs", renderIOCs);
  registerRouteHandler("findings", renderFindings);
  registerRouteHandler("timeline", renderTimeline);
  registerRouteHandler("assets", renderAssets);
  registerRouteHandler("reports", renderReports);
  registerRouteHandler("catalog", renderCatalog);
  registerRouteHandler("runtime", renderRuntime);
  registerRouteHandler("doctor", renderDoctor);

  // 3. Load Active Case State
  await loadActiveCase();

  // 4. Update Host Meta in Sidebar
  try {
    const runtime = await fetchJson("/api/runtime/status");
    const platElem = document.getElementById("sidebarPlatform");
    const profElem = document.getElementById("sidebarProfile");
    if (platElem && runtime.host) platElem.textContent = runtime.host.display_name || runtime.host.os;
    if (profElem) profElem.textContent = runtime.active_profile || "PYTHON-GO";
  } catch (e) {
    // Non-fatal
  }

  // 5. Wire Global Refresh Button
  const btnRefresh = document.getElementById("btnRefresh");
  if (btnRefresh) {
    btnRefresh.addEventListener("click", () => {
      window.dispatchEvent(new HashChangeEvent("hashchange"));
    });
  }

  // 6. Start Navigation Router
  initNavigation();
}

// Start on DOM ready
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", bootApplication);
} else {
  bootApplication();
}
