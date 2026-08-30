/**
 * TraceForge Navigation Router
 * Manages hash-based routing, active view lifecycle, and sidebar UI state.
 */

const VIEW_TITLES = {
  dashboard: { title: "Dashboard", subtitle: "Live workspace overview and core toolchain diagnostics" },
  cases: { title: "Cases", subtitle: "Investigation management and chain-of-custody tracking" },
  evidence: { title: "Evidence", subtitle: "Forensic artifact repository and SHA256 integrity records" },
  investigations: { title: "Investigation Modules", subtitle: "Specialized DFIR and OSINT investigation workbenches" },
  batch: { title: "Batch Suite", subtitle: "Multi-tool coordinated execution and cross-source correlation" },
  tools: { title: "Tool Runner", subtitle: "Direct execution console for individual catalog tools" },
  iocs: { title: "Indicators of Compromise", subtitle: "Defanged threat observables and indicators" },
  findings: { title: "Findings & Notes", subtitle: "Investigative observations, severity classifications, and analyst notes" },
  timeline: { title: "Investigation Timeline", subtitle: "Chronological sequence of forensic events and findings" },
  assets: { title: "Discovered Assets", subtitle: "Cataloged hostnames, IP endpoints, accounts, and email targets" },
  reports: { title: "Dossier & Reports", subtitle: "Multi-format case export (Markdown, HTML, JSON, STIX 2.1)" },
  catalog: { title: "Tool Catalog", subtitle: "175 verified DFIR/OSINT utilities with platform availability" },
  credentials: { title: "Credentials Vault", subtitle: "API key and access token management for 20+ OSINT providers" },
  runtime: { title: "Runtime & Acceleration", subtitle: "Active execution profile, Go fast-paths, and capabilities" },
  doctor: { title: "System Doctor", subtitle: "Platform diagnostics, dependency verification, and auto-repair" },
};


let currentRoute = "dashboard";
const routeListeners = new Map();

export function registerRouteHandler(route, handler) {
  routeListeners.set(route, handler);
}

export function initNavigation() {
  window.addEventListener("hashchange", handleHashChange);
  
  // Mobile sidebar toggle
  const toggleBtn = document.getElementById("btnToggleSidebar");
  const sidebar = document.getElementById("sidebar");
  if (toggleBtn && sidebar) {
    toggleBtn.addEventListener("click", () => {
      sidebar.classList.toggle("open");
    });
  }

  // Handle initial route
  handleHashChange();
}

export function navigateTo(route) {
  window.location.hash = route;
}

export function getCurrentRoute() {
  return currentRoute;
}

function handleHashChange() {
  const hash = window.location.hash.replace(/^#\/?/, "") || "dashboard";
  currentRoute = hash;

  // Update sidebar links
  document.querySelectorAll(".nav-link").forEach((link) => {
    link.classList.toggle("active", link.dataset.route === hash);
  });

  // Update header text
  const meta = VIEW_TITLES[hash] || { title: hash.toUpperCase(), subtitle: "TraceForge Workbench" };
  const heading = document.getElementById("pageHeading");
  const subtitle = document.getElementById("pageSubtitle");
  if (heading) heading.textContent = meta.title;
  if (subtitle) subtitle.textContent = meta.subtitle;

  // Close mobile sidebar if open
  const sidebar = document.getElementById("sidebar");
  if (sidebar) sidebar.classList.remove("open");

  // Invoke registered view renderer
  const handler = routeListeners.get(hash);
  const viewport = document.getElementById("appViewport");
  if (handler && viewport) {
    handler(viewport);
  } else if (viewport) {
    viewport.innerHTML = `<div class="empty-state"><h3>View not found</h3><p>Route #${hash} is not registered.</p></div>`;
  }
}

export function updateHeaderActiveCase(caseId) {
  const caseElem = document.getElementById("headerActiveCase");
  if (caseElem) {
    caseElem.textContent = caseId || "None";
    caseElem.classList.toggle("active-case", !!caseId);
  }
}
