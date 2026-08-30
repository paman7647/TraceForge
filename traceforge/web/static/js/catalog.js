/**
 * TraceForge Tool Catalog Browser
 * Explores 175 OSINT/DFIR tools across 13 domains with platform capability checks and installation modal.
 */

import { fetchJson, postJson } from "./api.js";

let allTools = [];
let activeCategory = "all";

export async function renderCatalog(container) {
  container.innerHTML = `<div class="loading-state"><div class="spinner"></div><span>Loading Tool Catalog...</span></div>`;
  try {
    const [toolsData, auditData] = await Promise.all([
      fetchJson("/api/tools"),
      fetchJson("/api/catalog/platform-audit"),
    ]);

    allTools = toolsData.tools || [];
    const audit = auditData.audit || {};

    const categories = Array.from(new Set(allTools.map((t) => t.category))).filter(Boolean);

    container.innerHTML = `
      <div class="panel">
        <div class="panel-header">
          <div>
            <h2 class="panel-title">TraceForge Tool Catalog (${allTools.length} Tools)</h2>
            <span class="text-subtle text-xs">Host: ${audit.display_name || "macOS"} | Installed: ${audit.installed_count} / ${audit.total_tools}</span>
          </div>

          <div class="catalog-summary-pills">
            <span class="badge badge-success">${audit.installed_count} Installed</span>
            <span class="badge badge-warning">${audit.missing_count} Missing</span>
            <span class="badge badge-neutral">${audit.manual_count} Manual</span>
          </div>
        </div>
        <div class="panel-body">
          <!-- Toolbar Filter -->
          <div class="toolbar">
            <div class="toolbar-left">
              <input type="text" class="input-text" id="catalogSearch" placeholder="Search by tool name, binary, or keyword..." style="max-width: 320px;">
              <select class="input-select ml-2" id="catalogCategorySelect" style="max-width: 250px;">
                <option value="all">All Categories (${allTools.length})</option>
                ${categories.map((c) => `<option value="${c}">${c}</option>`).join("")}
              </select>
            </div>
            <div class="toolbar-right">
              <label class="checkbox-label">
                <input type="checkbox" id="chkInstalledOnly">
                <span>Installed only</span>
              </label>
            </div>
          </div>

          <!-- Catalog Table -->
          <div class="table-container mt-3">
            <table class="data-table">
              <thead>
                <tr>
                  <th style="width: 40px;">#</th>
                  <th>Tool Name</th>
                  <th>Binary</th>
                  <th>Category / Subcategory</th>
                  <th>Status on Host</th>
                  <th>Ecosystem</th>
                  <th style="text-align: right;">Action</th>
                </tr>
              </thead>
              <tbody id="catalogTableBody">
                ${renderCatalogRows(allTools)}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    `;

    const searchInput = container.querySelector("#catalogSearch");
    const categorySelect = container.querySelector("#catalogCategorySelect");
    const installedChk = container.querySelector("#chkInstalledOnly");
    const tbody = container.querySelector("#catalogTableBody");

    function applyFilters() {
      const q = searchInput.value.toLowerCase();
      const cat = categorySelect.value;
      const installedOnly = installedChk.checked;

      const filtered = allTools.filter((t) => {
        if (cat !== "all" && t.category !== cat) return false;
        if (installedOnly && !t.is_installed) return false;
        if (q && !t.name.toLowerCase().includes(q) && !t.binary.toLowerCase().includes(q) && !t.description.toLowerCase().includes(q)) {
          return false;
        }
        return true;
      });

      tbody.innerHTML = renderCatalogRows(filtered);
      attachCatalogListeners(container);
    }

    searchInput.addEventListener("input", applyFilters);
    categorySelect.addEventListener("change", applyFilters);
    installedChk.addEventListener("change", applyFilters);

    attachCatalogListeners(container);
  } catch (e) {
    container.innerHTML = `<div class="error-banner">Failed to load catalog: ${e.message}</div>`;
  }
}

function renderCatalogRows(tools) {
  if (!tools.length) {
    return `<tr><td colspan="7" class="text-center text-subtle" style="padding: 30px;">No catalog tools matched the filter criteria.</td></tr>`;
  }
  return tools
    .map((t) => {
      let statusBadge = "";
      if (t.is_installed) {
        statusBadge = `<span class="badge badge-success">INSTALLED</span>`;
      } else if (!t.is_available_on_platform) {
        statusBadge = `<span class="badge badge-danger">UNAVAILABLE</span>`;
      } else if (t.is_manual) {
        statusBadge = `<span class="badge badge-neutral">MANUAL</span>`;
      } else {
        statusBadge = `<span class="badge badge-warning">INSTALLABLE</span>`;
      }

      return `
      <tr>
        <td class="text-subtle mono text-xs">${t.id}</td>
        <td class="font-semibold">${t.name}</td>
        <td class="mono font-semibold">${t.binary}</td>
        <td><div class="text-xs font-semibold">${t.category}</div><div class="text-subtle text-xs">${t.subcategory}</div></td>
        <td>${statusBadge}</td>
        <td><span class="badge badge-neutral lowercase">${t.ecosystem || "native"}</span></td>
        <td style="text-align: right;">
          ${
            !t.is_installed && t.is_available_on_platform && !t.is_manual
              ? `<button class="btn btn-xs btn-primary btn-install-tool" data-id="${t.id}" data-name="${t.name}">Install</button>`
              : ""
          }
          ${
            t.is_installed
              ? `<button class="btn btn-xs btn-subtle btn-run-from-cat" data-binary="${t.binary}">Run</button>`
              : ""
          }
        </td>
      </tr>
    `;
    })
    .join("");
}

function attachCatalogListeners(container) {
  container.querySelectorAll(".btn-run-from-cat").forEach((btn) => {
    btn.addEventListener("click", () => {
      window.location.hash = `tools?tool=${btn.dataset.binary}`;
    });
  });

  container.querySelectorAll(".btn-install-tool").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const toolId = btn.dataset.id;
      const toolName = btn.dataset.name;
      btn.disabled = true;
      btn.textContent = "Installing...";

      try {
        const res = await postJson(`/api/tools/${encodeURIComponent(toolId)}/install`);
        if (res.success) {
          alert(`[✓] Successfully installed ${toolName}!`);
          renderCatalog(container);
        } else {
          alert(`[!] Installation failed: ${res.error || res.stderr}`);
          btn.disabled = false;
          btn.textContent = "Install";
        }
      } catch (e) {
        alert(`[!] Installation request failed: ${e.message}`);
        btn.disabled = false;
        btn.textContent = "Install";
      }
    });
  });
}
