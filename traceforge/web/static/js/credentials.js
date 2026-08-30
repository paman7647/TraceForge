/**
 * TraceForge API Keys & OSINT Credentials Vault Web Controller
 * Manages third-party OSINT API keys, token masking, and live connectivity validation.
 */

import { fetchJson, postJson } from "./api.js";

let cachedCredentials = { providers: [], configured_count: 0, total_providers: 0, vault_path: "" };
let activeFilter = "all";
let searchQuery = "";

export async function renderCredentials(container) {
  container.innerHTML = `
    <div class="loading-state">
      <div class="spinner"></div>
      <span>Loading API Keys & Credentials Vault...</span>
    </div>
  `;

  try {
    const data = await fetchJson("/api/credentials");
    cachedCredentials = data || { providers: [], configured_count: 0, total_providers: 0, vault_path: "" };
    renderVaultView(container);
  } catch (e) {
    container.innerHTML = `<div class="error-banner">Failed to load credentials vault: ${e.message}</div>`;
  }
}

function renderVaultView(container) {
  const { providers, configured_count, total_providers, vault_path } = cachedCredentials;

  // Extract categories
  const categories = ["all", ...new Set(providers.map((p) => p.category).filter(Boolean))];

  // Filter providers
  const filtered = providers.filter((p) => {
    const matchCat = activeFilter === "all" || p.category === activeFilter;
    const matchSearch =
      !searchQuery ||
      p.name.toLowerCase().includes(searchQuery) ||
      p.key.toLowerCase().includes(searchQuery) ||
      p.description.toLowerCase().includes(searchQuery);
    return matchCat && matchSearch;
  });

  container.innerHTML = `
    <div class="credentials-view">
      <!-- Top Overview Card -->
      <div class="panel mb-4">
        <div class="panel-body">
          <div class="flex-between flex-wrap gap-4">
            <div>
              <h2 class="panel-title text-lg">API Keys & OSINT Credentials Vault</h2>
              <p class="text-subtle text-xs mt-1">
                Manage API keys and authentication tokens for third-party intelligence providers. Keys are stored locally at
                <code class="code-pill mono">${escapeHtml(vault_path)}</code> with strict <code class="code-pill">chmod 600</code> permissions.
              </p>
            </div>
            <div class="flex items-center gap-3">
              <div class="stat-pill">
                <span class="stat-num">${configured_count} / ${total_providers}</span>
                <span class="stat-lbl">Active Providers</span>
              </div>
              <button class="btn btn-secondary btn-sm" id="btnExportTemplate">
                <svg viewBox="0 0 24 24" width="13" height="13" stroke="currentColor" stroke-width="2" fill="none"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                <span>Export .env Template</span>
              </button>
            </div>
          </div>
        </div>
      </div>

      <!-- Filter & Search Bar -->
      <div class="filter-toolbar mb-4">
        <div class="search-box">
          <svg viewBox="0 0 24 24" width="14" height="14" stroke="currentColor" stroke-width="2" fill="none"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
          <input type="text" id="credSearchInput" class="search-input" placeholder="Search provider or variable name..." value="${escapeHtml(searchQuery)}">
        </div>
        <div class="category-chips" id="credCategoryChips">
          ${categories
            .map(
              (cat) => `
            <button class="chip ${cat === activeFilter ? "active" : ""}" data-cat="${escapeHtml(cat)}">
              ${escapeHtml(cat === "all" ? "All Categories" : cat)}
            </button>
          `
            )
            .join("")}
        </div>
      </div>

      <!-- Providers Grid / Table -->
      <div class="panel">
        <div class="table-responsive">
          <table class="data-table">
            <thead>
              <tr>
                <th style="width: 280px;">Provider / Service</th>
                <th style="width: 220px;">Environment Variable</th>
                <th>Status & Secret Value</th>
                <th style="width: 220px; text-align: right;">Actions</th>
              </tr>
            </thead>
            <tbody>
              ${
                filtered.length === 0
                  ? `<tr><td colspan="4" class="text-center py-6 text-subtle">No matching providers found.</td></tr>`
                  : filtered
                      .map((p) => {
                        return `
                  <tr data-key="${p.key}">
                    <td>
                      <div class="font-semibold text-sm">${escapeHtml(p.name)}</div>
                      <div class="text-xs text-subtle mt-0.5">${escapeHtml(p.description)}</div>
                      ${
                        p.docs_url
                          ? `<a href="${p.docs_url}" target="_blank" rel="noopener" class="text-xs text-primary underline mt-1 inline-block">Provider Docs ↗</a>`
                          : ""
                      }
                    </td>
                    <td>
                      <code class="code-pill mono">${p.key}</code>
                      <div class="text-xs text-subtle mt-1">${escapeHtml(p.category)}</div>
                    </td>
                    <td>
                      <div class="flex items-center gap-2">
                        <span class="badge badge-${p.is_configured ? "success" : "neutral"}">
                          ${p.is_configured ? "CONFIGURED" : "NOT SET"}
                        </span>
                        <code class="mono text-xs ${p.is_configured ? "text-success" : "text-subtle"}">
                          ${escapeHtml(p.masked_value)}
                        </code>
                      </div>
                    </td>
                    <td class="text-right">
                      <div class="flex justify-end gap-1.5">
                        <button class="btn btn-xs btn-primary btn-configure-key" data-key="${p.key}" data-name="${escapeHtml(p.name)}">
                          ${p.is_configured ? "Update" : "Set Key"}
                        </button>
                        ${
                          p.is_configured
                            ? `
                          <button class="btn btn-xs btn-secondary btn-test-key" data-key="${p.key}" title="Test API key validation">
                            Test
                          </button>
                          <button class="btn btn-xs btn-danger btn-remove-key" data-key="${p.key}" title="Remove key from vault">
                            ✕
                          </button>
                        `
                            : ""
                        }
                      </div>
                    </td>
                  </tr>
                `;
                      })
                      .join("")
              }
            </tbody>
          </table>
        </div>
      </div>
    </div>
  `;

  attachVaultEventListeners(container);
}

function attachVaultEventListeners(container) {
  // Search
  const searchInput = container.querySelector("#credSearchInput");
  if (searchInput) {
    searchInput.addEventListener("input", (e) => {
      searchQuery = e.target.value.toLowerCase().trim();
      renderVaultView(container);
    });
  }

  // Categories
  container.querySelectorAll("#credCategoryChips .chip").forEach((chip) => {
    chip.addEventListener("click", () => {
      activeFilter = chip.dataset.cat;
      renderVaultView(container);
    });
  });

  // Export template
  const btnExport = container.querySelector("#btnExportTemplate");
  if (btnExport) {
    btnExport.addEventListener("click", () => {
      window.open("/api/credentials/template", "_blank");
    });
  }

  // Configure key prompt
  container.querySelectorAll(".btn-configure-key").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const key = btn.dataset.key;
      const name = btn.dataset.name;
      const val = prompt(`Enter secret token or API key for ${name} (${key}):`);
      if (val === null) return;
      if (!val.trim()) {
        alert("Key value cannot be empty.");
        return;
      }

      try {
        await postJson("/api/credentials/set", { key, value: val.trim() });
        const updated = await fetchJson("/api/credentials");
        cachedCredentials = updated;
        renderVaultView(container);
      } catch (e) {
        alert(`Failed to save credential: ${e.message}`);
      }
    });
  });

  // Remove key
  container.querySelectorAll(".btn-remove-key").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const key = btn.dataset.key;
      if (!confirm(`Are you sure you want to remove ${key} from your credentials vault?`)) return;

      try {
        await postJson("/api/credentials/remove", { key });
        const updated = await fetchJson("/api/credentials");
        cachedCredentials = updated;
        renderVaultView(container);
      } catch (e) {
        alert(`Failed to remove credential: ${e.message}`);
      }
    });
  });

  // Test key
  container.querySelectorAll(".btn-test-key").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const key = btn.dataset.key;
      btn.disabled = true;
      btn.textContent = "...";

      try {
        const res = await postJson("/api/credentials/test", { key });
        alert(`[${res.status?.toUpperCase() || "STATUS"}] ${key}:\n${res.message || "Test completed."}`);
      } catch (e) {
        alert(`Test failed: ${e.message}`);
      } finally {
        btn.disabled = false;
        btn.textContent = "Test";
      }
    });
  });
}

function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
