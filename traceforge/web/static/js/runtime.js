/**
 * TraceForge Runtime & System Doctor Controller
 * Platform diagnostics, execution profile switching, path introspection, and auto-repair.
 */

import { fetchJson, postJson } from "./api.js";

export async function renderRuntime(container) {
  container.innerHTML = `<div class="loading-state"><div class="spinner"></div><span>Loading Runtime Environment...</span></div>`;
  try {
    const [runtimeData, pathsData] = await Promise.all([
      fetchJson("/api/runtime/status"),
      fetchJson("/api/runtime/paths"),
    ]);

    const host = runtimeData.host || {};
    const caps = runtimeData.capabilities || {};
    const paths = pathsData.paths || {};

    container.innerHTML = `
      <div class="panel">
        <div class="panel-header">
          <h2 class="panel-title">Active Execution Profile & Fast-Paths</h2>
          <span class="badge badge-info">${runtimeData.active_profile || "PYTHON-GO"}</span>
        </div>
        <div class="panel-body">
          <div class="form-group">
            <label class="form-label">Runtime Engine Profile</label>
            <div class="input-action-row" style="max-width: 400px;">
              <select class="input-select" id="runtimeProfileSelect">
                <option value="python-go" ${runtimeData.active_profile === "PYTHON-GO" ? "selected" : ""}>python-go (Python + Go acceleration)</option>
                <option value="python" ${runtimeData.active_profile === "PYTHON" ? "selected" : ""}>python (Pure Python fallback)</option>
                <option value="go" ${runtimeData.active_profile === "GO" ? "selected" : ""}>go (High-throughput native Go)</option>
                <option value="minimal" ${runtimeData.active_profile === "MINIMAL" ? "selected" : ""}>minimal (Core tools only)</option>
                <option value="full" ${runtimeData.active_profile === "FULL" ? "selected" : ""}>full (Complete 152 suite)</option>
              </select>
              <button class="btn btn-sm btn-primary" id="btnSaveProfile">Apply</button>
            </div>
          </div>

          <div class="table-container mt-4">
            <span class="text-xs font-semibold uppercase text-subtle">Engine Fast-Path Routing:</span>
            <table class="data-table mt-1">
              <thead>
                <tr>
                  <th>Feature</th>
                  <th>Description</th>
                  <th>Preferred Engine</th>
                  <th>Active Runtime Decision</th>
                </tr>
              </thead>
              <tbody>
                ${Object.entries(caps)
                  .map(
                    ([feat, item]) => `
                  <tr>
                    <td class="font-semibold mono">${feat}</td>
                    <td>${item.description}</td>
                    <td class="mono uppercase">${item.preferred}</td>
                    <td><span class="badge badge-${item.selected_runtime === "go" || item.selected_runtime === "native" ? "success" : "neutral"}">${item.selected_runtime.toUpperCase()}</span></td>
                  </tr>
                `
                  )
                  .join("")}
              </tbody>
            </table>
          </div>

          <div class="mt-4">
            <span class="text-xs font-semibold uppercase text-subtle">System & Data Path Isolation:</span>
            <div class="meta-list mt-1">
              ${Object.entries(paths)
                .map(
                  ([k, v]) => `
                <div class="meta-row"><span class="meta-lbl">${k.replace(/_/g, " ").toUpperCase()}</span><span class="meta-val mono text-xs">${v}</span></div>
              `
                )
                .join("")}
            </div>
          </div>
        </div>
      </div>
    `;

    container.querySelector("#btnSaveProfile").addEventListener("click", async () => {
      const prof = container.querySelector("#runtimeProfileSelect").value;
      try {
        await postJson("/api/runtime/profile", { profile: prof });
        alert(`[✓] Profile switched to ${prof}`);
        renderRuntime(container);
      } catch (e) {
        alert(`Failed to change profile: ${e.message}`);
      }
    });
  } catch (e) {
    container.innerHTML = `<div class="error-banner">Failed to load runtime data: ${e.message}</div>`;
  }
}

export async function renderDoctor(container) {
  container.innerHTML = `<div class="loading-state"><div class="spinner"></div><span>Running System Doctor Diagnostics...</span></div>`;
  try {
    const [runtimeData, auditData] = await Promise.all([
      fetchJson("/api/runtime/status"),
      fetchJson("/api/catalog/platform-audit"),
    ]);

    const host = runtimeData.host || {};
    const audit = auditData.audit || {};

    container.innerHTML = `
      <div class="panel">
        <div class="panel-header">
          <div>
            <h2 class="panel-title">TraceForge Environment & Toolchain Diagnostics</h2>
            <span class="text-subtle text-xs">${host.display_name || "macOS"} | Architecture: ${host.arch || "arm64"}</span>
          </div>
          <button class="btn btn-sm btn-primary" id="btnDoctorRepair">Execute Automated Repair</button>
        </div>
        <div class="panel-body">
          <div class="dashboard-grid">
            <div class="panel">
              <div class="panel-header"><h3 class="panel-title text-sm">Host System State</h3></div>
              <div class="panel-body">
                <div class="meta-list">
                  <div class="meta-row"><span class="meta-lbl">Operating System</span><span class="meta-val">${host.os} (${host.display_name})</span></div>
                  <div class="meta-row"><span class="meta-lbl">Package Manager</span><span class="meta-val mono">${host.pkg_mgr}</span></div>
                  <div class="meta-row"><span class="meta-lbl">Python Runtime</span><span class="meta-val mono">v${host.python_version}</span></div>
                  <div class="meta-row"><span class="meta-lbl">Go Toolchain</span><span class="meta-val mono">${host.go_version || "Not installed"}</span></div>
                  <div class="meta-row"><span class="meta-lbl">Privileges</span><span class="meta-val">${host.has_sudo ? "sudo available" : "Standard userland"}</span></div>
                </div>
              </div>
            </div>

            <div class="panel">
              <div class="panel-header"><h3 class="panel-title text-sm">Catalog Coverage (152 Tools)</h3></div>
              <div class="panel-body">
                <div class="meta-list">
                  <div class="meta-row"><span class="meta-lbl">Installed & Ready</span><span class="meta-val mono text-success font-semibold">${audit.installed_count} tools</span></div>
                  <div class="meta-row"><span class="meta-lbl">Missing (Installable)</span><span class="meta-val mono text-warning">${audit.missing_count} tools</span></div>
                  <div class="meta-row"><span class="meta-lbl">Manual Installation</span><span class="meta-val mono text-subtle">${audit.manual_count} tools</span></div>
                  <div class="meta-row"><span class="meta-lbl">Platform Restricted</span><span class="meta-val mono text-subtle">${audit.unavailable_count} tools</span></div>
                </div>
              </div>
            </div>
          </div>

          <div class="mt-4" id="doctorRepairLogBox" style="display: none;">
            <span class="text-xs font-semibold uppercase text-subtle">Repair Action Log:</span>
            <pre class="terminal-output mt-1" id="doctorRepairLog"></pre>
          </div>
        </div>
      </div>
    `;

    container.querySelector("#btnDoctorRepair").addEventListener("click", async () => {
      const btn = container.querySelector("#btnDoctorRepair");
      const logBox = container.querySelector("#doctorRepairLogBox");
      const logPre = container.querySelector("#doctorRepairLog");
      btn.disabled = true;
      btn.textContent = "Repairing...";
      logBox.style.display = "block";
      logPre.textContent = "[+] Running automated directory, configuration, and catalog repair routines...\n";

      try {
        const res = await postJson("/api/runtime/repair");
        if (res.success) {
          logPre.textContent += (res.actions || []).map((a) => `[✓] ${a}`).join("\n");
          logPre.textContent += "\n[+] System repair completed successfully.\n";
        } else {
          logPre.textContent += `[!] Repair error: ${res.error}\n`;
        }
      } catch (e) {
        logPre.textContent += `[!] Request failed: ${e.message}\n`;
      } finally {
        btn.disabled = false;
        btn.textContent = "Execute Automated Repair";
      }
    });
  } catch (e) {
    container.innerHTML = `<div class="error-banner">Failed to run doctor: ${e.message}</div>`;
  }
}
