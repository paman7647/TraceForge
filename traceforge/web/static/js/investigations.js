/**
 * TraceForge Investigation Modules Workbench
 * Dispatches domain forensic workflows: Image, Network, Domain, Email, Identity, Documents, OPSEC.
 */

import { fetchJson, postJson } from "./api.js";
import { getActiveCaseId } from "./cases.js";

let cachedModules = [];
let selectedModuleId = "image";

export async function renderInvestigations(container) {
  // Parse query params if any
  const urlParams = new URLSearchParams(window.location.hash.split("?")[1] || "");
  if (urlParams.get("module")) {
    selectedModuleId = urlParams.get("module");
  }
  const prefillTarget = urlParams.get("target") || "";

  container.innerHTML = `<div class="loading-state"><div class="spinner"></div><span>Loading Investigation Modules...</span></div>`;
  try {
    const data = await fetchJson("/api/investigations");
    cachedModules = data.modules || [];

    const activeMod = cachedModules.find((m) => m.id === selectedModuleId) || cachedModules[0] || {};

    container.innerHTML = `
      <div class="workbench-layout">
        <!-- Left Column: Module Selector -->
        <div class="workbench-sidebar">
          <div class="panel-header">
            <span class="font-semibold text-xs uppercase tracking-wider text-subtle">Investigation Domains</span>
          </div>
          <div class="module-nav-list" id="moduleNavList">
            ${cachedModules
              .map(
                (m) => `
              <div class="module-nav-item ${m.id === selectedModuleId ? "active" : ""}" data-id="${m.id}">
                <div class="module-nav-title">${m.name}</div>
                <div class="module-nav-sub">${m.installed_tools?.length || 0} tools ready</div>
              </div>
            `
              )
              .join("")}
          </div>
        </div>

        <!-- Right Column: Interactive Module Workbench -->
        <div class="workbench-main" id="moduleStage">
          ${renderModuleStageContent(activeMod, prefillTarget)}
        </div>
      </div>
    `;

    // Attach module switching
    container.querySelectorAll(".module-nav-item").forEach((item) => {
      item.addEventListener("click", () => {
        selectedModuleId = item.dataset.id;
        container.querySelectorAll(".module-nav-item").forEach((i) => i.classList.toggle("active", i.dataset.id === selectedModuleId));
        const mod = cachedModules.find((m) => m.id === selectedModuleId);
        container.querySelector("#moduleStage").innerHTML = renderModuleStageContent(mod, "");
        attachStageListeners(container, mod);
      });
    });

    attachStageListeners(container, activeMod);
  } catch (e) {
    container.innerHTML = `<div class="error-banner">Failed to load investigation modules: ${e.message}</div>`;
  }
}

function renderModuleStageContent(mod, prefillTarget = "") {
  if (!mod) return `<div class="empty-state"><p>Select a module from the left menu.</p></div>`;

  return `
    <div class="panel">
      <div class="panel-header">
        <div>
          <h2 class="panel-title">${mod.name}</h2>
          <span class="text-subtle text-xs">${mod.description}</span>
        </div>
        <span class="badge badge-${mod.is_ready ? "success" : "warning"}">${mod.is_ready ? "READY" : "MISSING TOOLS"}</span>
      </div>
      <div class="panel-body">
        <!-- Target Specimen Input -->
        <div class="form-group">
          <label class="form-label">${mod.input_label} *</label>
          <div class="input-action-row">
            <input type="text" class="input-text" id="moduleTargetInput" value="${prefillTarget}" placeholder="${mod.input_type === "file" ? "e.g. /path/to/specimen.jpg or workspace/evidence/file.png" : "e.g. example.com or user_handle"}" required>
            <button class="btn btn-primary btn-sm" id="btnExecuteModule" ${!mod.is_ready ? "disabled" : ""}>Run Module</button>
          </div>
        </div>

        <!-- Key Capabilities -->
        <div class="capabilities-box mt-3">
          <span class="text-xs font-semibold text-subtle uppercase">Capabilities:</span>
          <div class="tag-row mt-1">
            ${(mod.key_capabilities || []).map((c) => `<span class="tag">${c}</span>`).join("")}
          </div>
        </div>

        <!-- Toolchain Availability -->
        <div class="toolchain-box mt-3">
          <span class="text-xs font-semibold text-subtle uppercase">Engine Toolchain:</span>
          <div class="tag-row mt-1">
            ${(mod.supported_tools || [])
              .map((t) => {
                const installed = (mod.installed_tools || []).includes(t);
                return `<span class="tag ${installed ? "tag-installed" : "tag-missing"}">${t} ${installed ? "✓" : "!"}</span>`;
              })
              .join("")}
          </div>
        </div>

        <!-- Live Output Terminal -->
        <div class="output-wrapper mt-4">
          <div class="output-header">
            <span class="text-xs font-semibold uppercase">Forensic Results & Report Stream</span>
            <span class="badge badge-neutral" id="moduleExecStatus">Idle</span>
          </div>
          <pre class="terminal-output" id="moduleOutput">// Awaiting module execution...</pre>
        </div>
      </div>
    </div>
  `;
}

function attachStageListeners(container, mod) {
  const btn = container.querySelector("#btnExecuteModule");
  const input = container.querySelector("#moduleTargetInput");
  const output = container.querySelector("#moduleOutput");
  const statusBadge = container.querySelector("#moduleExecStatus");

  if (!btn || !input || !output) return;

  btn.addEventListener("click", async () => {
    const target = input.value.trim();
    if (!target) {
      alert("Please specify a target specimen or input value.");
      return;
    }

    btn.disabled = true;
    btn.textContent = "Executing...";
    statusBadge.textContent = "Running";
    statusBadge.className = "badge badge-info";
    output.textContent = `[*] Initializing ${mod.name} on target '${target}'...\n[*] Case ID: ${getActiveCaseId() || "Standalone"}\n`;

    try {
      const res = await postJson(`/api/investigations/${encodeURIComponent(mod.id)}/run`, {
        target,
        case_id: getActiveCaseId(),
      });

      statusBadge.textContent = "Complete";
      statusBadge.className = "badge badge-success";

      const results = res.results || {};
      let outText = `[✓] ${mod.name} completed successfully.\n`;
      if (results.report_file) outText += `[+] Report written to: ${results.report_file}\n\n`;
      if (results.output) outText += results.output;
      else if (results.stdout) outText += results.stdout;
      else outText += JSON.stringify(results, null, 2);

      output.textContent = outText;
    } catch (e) {
      statusBadge.textContent = "Failed";
      statusBadge.className = "badge badge-danger";
      output.textContent = `[!] Error during execution: ${e.message}`;
    } finally {
      btn.disabled = false;
      btn.textContent = "Run Module";
    }
  });
}
