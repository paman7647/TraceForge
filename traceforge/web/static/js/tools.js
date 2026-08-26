/**
 * TraceForge Tool Runner Controller
 * Direct execution console for single catalog tools with arguments.
 */

import { fetchJson, postJson } from "./api.js";

let installedTools = [];

export async function renderTools(container) {
  container.innerHTML = `<div class="loading-state"><div class="spinner"></div><span>Loading Installed Toolchain...</span></div>`;
  try {
    const data = await fetchJson("/api/tools?installed=1");
    installedTools = data.tools || [];

    container.innerHTML = `
      <div class="panel">
        <div class="panel-header">
          <h2 class="panel-title">Direct Tool Execution Console</h2>
          <span class="badge badge-info">${installedTools.length} Tools Installed</span>
        </div>
        <div class="panel-body">
          <div class="form-grid-2">
            <div class="form-group">
              <label class="form-label">Select Tool *</label>
              <select class="input-select" id="toolSelect">
                ${installedTools.map((t) => `<option value="${t.binary}">${t.name} (${t.binary}) — ${t.category}</option>`).join("")}
              </select>
            </div>
            <div class="form-group">
              <label class="form-label">Target / Specimen Input *</label>
              <input type="text" class="input-text" id="toolTarget" placeholder="e.g. example.com or /path/to/specimen.pcap">
            </div>
          </div>

          <div class="form-group mt-3">
            <label class="form-label">Optional Command Flags / Arguments (Space separated)</label>
            <input type="text" class="input-text mono" id="toolArgs" placeholder="e.g. -c 100 or -v">
          </div>

          <div class="action-bar mt-3">
            <button class="btn btn-primary btn-sm" id="btnRunSingleTool">Execute Tool</button>
          </div>

          <div class="output-wrapper mt-4">
            <div class="output-header">
              <span class="text-xs font-semibold uppercase">Command Execution Console</span>
              <span class="badge badge-neutral" id="toolRunBadge">Idle</span>
            </div>
            <pre class="terminal-output" id="toolRunOutput">// Select a tool and execute to inspect stdout/stderr stream...</pre>
          </div>
        </div>
      </div>
    `;

    const btn = container.querySelector("#btnRunSingleTool");
    const select = container.querySelector("#toolSelect");
    const targetInput = container.querySelector("#toolTarget");
    const argsInput = container.querySelector("#toolArgs");
    const output = container.querySelector("#toolRunOutput");
    const badge = container.querySelector("#toolRunBadge");

    btn.addEventListener("click", async () => {
      const toolBin = select.value;
      const target = targetInput.value.trim();
      const rawArgs = argsInput.value.trim();
      const extraArgs = rawArgs ? rawArgs.split(/\s+/) : [];

      if (!target && !extraArgs.length) {
        alert("Please specify a target or arguments for the tool.");
        return;
      }

      btn.disabled = true;
      btn.textContent = "Executing...";
      badge.textContent = "Running";
      badge.className = "badge badge-info";
      output.textContent = `[*] Spawning binary '${toolBin}' via ToolRunner...\n`;

      try {
        const res = await postJson(`/api/tools/${encodeURIComponent(toolBin)}/run`, {
          target,
          args: extraArgs,
        });

        badge.textContent = `Exit ${res.exit_code}`;
        badge.className = res.exit_code === 0 ? "badge badge-success" : "badge badge-danger";

        let text = `[+] Command: ${Array.isArray(res.command) ? res.command.join(" ") : toolBin}\n`;
        text += `[+] Execution Duration: ${(res.duration_seconds || 0).toFixed(2)}s | Exit Code: ${res.exit_code}\n\n`;
        if (res.stdout) text += `--- STDOUT ---\n${res.stdout}\n`;
        if (res.stderr) text += `--- STDERR ---\n${res.stderr}\n`;
        output.textContent = text;
      } catch (e) {
        badge.textContent = "Failed";
        badge.className = "badge badge-danger";
        output.textContent = `[!] Execution error: ${e.message}`;
      } finally {
        btn.disabled = false;
        btn.textContent = "Execute Tool";
      }
    });
  } catch (e) {
    container.innerHTML = `<div class="error-banner">Failed to load tools: ${e.message}</div>`;
  }
}
