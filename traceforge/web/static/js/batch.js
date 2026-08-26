/**
 * TraceForge Batch Investigation Controller
 * Predefined & custom toolset workflows, pre-flight plan, active probe confirmation, and parallel execution.
 */

import { fetchJson, postJson } from "./api.js";
import { getActiveCaseId } from "./cases.js";

let catalogTools = [];
let activePollingInterval = null;

export async function renderBatch(container) {
  container.innerHTML = `<div class="loading-state"><div class="spinner"></div><span>Loading Batch Investigation Suite...</span></div>`;
  try {
    const data = await fetchJson("/api/tools");
    catalogTools = data.tools || [];

    container.innerHTML = `
      <div class="workbench-layout">
        <!-- Configuration Column -->
        <div class="workbench-sidebar" style="width: 380px;">
          <div class="panel-header">
            <span class="font-semibold text-xs uppercase tracking-wider text-subtle">Batch Suite Setup</span>
          </div>
          <div class="panel-body" style="padding: 16px;">
            <!-- Target Input -->
            <div class="form-group">
              <label class="form-label">Target Specimen / Entity *</label>
              <input type="text" class="input-text" id="batchTargetInput" placeholder="e.g. example.com, /path/to/evidence.jpg, IP" required>
            </div>

            <!-- Workflow / Custom Selection -->
            <div class="form-group mt-3">
              <label class="form-label">Workflow Mode</label>
              <select class="input-select" id="batchWorkflowSelect">
                <option value="domain">Domain & DNS Intelligence</option>
                <option value="image">Media & Image Forensics</option>
                <option value="network">Network & PCAP Analysis</option>
                <option value="email">Email & Breach Reconnaissance</option>
                <option value="identity">Identity & Username Recon</option>
                <option value="documents">Document Metadata Harvesting</option>
                <option value="opsec">OPSEC & Anonymization Audit</option>
                <option value="full">Full Comprehensive Sweep</option>
                <option value="custom" selected>Custom Tool Set (Select tools)</option>
              </select>
            </div>

            <!-- Custom Tool Selector Box -->
            <div class="custom-tools-box mt-3" id="customToolsBox">
              <div class="flex-between">
                <label class="form-label mb-0">Select Tools:</label>
                <span class="text-xs text-subtle" id="selectedToolsCount">0 selected</span>
              </div>
              <input type="text" class="input-text mt-1" id="toolFilterInput" placeholder="Filter tools..." style="font-size: 11px; padding: 4px 8px;">
              <div class="tool-checkbox-list mt-1" id="toolCheckboxList">
                ${catalogTools
                  .map(
                    (t) => `
                  <label class="tool-checkbox-item">
                    <input type="checkbox" class="chk-batch-tool" value="${t.binary}" data-active="${t.is_active_scan ? "1" : "0"}">
                    <span class="font-semibold">${t.name}</span>
                    <span class="text-subtle mono text-xs">(${t.binary})</span>
                    ${t.is_active_scan ? `<span class="badge badge-danger text-xs ml-1">ACTIVE</span>` : ""}
                    ${!t.is_installed ? `<span class="badge badge-neutral text-xs ml-1">MISSING</span>` : ""}
                  </label>
                `
                  )
                  .join("")}
              </div>
            </div>

            <!-- Mode & Workers -->
            <div class="form-grid-2 mt-3">
              <div class="form-group">
                <label class="form-label">Execution</label>
                <select class="input-select" id="batchModeSelect">
                  <option value="sequential" selected>Sequential</option>
                  <option value="parallel">Parallel</option>
                </select>
              </div>
              <div class="form-group">
                <label class="form-label">Workers</label>
                <input type="number" class="input-text" id="batchWorkersInput" value="3" min="1" max="10">
              </div>
            </div>

            <div class="action-bar mt-4">
              <button class="btn btn-primary btn-sm" style="width: 100%;" id="btnPreviewPlan">Generate Pre-Flight Plan</button>
            </div>
          </div>
        </div>

        <!-- Right Column: Execution Stage & Results -->
        <div class="workbench-main" id="batchStage">
          <div class="panel">
            <div class="panel-header">
              <h2 class="panel-title">Batch Execution Console</h2>
              <span class="badge badge-neutral" id="batchJobBadge">Idle</span>
            </div>
            <div class="panel-body">
              <div id="batchStageNotice" class="text-subtle">
                Specify a target specimen and configure tool selection on the left to build and execute a batch investigation plan.
              </div>

              <!-- Live Execution Logs -->
              <div class="output-wrapper mt-3" id="batchLogWrapper" style="display: none;">
                <div class="output-header">
                  <span class="text-xs font-semibold uppercase">Real-Time Execution Logs</span>
                  <button class="btn btn-xs btn-subtle text-danger" id="btnCancelBatch">Cancel Execution</button>
                </div>
                <pre class="terminal-output" id="batchLogStream" style="max-height: 250px;"></pre>
              </div>

              <!-- Results Box -->
              <div id="batchResultsContainer" class="mt-4" style="display: none;"></div>
            </div>
          </div>
        </div>
      </div>
    `;

    setupBatchListeners(container);
  } catch (e) {
    container.innerHTML = `<div class="error-banner">Failed to load batch suite: ${e.message}</div>`;
  }
}

function setupBatchListeners(container) {
  const workflowSelect = container.querySelector("#batchWorkflowSelect");
  const customBox = container.querySelector("#customToolsBox");
  const toolFilter = container.querySelector("#toolFilterInput");
  const countLabel = container.querySelector("#selectedToolsCount");
  const btnPreview = container.querySelector("#btnPreviewPlan");

  workflowSelect.addEventListener("change", () => {
    customBox.style.display = workflowSelect.value === "custom" ? "block" : "none";
  });

  toolFilter.addEventListener("input", (e) => {
    const q = e.target.value.toLowerCase();
    container.querySelectorAll(".tool-checkbox-item").forEach((item) => {
      item.style.display = item.textContent.toLowerCase().includes(q) ? "flex" : "none";
    });
  });

  container.querySelectorAll(".chk-batch-tool").forEach((chk) => {
    chk.addEventListener("change", () => {
      const selected = container.querySelectorAll(".chk-batch-tool:checked").length;
      countLabel.textContent = `${selected} selected`;
    });
  });

  btnPreview.addEventListener("click", async () => {
    const target = container.querySelector("#batchTargetInput").value.trim();
    const workflow = workflowSelect.value;
    const mode = container.querySelector("#batchModeSelect").value;
    const workers = parseInt(container.querySelector("#batchWorkersInput").value, 10) || 3;

    if (!target) {
      alert("Please specify a target input specimen or entity.");
      return;
    }

    let selectedTools = [];
    if (workflow === "custom") {
      container.querySelectorAll(".chk-batch-tool:checked").forEach((c) => selectedTools.push(c.value));
      if (!selectedTools.length) {
        alert("Please select at least one tool from the list.");
        return;
      }
    }

    btnPreview.disabled = true;
    btnPreview.textContent = "Generating Plan...";

    try {
      const res = await postJson("/api/batch/plan", {
        input: target,
        workflow: workflow !== "custom" ? workflow : null,
        tools: selectedTools,
        mode,
        workers,
      });

      showPreFlightPlanModal(res.plan, target, selectedTools, workflow, mode, workers, container);
    } catch (e) {
      alert(`Plan generation failed: ${e.message}`);
    } finally {
      btnPreview.disabled = false;
      btnPreview.textContent = "Generate Pre-Flight Plan";
    }
  });
}

function showPreFlightPlanModal(plan, target, tools, workflow, mode, workers, parentContainer) {
  const modal = document.createElement("div");
  modal.className = "modal-overlay";

  const hasActiveProbe = (plan.tools_to_run || []).some((t) => t.is_active_scan);

  modal.innerHTML = `
    <div class="modal-card" style="max-width: 650px;">
      <div class="modal-header">
        <h3 class="modal-title">Pre-Flight Batch Investigation Plan</h3>
        <button class="btn-close" id="btnClosePlanModal">×</button>
      </div>
      <div class="modal-body">
        <div class="meta-list">
          <div class="meta-row"><span class="meta-lbl">Target Specimen</span><span class="meta-val mono font-semibold">${plan.input_target}</span></div>
          <div class="meta-row"><span class="meta-lbl">Detected Input Type</span><span class="meta-val badge badge-info">${plan.input_type}</span></div>
          <div class="meta-row"><span class="meta-lbl">Execution Mode</span><span class="meta-val uppercase font-semibold">${plan.execution_mode} (${plan.max_workers} workers)</span></div>
          <div class="meta-row"><span class="meta-lbl">Executable Tools</span><span class="meta-val mono text-success font-semibold">${plan.executable_tools_count} ready</span></div>
          <div class="meta-row"><span class="meta-lbl">Skipped Incompatible</span><span class="meta-val mono text-subtle">${plan.incompatible_tools_count} skipped</span></div>
        </div>

        ${
          hasActiveProbe
            ? `
          <div class="alert alert-warning mt-3">
            <strong>Active Probing Warning:</strong> Your selected toolset includes active port/vulnerability scanners. Ensure you have explicit authorization to scan the target entity.
            <div class="mt-2">
              <label class="checkbox-label font-semibold">
                <input type="checkbox" id="chkAuthorizeActive">
                <span>I confirm I am authorized to conduct active security assessments against this target.</span>
              </label>
            </div>
          </div>
        `
            : ""
        }

        <div class="plan-tool-list mt-3">
          <span class="text-xs font-semibold text-subtle uppercase">Planned Toolchain Execution:</span>
          <div class="mt-1" style="max-height: 150px; overflow-y: auto;">
            ${(plan.tools_to_run || [])
              .map(
                (t, idx) => `
              <div class="plan-tool-row">
                <span class="mono text-xs font-semibold">${idx + 1}. ${t.tool_name} (${t.binary})</span>
                <span class="badge badge-success text-xs">Ready</span>
              </div>
            `
              )
              .join("")}
          </div>
        </div>
      </div>
      <div class="modal-footer">
        <button class="btn btn-sm btn-subtle" id="btnCancelPlan">Cancel</button>
        <button class="btn btn-sm btn-primary" id="btnExecuteBatchPlan">Confirm & Run Batch</button>
      </div>
    </div>
  `;

  document.body.appendChild(modal);
  modal.querySelector("#btnClosePlanModal").onclick = () => modal.remove();
  modal.querySelector("#btnCancelPlan").onclick = () => modal.remove();

  modal.querySelector("#btnExecuteBatchPlan").onclick = async () => {
    if (hasActiveProbe && !modal.querySelector("#chkAuthorizeActive")?.checked) {
      alert("Please confirm authorization before running active security tools.");
      return;
    }

    modal.remove();
    startBatchExecution(target, tools, workflow, mode, workers, parentContainer);
  };
}

async function startBatchExecution(target, tools, workflow, mode, workers, parentContainer) {
  const badge = parentContainer.querySelector("#batchJobBadge");
  const logWrapper = parentContainer.querySelector("#batchLogWrapper");
  const logStream = parentContainer.querySelector("#batchLogStream");
  const resultsBox = parentContainer.querySelector("#batchResultsContainer");
  const notice = parentContainer.querySelector("#batchStageNotice");
  const cancelBtn = parentContainer.querySelector("#btnCancelBatch");

  notice.style.display = "none";
  logWrapper.style.display = "block";
  resultsBox.style.display = "none";
  badge.textContent = "Running";
  badge.className = "badge badge-info";
  logStream.textContent = `[*] Launching batch investigation against '${target}'...\n`;

  try {
    const res = await postJson("/api/batch/run", {
      input: target,
      workflow: workflow !== "custom" ? workflow : null,
      tools,
      mode,
      workers,
      case_id: getActiveCaseId(),
    });

    const jobId = res.job_id;
    cancelBtn.onclick = async () => {
      await postJson(`/api/batch/jobs/${encodeURIComponent(jobId)}/cancel`);
      badge.textContent = "Cancelled";
      badge.className = "badge badge-danger";
    };

    if (activePollingInterval) clearInterval(activePollingInterval);

    activePollingInterval = setInterval(async () => {
      try {
        const jobData = await fetchJson(`/api/batch/jobs/${encodeURIComponent(jobId)}`);
        const job = jobData.job;

        if (job.logs && job.logs.length) {
          logStream.textContent = job.logs.join("\n");
          logStream.scrollTop = logStream.scrollHeight;
        }

        if (job.status === "COMPLETED" || job.status === "FAILED" || job.status === "CANCELLED") {
          clearInterval(activePollingInterval);
          badge.textContent = job.status;
          badge.className = job.status === "COMPLETED" ? "badge badge-success" : "badge badge-danger";

          if (job.results) {
            renderBatchResults(job.results, resultsBox);
          }
        }
      } catch (e) {
        clearInterval(activePollingInterval);
      }
    }, 800);
  } catch (e) {
    badge.textContent = "Failed";
    badge.className = "badge badge-danger";
    logStream.textContent += `\n[!] Failed to start batch job: ${e.message}\n`;
  }
}

function renderBatchResults(results, container) {
  container.style.display = "block";
  const iocs = results.deduplicated_indicators || [];
  const findings = results.aggregated_findings || [];

  container.innerHTML = `
    <div class="panel mt-4">
      <div class="panel-header">
        <h2 class="panel-title">Batch Results Summary (${results.job_id})</h2>
        <span class="badge badge-success">${(results.duration_seconds || 0).toFixed(1)}s Duration</span>
      </div>
      <div class="panel-body">
        <div class="meta-list">
          <div class="meta-row"><span class="meta-lbl">Tools Executed</span><span class="meta-val mono font-semibold">${results.total_tools_run} tools</span></div>
          <div class="meta-row"><span class="meta-lbl">Extracted Threat Indicators</span><span class="meta-val mono font-semibold text-danger">${iocs.length} unique IOCs</span></div>
          <div class="meta-row"><span class="meta-lbl">Aggregated Findings</span><span class="meta-val mono font-semibold text-warning">${findings.length} findings</span></div>
        </div>

        ${
          iocs.length
            ? `
          <div class="mt-4">
            <span class="text-xs font-semibold uppercase text-subtle">Extracted & Defanged IOCs:</span>
            <div class="tag-row mt-1">
              ${iocs.map((ioc) => `<span class="tag tag-installed mono">${ioc.type.toUpperCase()}: ${ioc.defanged || ioc.value}</span>`).join("")}
            </div>
          </div>
        `
            : ""
        }

        <!-- Tool Outputs Accordion -->
        <div class="mt-4">
          <span class="text-xs font-semibold uppercase text-subtle">Toolchain Output Logs:</span>
          ${(results.tool_results || [])
            .map(
              (tr, idx) => `
            <details class="tool-result-details mt-2">
              <summary class="tool-summary-bar">
                <span class="font-semibold">${tr.tool_name} (${tr.binary})</span>
                <span class="badge badge-${tr.exit_code === 0 ? "success" : "danger"} text-xs">Exit ${tr.exit_code} (${(tr.duration_seconds || 0).toFixed(2)}s)</span>
              </summary>
              <pre class="terminal-output mt-2">${tr.stdout || tr.stderr || "// No output generated"}</pre>
            </details>
          `
            )
            .join("")}
        </div>
      </div>
    </div>
  `;
}
