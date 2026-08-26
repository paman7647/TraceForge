/**
 * TraceForge Case & Forensic Artifacts Controller
 * Manages Cases, Evidence specimens, IOCs, Findings, and Timelines.
 */

import { deleteJson, fetchJson, postJson, uploadEvidenceFile } from "./api.js";
import { navigateTo, updateHeaderActiveCase } from "./navigation.js";

let activeCaseId = null;
let cachedCases = [];

export async function loadActiveCase() {
  try {
    const data = await fetchJson("/api/cases/active");
    activeCaseId = data.active_case ? data.active_case.case_id : null;
    updateHeaderActiveCase(activeCaseId);
    return activeCaseId;
  } catch (e) {
    activeCaseId = null;
    updateHeaderActiveCase(null);
    return null;
  }
}

export function getActiveCaseId() {
  return activeCaseId;
}

export async function renderDashboard(container) {
  container.innerHTML = `<div class="loading-state"><div class="spinner"></div><span>Loading Dashboard...</span></div>`;
  try {
    const [casesData, runtimeData, auditData] = await Promise.all([
      fetchJson("/api/cases"),
      fetchJson("/api/runtime/status"),
      fetchJson("/api/catalog/platform-audit"),
    ]);

    cachedCases = casesData.cases || [];
    activeCaseId = casesData.active_case || null;
    updateHeaderActiveCase(activeCaseId);

    const activeCase = cachedCases.find((c) => c.case_id === activeCaseId) || null;
    const audit = auditData.audit || {};

    container.innerHTML = `
      <div class="dashboard-grid">
        <!-- Active Case Card -->
        <div class="panel">
          <div class="panel-header">
            <h2 class="panel-title">Active Investigation</h2>
            ${activeCase ? `<span class="badge badge-success">ACTIVE</span>` : `<span class="badge badge-neutral">NONE</span>`}
          </div>
          <div class="panel-body">
            ${
              activeCase
                ? `
              <div class="meta-list">
                <div class="meta-row"><span class="meta-lbl">Case ID</span><span class="meta-val mono">${activeCase.case_id}</span></div>
                <div class="meta-row"><span class="meta-lbl">Title</span><span class="meta-val font-semibold">${activeCase.name}</span></div>
                <div class="meta-row"><span class="meta-lbl">Lead Analyst</span><span class="meta-val">${activeCase.analyst}</span></div>
                <div class="meta-row"><span class="meta-lbl">Created</span><span class="meta-val">${activeCase.created_at || "—"}</span></div>
                <div class="meta-row"><span class="meta-lbl">Evidence / IOCs / Findings</span><span class="meta-val mono">${activeCase.evidence_count} / ${activeCase.ioc_count} / ${activeCase.finding_count}</span></div>
              </div>
              <div class="action-bar mt-4">
                <button class="btn btn-sm btn-primary" id="btnDashOpenEvidence">View Evidence</button>
                <button class="btn btn-sm btn-subtle" id="btnDashOpenBatch">Run Batch Suite</button>
                <button class="btn btn-sm btn-subtle" id="btnDashExport">Export Dossier</button>
              </div>
            `
                : `
              <p class="text-subtle">No active investigation selected. Create a new case or select an existing one to track evidence and chain of custody.</p>
              <div class="action-bar mt-4">
                <button class="btn btn-sm btn-primary" id="btnDashCreateCase">Create New Case</button>
                <button class="btn btn-sm btn-subtle" id="btnDashSelectCase">Browse Cases</button>
              </div>
            `
            }
          </div>
        </div>

        <!-- Platform & Toolchain Diagnostics Card -->
        <div class="panel">
          <div class="panel-header">
            <h2 class="panel-title">Platform & Toolchain Health</h2>
            <span class="badge badge-info">${audit.display_name || "Host"}</span>
          </div>
          <div class="panel-body">
            <div class="meta-list">
              <div class="meta-row"><span class="meta-lbl">Architecture / OS</span><span class="meta-val">${audit.display_name || "—"}</span></div>
              <div class="meta-row"><span class="meta-lbl">Execution Profile</span><span class="meta-val font-semibold">${runtimeData.active_profile || "PYTHON-GO"}</span></div>
              <div class="meta-row"><span class="meta-lbl">Catalog Coverage</span><span class="meta-val mono font-semibold">${audit.installed_count || 0} / ${audit.total_tools || 152} tools installed</span></div>
              <div class="meta-row"><span class="meta-lbl">Go Fast-Path Binary</span><span class="meta-val ${runtimeData.capabilities?.ioc?.selected_runtime === "go" ? "text-success" : "text-subtle"} font-semibold">${runtimeData.capabilities?.ioc?.selected_runtime === "go" ? "✓ ACCELERATED" : "Active"}</span></div>
            </div>
            <div class="action-bar mt-4">
              <button class="btn btn-sm btn-subtle" id="btnDashDoctor">Run Doctor</button>
              <button class="btn btn-sm btn-subtle" id="btnDashCatalog">Inspect Catalog (152)</button>
            </div>
          </div>
        </div>
      </div>

      <!-- Quick Launch Strip -->
      <div class="panel mt-4">
        <div class="panel-header">
          <h2 class="panel-title">Investigation Workbenches</h2>
        </div>
        <div class="module-quick-grid">
          <div class="quick-card" data-mod="image">
            <div class="quick-title">Media & Image</div>
            <div class="quick-desc">EXIF, GPS, IPTC, strings & steganography</div>
          </div>
          <div class="quick-card" data-mod="network">
            <div class="quick-title">Network & PCAP</div>
            <div class="quick-desc">Packet dissection, streams & protocol stats</div>
          </div>
          <div class="quick-card" data-mod="domain">
            <div class="quick-title">Domain & DNS</div>
            <div class="quick-desc">WHOIS, DNS records, subdomains & WAF</div>
          </div>
          <div class="quick-card" data-mod="email">
            <div class="quick-title">Email & Breach</div>
            <div class="quick-desc">MX deliverability, SPF/DMARC & registration</div>
          </div>
          <div class="quick-card" data-mod="identity">
            <div class="quick-title">Identity & SOCMINT</div>
            <div class="quick-desc">Username lookup & public alias profiling</div>
          </div>
          <div class="quick-card" data-mod="documents">
            <div class="quick-title">Documents</div>
            <div class="quick-desc">PDF, Office, OLE macros & author tracking</div>
          </div>
        </div>
      </div>
    `;

    // Wire up actions
    container.querySelector("#btnDashOpenEvidence")?.addEventListener("click", () => navigateTo("evidence"));
    container.querySelector("#btnDashOpenBatch")?.addEventListener("click", () => navigateTo("batch"));
    container.querySelector("#btnDashExport")?.addEventListener("click", () => navigateTo("reports"));
    container.querySelector("#btnDashCreateCase")?.addEventListener("click", () => showCreateCaseDialog());
    container.querySelector("#btnDashSelectCase")?.addEventListener("click", () => navigateTo("cases"));
    container.querySelector("#btnDashDoctor")?.addEventListener("click", () => navigateTo("doctor"));
    container.querySelector("#btnDashCatalog")?.addEventListener("click", () => navigateTo("catalog"));

    container.querySelectorAll(".quick-card").forEach((qc) => {
      qc.addEventListener("click", () => {
        window.location.hash = `investigations?module=${qc.dataset.mod}`;
      });
    });
  } catch (e) {
    container.innerHTML = `<div class="error-banner">Failed to load dashboard data: ${e.message}</div>`;
  }
}

export async function renderCases(container) {
  container.innerHTML = `<div class="loading-state"><div class="spinner"></div><span>Loading Cases...</span></div>`;
  try {
    const data = await fetchJson("/api/cases");
    cachedCases = data.cases || [];
    activeCaseId = data.active_case || null;
    updateHeaderActiveCase(activeCaseId);

    container.innerHTML = `
      <div class="toolbar">
        <div class="toolbar-left">
          <input type="text" class="input-text" id="caseSearch" placeholder="Filter cases by name or ID..." style="max-width: 300px;">
        </div>
        <div class="toolbar-right">
          <button class="btn btn-primary btn-sm" id="btnNewCase">
            <svg viewBox="0 0 24 24" width="14" height="14" stroke="currentColor" stroke-width="2" fill="none"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
            <span>New Case</span>
          </button>
        </div>
      </div>

      <div class="table-container mt-3">
        <table class="data-table">
          <thead>
            <tr>
              <th style="width: 40px;">Status</th>
              <th>Case ID</th>
              <th>Investigation Name</th>
              <th>Analyst</th>
              <th>Evidence</th>
              <th>IOCs</th>
              <th>Findings</th>
              <th>Created</th>
              <th style="text-align: right;">Actions</th>
            </tr>
          </thead>
          <tbody id="casesTableBody">
            ${renderCasesRows(cachedCases, activeCaseId)}
          </tbody>
        </table>
      </div>
    `;

    container.querySelector("#btnNewCase").addEventListener("click", () => showCreateCaseDialog());

    container.querySelector("#caseSearch").addEventListener("input", (e) => {
      const q = e.target.value.toLowerCase();
      const filtered = cachedCases.filter((c) => c.name.toLowerCase().includes(q) || c.case_id.toLowerCase().includes(q) || c.analyst.toLowerCase().includes(q));
      container.querySelector("#casesTableBody").innerHTML = renderCasesRows(filtered, activeCaseId);
      attachCaseRowListeners(container);
    });

    attachCaseRowListeners(container);
  } catch (e) {
    container.innerHTML = `<div class="error-banner">Failed to load cases: ${e.message}</div>`;
  }
}

function renderCasesRows(cases, activeId) {
  if (!cases.length) {
    return `<tr><td colspan="9" class="text-center text-subtle" style="padding: 30px;">No investigation cases found. Click 'New Case' to begin.</td></tr>`;
  }
  return cases
    .map((c) => {
      const isActive = c.case_id === activeId;
      return `
      <tr class="${isActive ? "row-active" : ""}">
        <td>${isActive ? `<span class="badge badge-success">ACTIVE</span>` : `<span class="badge badge-neutral">INACTIVE</span>`}</td>
        <td class="mono font-semibold">${c.case_id}</td>
        <td class="font-semibold">${c.name}</td>
        <td>${c.analyst}</td>
        <td class="mono">${c.evidence_count}</td>
        <td class="mono">${c.ioc_count}</td>
        <td class="mono">${c.finding_count}</td>
        <td class="text-subtle">${c.created_at || "—"}</td>
        <td style="text-align: right;">
          ${!isActive ? `<button class="btn btn-xs btn-subtle btn-activate-case" data-id="${c.case_id}">Activate</button>` : ""}
          <button class="btn btn-xs btn-subtle btn-delete-case text-danger" data-id="${c.case_id}">Delete</button>
        </td>
      </tr>
    `;
    })
    .join("");
}

function attachCaseRowListeners(container) {
  container.querySelectorAll(".btn-activate-case").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const cid = btn.dataset.id;
      try {
        await postJson("/api/cases/active", { case_id: cid });
        activeCaseId = cid;
        updateHeaderActiveCase(cid);
        renderCases(container);
      } catch (e) {
        alert(`Failed to activate case: ${e.message}`);
      }
    });
  });

  container.querySelectorAll(".btn-delete-case").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const cid = btn.dataset.id;
      if (!confirm(`Are you sure you want to permanently delete case ${cid}? This action cannot be undone.`)) {
        return;
      }
      try {
        await deleteJson(`/api/cases/${encodeURIComponent(cid)}`);
        renderCases(container);
      } catch (e) {
        alert(`Failed to delete case: ${e.message}`);
      }
    });
  });
}

export function showCreateCaseDialog() {
  const modal = document.createElement("div");
  modal.className = "modal-overlay";
  modal.innerHTML = `
    <div class="modal-card">
      <div class="modal-header">
        <h3 class="modal-title">Initialize New Investigation Case</h3>
        <button class="btn-close" id="btnCloseModal">×</button>
      </div>
      <div class="modal-body">
        <div class="form-group">
          <label class="form-label">Investigation Name *</label>
          <input type="text" class="input-text" id="modalCaseName" placeholder="e.g. Incident-2026-Alpha" required>
        </div>
        <div class="form-group mt-3">
          <label class="form-label">Lead Forensic Analyst</label>
          <input type="text" class="input-text" id="modalCaseAnalyst" placeholder="Analyst Name / Identifier" value="Analyst">
        </div>
      </div>
      <div class="modal-footer">
        <button class="btn btn-sm btn-subtle" id="btnCancelCase">Cancel</button>
        <button class="btn btn-sm btn-primary" id="btnConfirmCreateCase">Create Case</button>
      </div>
    </div>
  `;

  document.body.appendChild(modal);
  modal.querySelector("#btnCloseModal").onclick = () => modal.remove();
  modal.querySelector("#btnCancelCase").onclick = () => modal.remove();

  modal.querySelector("#btnConfirmCreateCase").onclick = async () => {
    const name = modal.querySelector("#modalCaseName").value.trim();
    const analyst = modal.querySelector("#modalCaseAnalyst").value.trim() || "Analyst";
    if (!name) {
      alert("Please specify an investigation name.");
      return;
    }
    try {
      const res = await postJson("/api/cases", { name, analyst });
      activeCaseId = res.case.case_id;
      updateHeaderActiveCase(activeCaseId);
      modal.remove();
      navigateTo("evidence");
    } catch (e) {
      alert(`Error creating case: ${e.message}`);
    }
  };
}

export async function renderEvidence(container) {
  if (!activeCaseId) {
    container.innerHTML = `
      <div class="empty-state">
        <h3>No Active Case Selected</h3>
        <p>You must activate or create an investigation case before uploading evidence specimens.</p>
        <button class="btn btn-sm btn-primary mt-3" id="btnEvSelectCase">Go to Cases</button>
      </div>
    `;
    container.querySelector("#btnEvSelectCase")?.addEventListener("click", () => navigateTo("cases"));
    return;
  }

  container.innerHTML = `<div class="loading-state"><div class="spinner"></div><span>Loading Evidence Repository...</span></div>`;
  try {
    const data = await fetchJson(`/api/cases/${encodeURIComponent(activeCaseId)}/evidence`);
    const evidenceList = data.evidence || [];

    container.innerHTML = `
      <div class="toolbar">
        <div class="toolbar-left">
          <span class="mono font-semibold">Active Case: ${activeCaseId}</span>
          <span class="badge badge-info ml-2">${evidenceList.length} Specimens</span>
        </div>
        <div class="toolbar-right">
          <button class="btn btn-primary btn-sm" id="btnUploadEvidence">
            <svg viewBox="0 0 24 24" width="14" height="14" stroke="currentColor" stroke-width="2" fill="none"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
            <span>Upload Specimen</span>
          </button>
        </div>
      </div>

      <div class="table-container mt-3">
        <table class="data-table">
          <thead>
            <tr>
              <th>Specimen Filename</th>
              <th>Description</th>
              <th>File Size</th>
              <th>SHA256 Checksum</th>
              <th>Ingestion Timestamp</th>
              <th style="text-align: right;">Actions</th>
            </tr>
          </thead>
          <tbody>
            ${
              evidenceList.length
                ? evidenceList
                    .map(
                      (ev) => `
              <tr>
                <td class="font-semibold mono">${ev.filename || ev.name}</td>
                <td>${ev.description || "—"}</td>
                <td class="mono">${ev.size ? `${(ev.size / 1024).toFixed(1)} KB` : "—"}</td>
                <td class="mono text-subtle" title="${ev.sha256}">${ev.sha256 ? `${ev.sha256.substring(0, 16)}...` : "—"}</td>
                <td class="text-subtle">${ev.added_at || ev.timestamp || "—"}</td>
                <td style="text-align: right;">
                  <button class="btn btn-xs btn-subtle btn-inspect-specimen" data-path="${ev.path}">Inspect in Modules</button>
                </td>
              </tr>
            `
                    )
                    .join("")
                : `<tr><td colspan="6" class="text-center text-subtle" style="padding: 30px;">No evidence specimens uploaded yet. Click 'Upload Specimen' to ingest forensic files.</td></tr>`
            }
          </tbody>
        </table>
      </div>
    `;

    container.querySelector("#btnUploadEvidence").addEventListener("click", () => showUploadDialog(activeCaseId, container));
    container.querySelectorAll(".btn-inspect-specimen").forEach((btn) => {
      btn.addEventListener("click", () => {
        window.location.hash = `investigations?target=${encodeURIComponent(btn.dataset.path)}`;
      });
    });
  } catch (e) {
    container.innerHTML = `<div class="error-banner">Failed to load evidence: ${e.message}</div>`;
  }
}

function showUploadDialog(caseId, parentContainer) {
  const modal = document.createElement("div");
  modal.className = "modal-overlay";
  modal.innerHTML = `
    <div class="modal-card">
      <div class="modal-header">
        <h3 class="modal-title">Upload Evidence Specimen</h3>
        <button class="btn-close" id="btnCloseUploadModal">×</button>
      </div>
      <div class="modal-body">
        <div class="form-group">
          <label class="form-label">Select File *</label>
          <input type="file" class="input-file" id="modalUploadInput" required>
        </div>
        <div class="form-group mt-3">
          <label class="form-label">Evidence Description / Notes</label>
          <input type="text" class="input-text" id="modalUploadDesc" placeholder="e.g. Memory dump, suspect image, PCAP capture">
        </div>
      </div>
      <div class="modal-footer">
        <button class="btn btn-sm btn-subtle" id="btnCancelUpload">Cancel</button>
        <button class="btn btn-sm btn-primary" id="btnConfirmUpload">Upload & Hash</button>
      </div>
    </div>
  `;

  document.body.appendChild(modal);
  modal.querySelector("#btnCloseUploadModal").onclick = () => modal.remove();
  modal.querySelector("#btnCancelUpload").onclick = () => modal.remove();

  modal.querySelector("#btnConfirmUpload").onclick = async () => {
    const fileInput = modal.querySelector("#modalUploadInput");
    const desc = modal.querySelector("#modalUploadDesc").value.trim();
    if (!fileInput.files.length) {
      alert("Please select a file to upload.");
      return;
    }
    const file = fileInput.files[0];
    const btn = modal.querySelector("#btnConfirmUpload");
    btn.disabled = true;
    btn.textContent = "Uploading...";

    try {
      await uploadEvidenceFile(caseId, file, desc);
      modal.remove();
      renderEvidence(parentContainer);
    } catch (e) {
      alert(`Upload failed: ${e.message}`);
      btn.disabled = false;
      btn.textContent = "Upload & Hash";
    }
  };
}

export async function renderIOCs(container) {
  if (!activeCaseId) {
    container.innerHTML = `<div class="empty-state"><h3>No Active Case Selected</h3><p>Select a case to inspect indicators of compromise.</p></div>`;
    return;
  }

  container.innerHTML = `<div class="loading-state"><div class="spinner"></div><span>Loading Threat Indicators...</span></div>`;
  try {
    const data = await fetchJson(`/api/cases/${encodeURIComponent(activeCaseId)}/iocs`);
    const iocs = data.iocs || [];

    container.innerHTML = `
      <div class="toolbar">
        <div class="toolbar-left">
          <input type="text" class="input-text" id="iocSearch" placeholder="Search observables..." style="max-width: 250px;">
          <select class="input-select ml-2" id="iocTypeFilter" style="max-width: 150px;">
            <option value="all">All Types</option>
            <option value="ip">IP Addresses</option>
            <option value="domain">Domains / Hosts</option>
            <option value="email">Emails</option>
            <option value="hash">File Hashes</option>
            <option value="url">URLs</option>
          </select>
        </div>
        <div class="toolbar-right">
          <button class="btn btn-primary btn-sm" id="btnAddIoc">Add Observable</button>
        </div>
      </div>

      <div class="table-container mt-3">
        <table class="data-table">
          <thead>
            <tr>
              <th style="width: 100px;">Type</th>
              <th>Defanged Observable</th>
              <th>Raw Value</th>
              <th>Confidence</th>
              <th>Discovered At</th>
            </tr>
          </thead>
          <tbody id="iocsTableBody">
            ${renderIocRows(iocs)}
          </tbody>
        </table>
      </div>
    `;

    container.querySelector("#btnAddIoc").addEventListener("click", () => showAddIocDialog(activeCaseId, container));
  } catch (e) {
    container.innerHTML = `<div class="error-banner">Failed to load IOCs: ${e.message}</div>`;
  }
}

function renderIocRows(iocs) {
  if (!iocs.length) {
    return `<tr><td colspan="5" class="text-center text-subtle" style="padding: 30px;">No threat indicators recorded for this case.</td></tr>`;
  }
  return iocs
    .map(
      (ioc) => `
    <tr>
      <td><span class="badge badge-info uppercase">${ioc.type}</span></td>
      <td class="mono font-semibold text-danger">${ioc.defanged || ioc.value}</td>
      <td class="mono text-subtle">${ioc.value}</td>
      <td><span class="badge badge-neutral">${ioc.confidence || "high"}</span></td>
      <td class="text-subtle">${ioc.added_at || ioc.timestamp || "—"}</td>
    </tr>
  `
    )
    .join("");
}

function showAddIocDialog(caseId, parentContainer) {
  const modal = document.createElement("div");
  modal.className = "modal-overlay";
  modal.innerHTML = `
    <div class="modal-card">
      <div class="modal-header">
        <h3 class="modal-title">Record Threat Observable / IOC</h3>
        <button class="btn-close" id="btnCloseIocModal">×</button>
      </div>
      <div class="modal-body">
        <div class="form-group">
          <label class="form-label">Indicator Type</label>
          <select class="input-select" id="modalIocType">
            <option value="domain">Domain / Hostname</option>
            <option value="ip">IPv4 / IPv6 Address</option>
            <option value="email">Email Address</option>
            <option value="sha256">SHA256 Hash</option>
            <option value="md5">MD5 Hash</option>
            <option value="url">URL Endpoint</option>
          </select>
        </div>
        <div class="form-group mt-3">
          <label class="form-label">Observable Value *</label>
          <input type="text" class="input-text" id="modalIocValue" placeholder="e.g. evil-c2.example.com" required>
        </div>
      </div>
      <div class="modal-footer">
        <button class="btn btn-sm btn-subtle" id="btnCancelIoc">Cancel</button>
        <button class="btn btn-sm btn-primary" id="btnConfirmAddIoc">Record IOC</button>
      </div>
    </div>
  `;

  document.body.appendChild(modal);
  modal.querySelector("#btnCloseIocModal").onclick = () => modal.remove();
  modal.querySelector("#btnCancelIoc").onclick = () => modal.remove();

  modal.querySelector("#btnConfirmAddIoc").onclick = async () => {
    const iocType = modal.querySelector("#modalIocType").value;
    const val = modal.querySelector("#modalIocValue").value.trim();
    if (!val) {
      alert("Observable value is required.");
      return;
    }
    try {
      await postJson(`/api/cases/${encodeURIComponent(caseId)}/iocs`, { type: iocType, value: val });
      modal.remove();
      renderIOCs(parentContainer);
    } catch (e) {
      alert(`Failed to add IOC: ${e.message}`);
    }
  };
}

export async function renderFindings(container) {
  if (!activeCaseId) {
    container.innerHTML = `<div class="empty-state"><h3>No Active Case Selected</h3><p>Select a case to view investigative findings.</p></div>`;
    return;
  }

  container.innerHTML = `<div class="loading-state"><div class="spinner"></div><span>Loading Findings...</span></div>`;
  try {
    const data = await fetchJson(`/api/cases/${encodeURIComponent(activeCaseId)}/findings`);
    const findings = data.findings || [];

    container.innerHTML = `
      <div class="toolbar">
        <div class="toolbar-left">
          <span class="mono font-semibold">Findings & Analyst Observations (${findings.length})</span>
        </div>
        <div class="toolbar-right">
          <button class="btn btn-primary btn-sm" id="btnAddFinding">Record Finding</button>
        </div>
      </div>

      <div class="table-container mt-3">
        <table class="data-table">
          <thead>
            <tr>
              <th style="width: 100px;">Severity</th>
              <th>Finding Title</th>
              <th>Details / Technical Context</th>
              <th>Timestamp</th>
            </tr>
          </thead>
          <tbody>
            ${
              findings.length
                ? findings
                    .map(
                      (f) => `
              <tr>
                <td><span class="badge badge-${f.severity?.toLowerCase() === "high" || f.severity?.toLowerCase() === "critical" ? "danger" : f.severity?.toLowerCase() === "low" ? "neutral" : "warning"}">${f.severity || "Medium"}</span></td>
                <td class="font-semibold">${f.title}</td>
                <td style="white-space: pre-wrap;">${f.details || f.description || "—"}</td>
                <td class="text-subtle">${f.created_at || f.timestamp || "—"}</td>
              </tr>
            `
                    )
                    .join("")
                : `<tr><td colspan="4" class="text-center text-subtle" style="padding: 30px;">No findings recorded yet for this investigation.</td></tr>`
            }
          </tbody>
        </table>
      </div>
    `;

    container.querySelector("#btnAddFinding").addEventListener("click", () => showAddFindingDialog(activeCaseId, container));
  } catch (e) {
    container.innerHTML = `<div class="error-banner">Failed to load findings: ${e.message}</div>`;
  }
}

function showAddFindingDialog(caseId, parentContainer) {
  const modal = document.createElement("div");
  modal.className = "modal-overlay";
  modal.innerHTML = `
    <div class="modal-card">
      <div class="modal-header">
        <h3 class="modal-title">Record Forensic Finding</h3>
        <button class="btn-close" id="btnCloseFindingModal">×</button>
      </div>
      <div class="modal-body">
        <div class="form-group">
          <label class="form-label">Finding Title *</label>
          <input type="text" class="input-text" id="modalFindingTitle" placeholder="e.g. Hidden GPS metadata discovered in suspect JPEG" required>
        </div>
        <div class="form-group mt-3">
          <label class="form-label">Severity Level</label>
          <select class="input-select" id="modalFindingSeverity">
            <option value="Low">Low</option>
            <option value="Medium" selected>Medium</option>
            <option value="High">High</option>
            <option value="Critical">Critical</option>
          </select>
        </div>
        <div class="form-group mt-3">
          <label class="form-label">Technical Observation Details</label>
          <textarea class="input-textarea" id="modalFindingDetails" rows="4" placeholder="Detailed evidence analysis notes..."></textarea>
        </div>
      </div>
      <div class="modal-footer">
        <button class="btn btn-sm btn-subtle" id="btnCancelFinding">Cancel</button>
        <button class="btn btn-sm btn-primary" id="btnConfirmAddFinding">Save Finding</button>
      </div>
    </div>
  `;

  document.body.appendChild(modal);
  modal.querySelector("#btnCloseFindingModal").onclick = () => modal.remove();
  modal.querySelector("#btnCancelFinding").onclick = () => modal.remove();

  modal.querySelector("#btnConfirmAddFinding").onclick = async () => {
    const title = modal.querySelector("#modalFindingTitle").value.trim();
    const severity = modal.querySelector("#modalFindingSeverity").value;
    const details = modal.querySelector("#modalFindingDetails").value.trim();
    if (!title) {
      alert("Finding title is required.");
      return;
    }
    try {
      await postJson(`/api/cases/${encodeURIComponent(caseId)}/findings`, { title, severity, details });
      modal.remove();
      renderFindings(parentContainer);
    } catch (e) {
      alert(`Failed to save finding: ${e.message}`);
    }
  };
}

export async function renderTimeline(container) {
  if (!activeCaseId) {
    container.innerHTML = `<div class="empty-state"><h3>No Active Case Selected</h3><p>Select a case to inspect the chronological timeline.</p></div>`;
    return;
  }

  container.innerHTML = `<div class="loading-state"><div class="spinner"></div><span>Loading Timeline Events...</span></div>`;
  try {
    const data = await fetchJson(`/api/cases/${encodeURIComponent(activeCaseId)}/timeline`);
    const events = data.timeline || [];

    container.innerHTML = `
      <div class="toolbar">
        <div class="toolbar-left">
          <span class="mono font-semibold">Chronological Investigation Events (${events.length})</span>
        </div>
        <div class="toolbar-right">
          <button class="btn btn-primary btn-sm" id="btnAddTimelineEvent">Record Event</button>
        </div>
      </div>

      <div class="timeline-container mt-3">
        ${
          events.length
            ? events
                .map(
                  (evt) => `
          <div class="timeline-item">
            <div class="timeline-dot"></div>
            <div class="timeline-content">
              <div class="timeline-header">
                <span class="timeline-time mono">${evt.timestamp || evt.time || "—"}</span>
                <span class="badge badge-neutral">${evt.source || "analyst"}</span>
              </div>
              <div class="timeline-desc">${evt.description || evt.event}</div>
            </div>
          </div>
        `
                )
                .join("")
            : `<div class="empty-state"><p class="text-subtle">No timeline events recorded for this case.</p></div>`
        }
      </div>
    `;

    container.querySelector("#btnAddTimelineEvent").addEventListener("click", () => showAddTimelineDialog(activeCaseId, container));
  } catch (e) {
    container.innerHTML = `<div class="error-banner">Failed to load timeline: ${e.message}</div>`;
  }
}

function showAddTimelineDialog(caseId, parentContainer) {
  const modal = document.createElement("div");
  modal.className = "modal-overlay";
  modal.innerHTML = `
    <div class="modal-card">
      <div class="modal-header">
        <h3 class="modal-title">Record Timeline Event</h3>
        <button class="btn-close" id="btnCloseTimelineModal">×</button>
      </div>
      <div class="modal-body">
        <div class="form-group">
          <label class="form-label">Event Description *</label>
          <input type="text" class="input-text" id="modalTimelineDesc" placeholder="e.g. Received secondary USB evidence disk from field team" required>
        </div>
      </div>
      <div class="modal-footer">
        <button class="btn btn-sm btn-subtle" id="btnCancelTimeline">Cancel</button>
        <button class="btn btn-sm btn-primary" id="btnConfirmAddTimeline">Record Event</button>
      </div>
    </div>
  `;

  document.body.appendChild(modal);
  modal.querySelector("#btnCloseTimelineModal").onclick = () => modal.remove();
  modal.querySelector("#btnCancelTimeline").onclick = () => modal.remove();

  modal.querySelector("#btnConfirmAddTimeline").onclick = async () => {
    const desc = modal.querySelector("#modalTimelineDesc").value.trim();
    if (!desc) {
      alert("Event description is required.");
      return;
    }
    try {
      await postJson(`/api/cases/${encodeURIComponent(caseId)}/timeline`, { description: desc, source: "analyst" });
      modal.remove();
      renderTimeline(parentContainer);
    } catch (e) {
      alert(`Failed to add timeline event: ${e.message}`);
    }
  };
}

export async function renderAssets(container) {
  if (!activeCaseId) {
    container.innerHTML = `<div class="empty-state"><h3>No Active Case Selected</h3><p>Select a case to view discovered assets.</p></div>`;
    return;
  }
  container.innerHTML = `
    <div class="panel">
      <div class="panel-header">
        <h2 class="panel-title">Asset Inventory (${activeCaseId})</h2>
      </div>
      <div class="panel-body">
        <p class="text-subtle">Discovered domains, hosts, email addresses, and network nodes are automatically indexed here from investigation modules.</p>
        <button class="btn btn-sm btn-subtle mt-3" id="btnBrowseIocs">Browse Recorded IOCs</button>
      </div>
    </div>
  `;
  container.querySelector("#btnBrowseIocs")?.addEventListener("click", () => navigateTo("iocs"));
}
