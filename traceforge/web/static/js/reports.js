/**
 * TraceForge Reports & Dossier Controller
 * Generates and downloads multi-format case reports (Markdown, HTML, JSON, STIX 2.1).
 */

import { fetchJson, postJson } from "./api.js";
import { getActiveCaseId } from "./cases.js";

export async function renderReports(container) {
  const caseId = getActiveCaseId();
  if (!caseId) {
    container.innerHTML = `
      <div class="empty-state">
        <h3>No Active Case Selected</h3>
        <p>You must select or activate an investigation case to generate export dossiers.</p>
      </div>
    `;
    return;
  }

  container.innerHTML = `
    <div class="panel">
      <div class="panel-header">
        <h2 class="panel-title">Forensic Dossier & Report Export (${caseId})</h2>
      </div>
      <div class="panel-body">
        <p class="text-subtle">Generate formalized forensic reports, threat intelligence bundles, and timeline archives for your active investigation.</p>

        <div class="report-format-grid mt-4">
          <!-- Markdown Format -->
          <div class="report-card">
            <h3 class="font-semibold">Markdown Dossier (.md)</h3>
            <p class="text-subtle text-xs mt-1">Clean, standard GitHub-flavored Markdown dossier for technical archiving.</p>
            <div class="action-bar mt-3">
              <button class="btn btn-sm btn-subtle btn-preview-report" data-fmt="markdown">Preview</button>
              <button class="btn btn-sm btn-primary btn-dl-report" data-fmt="markdown">Download</button>
            </div>
          </div>

          <!-- HTML Format -->
          <div class="report-card">
            <h3 class="font-semibold">Standalone HTML Report (.html)</h3>
            <p class="text-subtle text-xs mt-1">Self-contained styled executive report suitable for presentation and sharing.</p>
            <div class="action-bar mt-3">
              <button class="btn btn-sm btn-subtle btn-preview-report" data-fmt="html">Open HTML</button>
              <button class="btn btn-sm btn-primary btn-dl-report" data-fmt="html">Download</button>
            </div>
          </div>

          <!-- JSON Bundle -->
          <div class="report-card">
            <h3 class="font-semibold">JSON Case Bundle (.json)</h3>
            <p class="text-subtle text-xs mt-1">Structured machine-readable archive including all evidence records, findings, and IOCs.</p>
            <div class="action-bar mt-3">
              <button class="btn btn-sm btn-subtle btn-preview-report" data-fmt="json">Preview JSON</button>
              <button class="btn btn-sm btn-primary btn-dl-report" data-fmt="json">Download</button>
            </div>
          </div>

          <!-- STIX 2.1 -->
          <div class="report-card">
            <h3 class="font-semibold">STIX 2.1 Threat Intel (.json)</h3>
            <p class="text-subtle text-xs mt-1">OASIS STIX 2.1 standardized threat intelligence bundle for SIEM/TIP ingestion.</p>
            <div class="action-bar mt-3">
              <button class="btn btn-sm btn-subtle btn-preview-report" data-fmt="stix">Preview STIX</button>
              <button class="btn btn-sm btn-primary btn-dl-report" data-fmt="stix">Download</button>
            </div>
          </div>
        </div>

        <!-- Export All Button -->
        <div class="action-bar mt-4">
          <button class="btn btn-primary btn-sm" id="btnExportAllBundle">Export Complete Multi-Format Archive</button>
        </div>
      </div>
    </div>
  `;

  container.querySelectorAll(".btn-preview-report").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const fmt = btn.dataset.fmt;
      if (fmt === "html") {
        window.open(`/api/cases/${encodeURIComponent(caseId)}/report?format=html`, "_blank");
      } else {
        try {
          const res = await fetch(`/api/cases/${encodeURIComponent(caseId)}/report?format=${fmt}`);
          const text = await res.text();
          showReportPreviewModal(text, fmt);
        } catch (e) {
          alert(`Failed to preview report: ${e.message}`);
        }
      }
    });
  });

  container.querySelectorAll(".btn-dl-report").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const fmt = btn.dataset.fmt;
      const ext = fmt === "html" ? "html" : fmt === "markdown" ? "md" : "json";
      const url = `/api/cases/${encodeURIComponent(caseId)}/report?format=${fmt}`;
      const a = document.createElement("a");
      a.href = url;
      a.download = `${caseId}_report.${ext}`;
      document.body.appendChild(a);
      a.click();
      a.remove();
    });
  });

  container.querySelector("#btnExportAllBundle").addEventListener("click", async () => {
    try {
      const res = await postJson(`/api/cases/${encodeURIComponent(caseId)}/export`, { redact: false });
      alert(`[✓] Successfully exported all case formats into case 'exports/' directory!`);
    } catch (e) {
      alert(`Export failed: ${e.message}`);
    }
  });
}

function showReportPreviewModal(content, fmt) {
  const modal = document.createElement("div");
  modal.className = "modal-overlay";
  modal.innerHTML = `
    <div class="modal-card" style="max-width: 800px; width: 90%;">
      <div class="modal-header">
        <h3 class="modal-title">Report Preview (${fmt.toUpperCase()})</h3>
        <button class="btn-close" id="btnClosePreviewModal">×</button>
      </div>
      <div class="modal-body">
        <pre class="terminal-output" style="max-height: 450px; overflow-y: auto;">${escapeHtml(content)}</pre>
      </div>
      <div class="modal-footer">
        <button class="btn btn-sm btn-subtle" id="btnClosePreviewBtn">Close</button>
      </div>
    </div>
  `;

  document.body.appendChild(modal);
  modal.querySelector("#btnClosePreviewModal").onclick = () => modal.remove();
  modal.querySelector("#btnClosePreviewBtn").onclick = () => modal.remove();
}

function escapeHtml(text) {
  const div = document.createElement("div");
  div.textContent = text;
  return div.innerHTML;
}
