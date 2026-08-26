/**
 * TraceForge API Client
 * Reusable HTTP client for communicating with backend REST endpoints.
 */

export async function fetchJson(url) {
  try {
    const res = await fetch(url, { headers: { "Accept": "application/json" } });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: `HTTP ${res.status}: ${res.statusText}` }));
      throw new Error(err.error || `HTTP ${res.status}`);
    }
    return await res.json();
  } catch (e) {
    console.error(`API error on GET ${url}:`, e);
    throw e;
  }
}

export async function postJson(url, payload = {}) {
  try {
    const res = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Accept": "application/json",
      },
      body: JSON.stringify(payload),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      throw new Error(data.error || `HTTP ${res.status}`);
    }
    return data;
  } catch (e) {
    console.error(`API error on POST ${url}:`, e);
    throw e;
  }
}

export async function deleteJson(url) {
  try {
    const res = await fetch(url, {
      method: "DELETE",
      headers: { "Accept": "application/json" },
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      throw new Error(data.error || `HTTP ${res.status}`);
    }
    return data;
  } catch (e) {
    console.error(`API error on DELETE ${url}:`, e);
    throw e;
  }
}

export async function uploadEvidenceFile(caseId, file, description = "") {
  const formData = new FormData();
  formData.append("file", file, file.name);
  if (description) {
    formData.append("description", description);
  }

  const res = await fetch(`/api/cases/${encodeURIComponent(caseId)}/evidence`, {
    method: "POST",
    body: formData,
  });

  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(data.error || `Upload failed (HTTP ${res.status})`);
  }
  return data;
}
