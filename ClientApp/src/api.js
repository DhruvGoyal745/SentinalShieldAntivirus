const apiBaseUrl = import.meta.env.VITE_API_BASE_URL ?? "";

let activeTenantKey = "sentinel-demo";

function resolveTenantKey() {
  return activeTenantKey;
}

export function setTenantKey(value) {
  activeTenantKey = value || "sentinel-demo";
}

async function request(path, options = {}) {
  const response = await fetch(`${apiBaseUrl}${path}`, {
    headers: {
      "Content-Type": "application/json",
      "X-Tenant-Key": resolveTenantKey(),
      ...(options.headers ?? {})
    },
    ...options
  });

  if (!response.ok) {
    let message = "Request failed";

    try {
      const body = await response.json();
      if (body.detail || body.error) {
        message = body.detail ?? body.error;
      } else if (body.title) {
        const validationMessages = body.errors
          ? Object.values(body.errors).flat().filter(Boolean)
          : [];
        message = validationMessages.length > 0
          ? `${body.title}: ${validationMessages.join(" ")}`
          : body.title;
      }
    } catch {
      message = await response.text();
    }

    throw new Error(message);
  }

  if (response.status === 204) {
    return null;
  }

  return response.json();
}

async function download(path) {
  const response = await fetch(`${apiBaseUrl}${path}`, {
    headers: {
      "X-Tenant-Key": resolveTenantKey()
    }
  });

  if (!response.ok) {
    throw new Error("Download failed");
  }

  const blob = await response.blob();
  const contentDisposition = response.headers.get("Content-Disposition") ?? "";
  const match = contentDisposition.match(/filename="?([^\"]+)"?/i);

  return {
    blob,
    fileName: match?.[1] ?? "scan-report.xls"
  };
}

export const api = {
  getControlPlaneSummary: () => request("/api/controlplane/summary"),
  getTenants: () => request("/api/controlplane/tenants"),
  getPacks: () => request("/api/controlplane/packs"),
  getCompliance: () => request("/api/controlplane/compliance"),
  captureCompliance: () =>
    request("/api/controlplane/compliance/capture", {
      method: "POST"
    }),
  resolveIncident: (id) =>
    request(`/api/controlplane/incidents/${id}/resolve`, {
      method: "POST"
    }),
  getParity: () => request("/api/governance/parity"),
  getSandbox: () => request("/api/governance/sandbox"),
  getReviews: () => request("/api/governance/reviews"),
  submitReview: (payload) =>
    request("/api/governance/reviews", {
      method: "POST",
      body: JSON.stringify(payload)
    }),
  decideReview: (id, payload) =>
    request(`/api/governance/reviews/${id}/decision`, {
      method: "POST",
      body: JSON.stringify(payload)
    }),
  getDashboard: () => request("/api/dashboard"),
  getScans: () => request("/api/scans"),
  getScanProgress: (scanId) => request(`/api/scans/${scanId}/progress`),
  getThreats: () => request("/api/threats"),
  getFileEvents: () => request("/api/fileevents"),
  getHealth: () => request("/api/health/status"),
  getEngineStatus: () => request("/api/engine/status"),
  registerAgent: (payload) =>
    request("/api/agent/register", {
      method: "POST",
      body: JSON.stringify(payload)
    }),
  heartbeat: (payload) =>
    request("/api/agent/heartbeat", {
      method: "POST",
      body: JSON.stringify(payload)
    }),
  getAgentPolicy: () => request("/api/agent/policy"),
  getAgentPack: () => request("/api/agent/pack"),
  getScanExports: () => request("/api/reports/scans/exports"),
  exportAllScans: () => download("/api/reports/scans/export"),
  exportScan: (scanId) => download(`/api/reports/scans/${scanId}/export`),
  startScan: (payload) =>
    request("/api/scans", {
      method: "POST",
      body: JSON.stringify(payload)
    }),
  stopScan: (scanId) =>
    request(`/api/scans/${scanId}/stop`, {
      method: "POST"
    }),
  submitFileDecision: (scanId, filePath, action) =>
    request(`/api/scans/${scanId}/file-decision`, {
      method: "POST",
      body: JSON.stringify({ filePath, action })
    }),
  quarantineThreat: (id) =>
    request(`/api/threats/${id}/quarantine`, {
      method: "POST"
    })
};
