const apiBaseUrl = import.meta.env.VITE_API_BASE_URL ?? "";

let activeTenantKey = "sentinel-demo";
let authToken = null;

function resolveTenantKey() {
  return activeTenantKey;
}

export function setTenantKey(value) {
  activeTenantKey = value || "sentinel-demo";
}

async function ensureAuthenticated() {
  if (authToken) {
    return;
  }

  try {
    const response = await fetch(`${apiBaseUrl}/api/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: "admin", password: "SentinelAdmin!2026" })
    });

    if (response.ok) {
      const data = await response.json();
      authToken = data.token;
    }
  } catch {
    // auth unavailable — proceed without token
  }
}

async function request(path, options = {}) {
  await ensureAuthenticated();

  const headers = {
    "Content-Type": "application/json",
    "X-Tenant-Key": resolveTenantKey(),
    ...(options.headers ?? {})
  };

  if (authToken) {
    headers["Authorization"] = `Bearer ${authToken}`;
  }

  const response = await fetch(`${apiBaseUrl}${path}`, {
    headers,
    ...options
  });

  if (response.status === 401 && authToken) {
    authToken = null;
    return request(path, options);
  }

  if (!response.ok) {
    let message = "Request failed";

    try {
      const text = await response.text();
      try {
        const body = JSON.parse(text);
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
        message = text || message;
      }
    } catch {
      // body completely unreadable — use default message
    }

    throw new Error(message);
  }

  if (response.status === 204) {
    return null;
  }

  return response.json();
}

async function download(path) {
  await ensureAuthenticated();

  const headers = {
    "X-Tenant-Key": resolveTenantKey()
  };

  if (authToken) {
    headers["Authorization"] = `Bearer ${authToken}`;
  }

  const response = await fetch(`${apiBaseUrl}${path}`, {
    headers
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
    }),

  // ── Phase 1: Platform Foundation ──────────────────────────────────
  getFeatureFlags: (tenant) =>
    request(`/api/platform/flags${tenant ? `?tenant=${encodeURIComponent(tenant)}` : ""}`),
  setFeatureFlag: (featureKey, enabled, tenant) =>
    request(`/api/platform/flags/${encodeURIComponent(featureKey)}?enabled=${enabled}${tenant ? `&tenant=${encodeURIComponent(tenant)}` : ""}`, {
      method: "POST"
    }),
  removeFeatureFlag: (featureKey, tenant) =>
    request(`/api/platform/flags/${encodeURIComponent(featureKey)}${tenant ? `?tenant=${encodeURIComponent(tenant)}` : ""}`, {
      method: "DELETE"
    }),
  getDeepHealth: () => request("/api/health/deep"),

  // ── Phase 2: Quarantine Vault ─────────────────────────────────────
  getQuarantineItems: (status, page, pageSize) => {
    const params = new URLSearchParams();
    if (status) params.set("status", status);
    if (page) params.set("page", String(page));
    if (pageSize) params.set("pageSize", String(pageSize));
    const qs = params.toString();
    return request(`/api/quarantine${qs ? `?${qs}` : ""}`);
  },
  restoreQuarantineItem: (id) =>
    request(`/api/quarantine/${id}/restore`, {
      method: "POST",
      body: JSON.stringify({})
    }),
  purgeQuarantineItem: (id) =>
    request(`/api/quarantine/${id}`, {
      method: "DELETE"
    }),
  purgeExpiredQuarantine: () =>
    request("/api/quarantine/purge-expired", {
      method: "POST"
    }),

  // ── Phase 2: Ransomware Shield ────────────────────────────────────
  getRansomwareSignals: (maxCount) =>
    request(`/api/ransomware/signals${maxCount ? `?maxCount=${maxCount}` : ""}`),
  getProtectedFolders: () => request("/api/ransomware/protected-folders"),

  // ── Phase 3: Threat Intelligence ──────────────────────────────────
  reputationLookup: (body) =>
    request("/api/reputation/lookup", { method: "POST", body: JSON.stringify(body) }),
  getReputationProviderHealth: () => request("/api/reputation/providers/health"),
  getReputationAudit: (max = 100) => request(`/api/reputation/audit?max=${max}`),

  searchIocs: (params = {}) => {
    const q = new URLSearchParams();
    Object.entries(params).forEach(([k, v]) => {
      if (v !== undefined && v !== null && v !== "") q.set(k, v);
    });
    const qs = q.toString();
    return request(`/api/iocs${qs ? `?${qs}` : ""}`);
  },
  getIocStats: () => request("/api/iocs/stats"),
  createIoc: (body) => request("/api/iocs", { method: "POST", body: JSON.stringify(body) }),
  deleteIoc: (id) => request(`/api/iocs/${id}`, { method: "DELETE" }),

  getThreatFeedSettings: () => request("/api/threat-feeds/settings"),
  updateThreatFeedSettings: (body) =>
    request("/api/threat-feeds/settings", { method: "PUT", body: JSON.stringify(body) }),
  syncThreatFeed: (provider) =>
    request(`/api/threat-feeds/${encodeURIComponent(provider)}/sync`, { method: "POST" }),
  getThreatFeedRuns: (provider, max = 50) => {
    const q = new URLSearchParams({ max });
    if (provider) q.set("provider", provider);
    return request(`/api/threat-feeds/runs?${q.toString()}`);
  },

  listSecrets: () => request("/api/secrets"),
  setSecret: (provider, key, value) =>
    request(`/api/secrets/${encodeURIComponent(provider)}/${encodeURIComponent(key)}`, {
      method: "PUT",
      body: JSON.stringify({ value })
    }),
  deleteSecret: (provider, key) =>
    request(`/api/secrets/${encodeURIComponent(provider)}/${encodeURIComponent(key)}`, { method: "DELETE" }),
};
