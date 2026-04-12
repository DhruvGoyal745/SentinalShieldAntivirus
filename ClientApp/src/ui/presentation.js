import { pageDefinitions } from "./constants";

function clamp(value, minimum, maximum) {
  return Math.min(Math.max(value, minimum), maximum);
}

function formatTimeUnit(value, unit) {
  const rounded = Math.round(value);
  return new Intl.RelativeTimeFormat(undefined, { numeric: "auto" }).format(rounded, unit);
}

export function formatAbsoluteTime(value) {
  if (!value) {
    return "Unavailable";
  }

  return new Date(value).toISOString();
}

export function formatCompactDate(value) {
  if (!value) {
    return "Unknown";
  }

  return new Intl.DateTimeFormat(undefined, {
    month: "short",
    day: "numeric",
    year: "numeric"
  }).format(new Date(value));
}

export function formatRelativeTime(value) {
  if (!value) {
    return "Unavailable";
  }

  const now = Date.now();
  const date = new Date(value).getTime();
  const diffMs = date - now;
  const diffSeconds = diffMs / 1000;
  const diffMinutes = diffSeconds / 60;
  const diffHours = diffMinutes / 60;
  const diffDays = diffHours / 24;

  if (Math.abs(diffSeconds) < 60) {
    return formatTimeUnit(diffSeconds, "second");
  }

  if (Math.abs(diffMinutes) < 60) {
    return formatTimeUnit(diffMinutes, "minute");
  }

  if (Math.abs(diffHours) < 24) {
    return formatTimeUnit(diffHours, "hour");
  }

  return formatTimeUnit(diffDays, "day");
}

export function formatPercent(value, digits = 0) {
  return `${Number(value ?? 0).toFixed(digits)}%`;
}

export function formatNumber(value) {
  return Number(value ?? 0).toLocaleString();
}

export function formatFileSize(bytes) {
  const numeric = Number(bytes ?? 0);
  if (!numeric) {
    return "0 B";
  }

  const units = ["B", "KB", "MB", "GB"];
  const exponent = Math.min(Math.floor(Math.log(numeric) / Math.log(1024)), units.length - 1);
  const normalized = numeric / 1024 ** exponent;
  return `${normalized.toFixed(exponent === 0 ? 0 : 1)} ${units[exponent]}`;
}

export function formatDurationFromScan(scan, now = Date.now()) {
  if (!scan) {
    return "00:00:00";
  }

  const origin = new Date(scan.startedAt ?? scan.createdAt).getTime();
  const endpoint = scan.completedAt ? new Date(scan.completedAt).getTime() : now;
  const elapsedSeconds = Math.max(0, Math.floor((endpoint - origin) / 1000));
  const hours = Math.floor(elapsedSeconds / 3600);
  const minutes = Math.floor((elapsedSeconds % 3600) / 60);
  const seconds = elapsedSeconds % 60;
  return [hours, minutes, seconds].map((part) => String(part).padStart(2, "0")).join(":");
}

export function formatCompactDuration(scan, now = Date.now()) {
  const clock = formatDurationFromScan(scan, now).split(":").map(Number);
  const [hours, minutes, seconds] = clock;

  if (hours > 0) {
    return `${hours}h ${minutes}m`;
  }

  if (minutes > 0) {
    return `${minutes}m ${seconds}s`;
  }

  return `${seconds}s`;
}

export function severityTone(severity) {
  switch (severity) {
    case "Critical":
      return "critical";
    case "High":
      return "high";
    case "Medium":
    case "Suspicious":
      return "warning";
    case "Low":
    case "Informational":
    default:
      return "neutral";
  }
}

export function scanStatusTone(status) {
  switch (status) {
    case "Completed":
      return "healthy";
    case "Running":
      return "active";
    case "Failed":
      return "critical";
    case "Cancelled":
      return "muted";
    default:
      return "warning";
  }
}

export function fileEventTone(status) {
  switch (status) {
    case "ThreatDetected":
      return "critical";
    case "Suspicious":
      return "warning";
    case "Clean":
      return "healthy";
    case "Processing":
      return "active";
    case "Skipped":
      return "muted";
    default:
      return "neutral";
  }
}

export function reviewStatusTone(status) {
  switch (status) {
    case "Approved":
      return "healthy";
    case "Rejected":
      return "critical";
    case "UnderReview":
      return "active";
    case "Submitted":
    default:
      return "warning";
  }
}

export function sandboxVerdictTone(verdict) {
  switch (verdict) {
    case "Malicious":
      return "critical";
    case "Suspicious":
      return "warning";
    case "Benign":
      return "healthy";
    default:
      return "muted";
  }
}

export function incidentStatusTone(status) {
  switch (status) {
    case "Resolved":
      return "healthy";
    case "Contained":
      return "warning";
    case "Investigating":
      return "active";
    default:
      return "critical";
  }
}

export function complianceTone(value) {
  const numeric = Number(value ?? 0);
  if (numeric > 90) {
    return "healthy";
  }

  if (numeric >= 70) {
    return "warning";
  }

  return "critical";
}

export function getInitialPage() {
  const hash = window.location.hash.replace(/^#/, "").trim().toLowerCase();
  const pageKey = hash.split("/")[0];
  return pageDefinitions.some((page) => page.key === pageKey) ? pageKey : "home";
}

export function getInitialScanId() {
  const value = new URLSearchParams(window.location.search).get("scanId");
  const parsed = Number.parseInt(value ?? "", 10);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : null;
}

export function getGovernanceTabFromHash() {
  const hash = window.location.hash.replace(/^#/, "").trim().toLowerCase();
  const [, tab = "legacy-parity"] = hash.split("/");
  return tab || "legacy-parity";
}

export function mergeScanWithProgress(scan, progressEvent) {
  if (!scan) {
    return null;
  }

  if (!progressEvent) {
    return scan;
  }

  return {
    ...scan,
    percentComplete: progressEvent.percentComplete ?? scan.percentComplete,
    stage: progressEvent.stage ?? scan.stage,
    currentTarget: progressEvent.currentPath ?? scan.currentTarget,
    filesScanned: progressEvent.filesScanned ?? scan.filesScanned,
    totalFiles: progressEvent.totalFiles ?? scan.totalFiles,
    threatCount: progressEvent.findingsCount ?? scan.threatCount,
    startedAt: progressEvent.startedAt ?? scan.startedAt,
    completedAt: progressEvent.completedAt ?? scan.completedAt
  };
}

export function getLatestScanProgress(progressEvents) {
  if (!Array.isArray(progressEvents) || progressEvents.length === 0) {
    return null;
  }

  return progressEvents.reduce((latest, candidate) =>
    !latest || new Date(candidate.recordedAt).getTime() > new Date(latest.recordedAt).getTime()
      ? candidate
      : latest, null);
}

export function getSkippedEventKey(progressEvent) {
  if (!progressEvent) {
    return "";
  }

  return `${progressEvent.scanJobId}-${progressEvent.recordedAt}-${progressEvent.currentPath ?? "unknown"}`;
}

export function deriveScanProgress(scan, now) {
  if (!scan) {
    return 0;
  }

  if (typeof scan.percentComplete === "number" && Number.isFinite(scan.percentComplete)) {
    return clamp(Math.round(scan.percentComplete), 0, 100);
  }

  if (scan.status === "Completed" || scan.status === "Failed" || scan.status === "Cancelled") {
    return 100;
  }

  const startedAt = new Date(scan.startedAt ?? scan.createdAt).getTime();
  const elapsedSeconds = Math.max(0, (now - startedAt) / 1000);

  switch (scan.mode) {
    case "Quick":
      return clamp(Math.round(12 + elapsedSeconds * 4), 12, 96);
    case "Full":
      return clamp(Math.round(8 + elapsedSeconds * 1.4), 8, 94);
    case "Custom":
      return clamp(Math.round(14 + elapsedSeconds * 2.4), 14, 95);
    default:
      return clamp(Math.round(10 + elapsedSeconds * 2), 10, 94);
  }
}

export function describeFilesScanned(scan) {
  if (!scan) {
    return "0 / 0";
  }

  if (typeof scan.totalFiles === "number" && scan.totalFiles > 0) {
    return `${formatNumber(scan.filesScanned)} / ${formatNumber(scan.totalFiles)}`;
  }

  return formatNumber(scan.filesScanned);
}

export function describeScanTarget(scan) {
  if (!scan) {
    return "Awaiting target";
  }

  return scan.currentTarget ?? scan.targetPath ?? "Scanning managed estate";
}

export function describeHealthStatus(health) {
  if (!health) {
    return "Health snapshot pending";
  }

  const checks = [
    health.antivirusEnabled,
    health.realTimeProtectionEnabled,
    health.engineServiceEnabled,
    !health.signaturesOutOfDate
  ];
  const healthyCount = checks.filter(Boolean).length;
  return `${healthyCount} / ${checks.length} health checks passing`;
}

export function computeSystemHealthPercent(health) {
  if (!health) {
    return 0;
  }

  const checks = [
    health.antivirusEnabled,
    health.realTimeProtectionEnabled,
    health.ioavProtectionEnabled,
    health.networkInspectionEnabled,
    health.engineServiceEnabled,
    !health.signaturesOutOfDate
  ];

  return Math.round((checks.filter(Boolean).length / checks.length) * 100);
}

export function buildSparklinePoints(scans) {
  const sample = scans.slice(0, 7).reverse();
  if (sample.length === 0) {
    return "0,24 40,24 80,24 120,24 160,24 200,24";
  }

  return sample
    .map((scan, index) => {
      const x = sample.length === 1 ? 0 : (index / (sample.length - 1)) * 200;
      const progress = clamp(Number(scan.percentComplete ?? scan.threatCount ?? 0), 0, 100);
      const y = 48 - (progress / 100) * 36;
      return `${x},${y}`;
    })
    .join(" ");
}

export function parseEvidenceSha(evidenceJson) {
  if (!evidenceJson) {
    return null;
  }

  try {
    const evidence = JSON.parse(evidenceJson);
    return evidence.sha256 ?? evidence.hashSha256 ?? evidence.hash ?? null;
  } catch {
    return null;
  }
}

export function formatConfidence(confidence) {
  const numeric = Number(confidence ?? 0);
  return `${Math.round(numeric > 1 ? numeric : numeric * 100)}%`;
}
