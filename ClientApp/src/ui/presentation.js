import { pageDefinitions } from "./constants";

export function formatDate(value) {
  if (!value) {
    return "Unavailable";
  }

  return new Date(value).toLocaleString();
}

export function formatPercent(value) {
  return `${Number(value ?? 0).toFixed(2)}%`;
}

function clamp(value, minimum, maximum) {
  return Math.min(Math.max(value, minimum), maximum);
}

export function severityTone(severity) {
  switch (severity) {
    case "Critical":
      return "critical";
    case "High":
      return "high";
    case "Medium":
    case "Suspicious":
      return "medium";
    case "Low":
      return "low";
    case "Informational":
    default:
      return "info";
  }
}

export function scanStatusTone(status) {
  switch (status) {
    case "Completed":
      return "success";
    case "Cancelled":
      return "pending";
    case "Failed":
      return "danger";
    case "Running":
      return "active";
    default:
      return "pending";
  }
}

export function fileEventTone(status) {
  switch (status) {
    case "ThreatDetected":
      return "critical";
    case "Error":
      return "danger";
    case "Suspicious":
      return "medium";
    case "Clean":
      return "success";
    case "Processing":
      return "active";
    default:
      return "pending";
  }
}

export function sandboxVerdictTone(verdict) {
  switch (verdict) {
    case "Malicious":
      return "critical";
    case "Suspicious":
      return "medium";
    case "Benign":
      return "success";
    default:
      return "pending";
  }
}

export function reviewStatusTone(status) {
  switch (status) {
    case "Approved":
      return "success";
    case "Rejected":
      return "danger";
    case "UnderReview":
      return "active";
    default:
      return "pending";
  }
}

export function getLatestScanProgress(progressEvents) {
  if (!Array.isArray(progressEvents) || progressEvents.length === 0) {
    return null;
  }

  return progressEvents.reduce((latest, candidate) => {
    if (!latest) {
      return candidate;
    }

    return new Date(candidate.recordedAt).getTime() > new Date(latest.recordedAt).getTime()
      ? candidate
      : latest;
  }, null);
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

export function getSkippedEventKey(progressEvent) {
  if (!progressEvent) {
    return "";
  }

  return `${progressEvent.scanJobId}-${progressEvent.recordedAt}-${progressEvent.currentPath ?? "unknown"}`;
}

export function describeFilesScanned(scan) {
  if (!scan) {
    return "Waiting";
  }

  if (typeof scan.totalFiles === "number" && scan.totalFiles > 0) {
    return `${scan.filesScanned ?? 0} / ${scan.totalFiles}`;
  }

  return `${scan.filesScanned ?? 0} processed`;
}

export function describeScanTarget(scan) {
  if (!scan) {
    return "Awaiting scan";
  }

  return scan.currentTarget ?? scan.targetPath ?? "Working through queued targets";
}

export function describeHealthStatus(health) {
  if (!health) {
    return "Waiting for runtime data";
  }

  if (health.antivirusSignatureLastUpdated) {
    const freshness = health.signaturesOutOfDate ? "Signatures stale" : "Signatures current";
    return `${freshness} | updated ${formatDate(health.antivirusSignatureLastUpdated)}`;
  }

  return health.antivirusSignatureVersion
    ? `Signature version ${health.antivirusSignatureVersion}`
    : "Runtime health captured";
}

export function getInitialPage() {
  const hash = window.location.hash.replace("#", "").trim().toLowerCase();
  return pageDefinitions.some((page) => page.key === hash) ? hash : "home";
}

export function deriveScanProgress(scan, now) {
  if (!scan) {
    return 0;
  }

  if (typeof scan.percentComplete === "number" && Number.isFinite(scan.percentComplete)) {
    return clamp(Math.round(scan.percentComplete), 0, 100);
  }

  if (scan.status === "Completed" || scan.status === "Failed") {
    return 100;
  }

  if (scan.status === "Pending") {
    return 8;
  }

  const origin = scan.startedAt ?? scan.createdAt;
  const elapsedSeconds = Math.max(0, (now - new Date(origin).getTime()) / 1000);

  switch (scan.mode) {
    case "Quick":
      return clamp(Math.round(18 + elapsedSeconds * 5), 18, 93);
    case "Full":
      return clamp(Math.round(14 + elapsedSeconds * 1.6), 14, 92);
    case "Custom":
      return clamp(Math.round(16 + elapsedSeconds * 2.8), 16, 92);
    default:
      return clamp(Math.round(18 + elapsedSeconds * 2), 18, 92);
  }
}

export function formatRuntime(scan) {
  if (!scan) {
    return "Waiting for a scan";
  }

  if (scan.status === "Pending" && !scan.startedAt) {
    return "Awaiting worker";
  }

  if (scan.status === "Cancelled") {
    return "Stopped";
  }

  const startedAt = scan.startedAt ?? scan.createdAt;
  const completedAt = scan.completedAt ?? new Date().toISOString();
  const elapsedMs = new Date(completedAt).getTime() - new Date(startedAt).getTime();

  if (!Number.isFinite(elapsedMs) || elapsedMs <= 0) {
    return "Just started";
  }

  const totalSeconds = Math.floor(elapsedMs / 1000);
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;

  if (minutes <= 0) {
    return `${seconds}s elapsed`;
  }

  return `${minutes}m ${seconds.toString().padStart(2, "0")}s elapsed`;
}

export function deriveAnalysisHeadline(scan) {
  if (!scan) {
    return "Choose a scan mode and start a customer-friendly security review.";
  }

  if (scan.status === "Pending") {
    return `Scan #${scan.id} is queued and waiting for the background worker.`;
  }

  if (scan.status === "Completed") {
    return scan.threatCount > 0
      ? `Scan #${scan.id} finished with ${scan.threatCount} findings ready for review.`
      : `Scan #${scan.id} finished clean with no confirmed detections.`;
  }

  if (scan.status === "Cancelled") {
    return `Scan #${scan.id} was stopped before completion.`;
  }

  if (scan.status === "Failed") {
    return `Scan #${scan.id} stopped before completion.`;
  }

  return `Scan #${scan.id} is actively analyzing the endpoint in realtime.`;
}

export function deriveAnalysisDetail(scan, progress) {
  if (!scan) {
    return "The analysis bar will light up here as soon as a user starts a scan.";
  }

  if (scan.notes) {
    return scan.notes;
  }

  if (scan.status === "Pending") {
    return "Queued in the scheduler and reserving the engine for execution.";
  }

  switch (scan.stage) {
    case "Observe":
      return "Observing configured roots and preparing the clean-room engine pipeline.";
    case "Normalize":
      return "Normalizing file metadata and building the scan queue.";
    case "StaticAnalysis":
      return "Hashing files and applying clean-room static signatures.";
    case "HeuristicAnalysis":
      return "Correlating behavior signals and clean-room heuristics.";
    case "ReputationLookup":
      return "Checking reputation and optional sandbox enrichment.";
    case "Response":
      return "Applying high-confidence remediation and quarantine decisions.";
    case "Telemetry":
      return "Persisting verdicts, detections, and scan telemetry.";
    default:
      break;
  }

  if (progress < 28) {
    return "Preparing scan roots and normalizing endpoint context.";
  }

  if (progress < 50) {
    return "Hashing files and applying proprietary static signatures.";
  }

  if (progress < 72) {
    return "Correlating behavior signals and suspicious execution patterns.";
  }

  if (progress < 88) {
    return "Fusing reputation signals and optional sandbox enrichment.";
  }

  return "Finalizing verdicts, remediation hints, and telemetry persistence.";
}
