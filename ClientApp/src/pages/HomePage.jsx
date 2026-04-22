import { ShieldCheck, Lock, ShieldAlert } from "lucide-react";
import PageHeader from "../components/PageHeader";
import Timestamp from "../components/Timestamp";
import { ErrorState } from "../components/States";
import { scanModeOptions } from "../ui/constants";
import {
  computeSystemHealthPercent,
  describeFilesScanned,
  formatCompactDuration,
  formatDurationFromScan,
  formatFileSize,
  formatNumber,
  formatPercent,
  scanStatusTone
} from "../ui/presentation";

function ProgressRing({ value }) {
  const radius = 36;
  const circumference = 2 * Math.PI * radius;
  const dashOffset = circumference - (value / 100) * circumference;

  return (
    <svg viewBox="0 0 96 96" className="progress-ring" aria-hidden="true">
      <circle cx="48" cy="48" r={radius} className="progress-ring-track" />
      <circle
        cx="48"
        cy="48"
        r={radius}
        className="progress-ring-value"
        strokeDasharray={circumference}
        strokeDashoffset={dashOffset}
      />
      <text x="48" y="52" textAnchor="middle">
        {value}%
      </text>
    </svg>
  );
}

export default function HomePage({
  scanRequest,
  setScanRequest,
  submitting,
  onSubmit,
  activeScan,
  analysisProgress,
  analysisSteps,
  handleStopScan,
  stoppingScanId,
  scans,
  threats,
  fileEvents,
  health,
  fleet,
  engineStatus,
  dashboardStats,
  quarantineItems = [],
  ransomwareSignals = [],
  onRefresh,
  onFocusScan,
  loading,
  error,
  lastUpdated
}) {
  const systemHealthPercent = computeSystemHealthPercent(health);
  const totalScans = scans.length;
  const uniqueThreatCount = dashboardStats?.uniqueThreatsFound ?? 0;
  const uniqueFilesChecked = dashboardStats?.uniqueFilesChecked ?? 0;

  const latestCompletedScan = scans.find((scan) => scan.completedAt) ?? scans[0] ?? null;
  const recentScans = scans.slice(0, 6);
  const isActive = activeScan && (activeScan.status === "Running" || activeScan.status === "Pending");

  return (
    <div className="page-stack">
      <PageHeader
        eyebrow="Dashboard"
        title="Home"
        lastUpdated={lastUpdated}
        actions={
          <div className="header-inline-actions">
            <div className="context-chip">
              <span className={`engine-dot ${engineStatus?.online ? "online" : "offline"}`} aria-hidden="true" />
              {engineStatus?.online ? "Protection active" : "Protection offline"}
            </div>
          </div>
        }
      />

      <section className="panel sticky-toolbar">
        <form className="toolbar-grid" onSubmit={onSubmit}>
          <label className="field">
            <span>Scan mode</span>
            <select
              value={scanRequest.mode}
              onChange={(event) => setScanRequest((current) => ({ ...current, mode: event.target.value }))}
            >
              {scanModeOptions.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </select>
          </label>

          {scanRequest.mode === "Custom" ? (
            <label className="field field-flex">
              <span>Target path</span>
              <input
                value={scanRequest.targetPath}
                onChange={(event) => setScanRequest((current) => ({ ...current, targetPath: event.target.value }))}
                placeholder="e.g. C:\Users\Documents"
              />
            </label>
          ) : null}

          <button className="button button-primary" type="submit" disabled={submitting || isActive}>
            {submitting ? "Starting..." : "Start Scan"}
          </button>

          {isActive ? (
            <button
              className="button button-danger-outline"
              type="button"
              onClick={() => handleStopScan(activeScan.id)}
              disabled={stoppingScanId === activeScan.id}
            >
              {stoppingScanId === activeScan.id ? "Stopping..." : "Stop"}
            </button>
          ) : null}
        </form>
      </section>

      {error ? <ErrorState message={error} onRetry={onRefresh} /> : null}

      <section className="panel home-progress">
        {!activeScan ? (
          <div className="protected-state">
            <div className="protected-icon">
              <ShieldCheck size={42} aria-hidden="true" />
            </div>
            <strong>System Protected</strong>
            <span>
              Last scan: <Timestamp value={latestCompletedScan?.completedAt ?? latestCompletedScan?.createdAt} />
            </span>
          </div>
        ) : (
          <>
            <div className="progress-header">
              <div>
                <span className="page-eyebrow">Scanning now</span>
                <h2>{activeScan.mode} Scan</h2>
              </div>
              <div className="progress-meta">
                <span className={`pill pill-${scanStatusTone(activeScan.status)}`}>{activeScan.status}</span>
                <strong>{analysisProgress}%</strong>
              </div>
            </div>

            <div className="progress-track" aria-hidden="true">
              <div className="progress-fill progress-fill-animated" style={{ width: `${analysisProgress}%` }} />
            </div>

            <div className="progress-stats">
              <div>
                <span>Files checked</span>
                <strong>{describeFilesScanned(activeScan)}</strong>
              </div>
              <div>
                <span>Threats found</span>
                <strong className={activeScan.threatCount > 0 ? "text-critical" : ""}>{activeScan.threatCount}</strong>
              </div>
              <div>
                <span>Time elapsed</span>
                <strong>{formatDurationFromScan(activeScan)}</strong>
              </div>
            </div>

            <ul className="stage-strip">
              {analysisSteps.map((step) => (
                <li key={step.key} className={`stage-pill stage-${step.state}`}>
                  {step.label}
                </li>
              ))}
            </ul>
          </>
        )}
      </section>

      <section className="stats-grid">
        <article className="metric-card">
          <span>Scans completed</span>
          <strong>{formatNumber(totalScans)}</strong>
        </article>

        <article className="metric-card">
          <span>Threats found</span>
          <strong className={uniqueThreatCount > 0 ? "text-critical" : "text-healthy"}>{formatNumber(uniqueThreatCount)}</strong>
          <small>{uniqueThreatCount > 0 ? "Needs your attention" : "You're safe"}</small>
        </article>

        <article className="metric-card">
          <span>Files checked</span>
          <strong>{formatNumber(uniqueFilesChecked)}</strong>
        </article>

        <article className="metric-card metric-card-ring">
          <div>
            <span>Protection</span>
            <strong>{formatPercent(systemHealthPercent)}</strong>
          </div>
          <ProgressRing value={systemHealthPercent} />
        </article>

        <article className="metric-card">
          <Lock size={20} aria-hidden="true" />
          <span>Quarantine Vault</span>
          <strong>{formatNumber(quarantineItems.filter(i => i.purgeState === "Active" || i.purgeState === 0).length)}</strong>
          <small>{formatFileSize(quarantineItems.reduce((sum, i) => sum + (i.fileSizeBytes ?? 0), 0))} encrypted</small>
        </article>

        <article className="metric-card">
          <ShieldAlert size={20} aria-hidden="true" />
          <span>Ransomware Shield</span>
          <strong className={ransomwareSignals.length > 0 ? "text-warning" : "text-healthy"}>{ransomwareSignals.length}</strong>
          <small>{ransomwareSignals.length > 0 ? "Recent signals detected" : "No threats detected"}</small>
        </article>
      </section>

      {recentScans.length > 0 ? (
        <section className="panel">
          <div className="section-head">
            <h2>Recent Scans</h2>
          </div>
          <div className="table-shell">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Type</th>
                  <th>Status</th>
                  <th>Threats</th>
                  <th>Duration</th>
                  <th>Date</th>
                </tr>
              </thead>
              <tbody>
                {recentScans.map((scan) => (
                  <tr key={scan.id} onClick={() => onFocusScan(scan.id)} className="clickable-row">
                    <td>{scan.mode} scan</td>
                    <td>
                      <span className={`pill pill-${scanStatusTone(scan.status)}`}>{scan.status}</span>
                    </td>
                    <td className={scan.threatCount > 0 ? "text-critical" : ""}>{scan.threatCount}</td>
                    <td>{formatCompactDuration(scan)}</td>
                    <td><Timestamp value={scan.completedAt ?? scan.createdAt} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      ) : null}
    </div>
  );
}
