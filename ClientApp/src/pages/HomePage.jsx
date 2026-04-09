import { RefreshCcw, Shield, ShieldCheck } from "lucide-react";
import PageHeader from "../components/PageHeader";
import ScanSelector from "../components/ScanSelector";
import Timestamp from "../components/Timestamp";
import { EmptyState, ErrorState, TableSkeleton } from "../components/States";
import { scanModeOptions } from "../ui/constants";
import {
  buildSparklinePoints,
  computeSystemHealthPercent,
  describeFilesScanned,
  describeScanTarget,
  formatCompactDuration,
  formatDurationFromScan,
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
  onRefresh,
  onFocusScan,
  loading,
  error,
  lastUpdated
}) {
  const systemHealthPercent = computeSystemHealthPercent(health);
  const totalScans = scans.length;
  const totalThreats = threats.length;
  const cumulativeFiles = scans.reduce((sum, scan) => sum + Number(scan.filesScanned ?? 0), 0);
  const sparklinePoints = buildSparklinePoints(scans);
  const latestCompletedScan = scans.find((scan) => scan.completedAt) ?? scans[0] ?? null;
  const recentScans = scans.slice(0, 6);
  const recentFileEvents = fileEvents.slice(0, 6);
  const isActive = activeScan && (activeScan.status === "Running" || activeScan.status === "Pending");

  return (
    <div className="page-stack">
      <PageHeader
        eyebrow="Sentinel Shield Command"
        title="Home"
        description="System health at a glance, a fast scan workflow, and the latest endpoint activity."
        lastUpdated={lastUpdated}
        actions={
          <div className="header-inline-actions">
            <div className="context-chip">
              <span className={`engine-dot ${engineStatus?.online ? "online" : "offline"}`} aria-hidden="true" />
              {engineStatus?.online ? "Realtime protection on" : "Realtime protection offline"}
            </div>
            <div className="context-chip">
              {formatNumber(fleet?.activeDeviceCount)} endpoints
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
                placeholder="C:\\Suspicious\\Path"
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

          <ScanSelector scans={scans} label="Scan selector" id="home-scan-selector" />

          <button
            className="button button-secondary icon-button"
            type="button"
            aria-label="Refresh home data"
            onClick={onRefresh}
          >
            <RefreshCcw size={16} />
          </button>
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
                <span className="page-eyebrow">Active scan</span>
                <h2>{`SCAN-${String(activeScan.id).padStart(5, "0")}`}</h2>
                <p className="scan-target font-mono">{describeScanTarget(activeScan)}</p>
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
                <span>Current stage</span>
                <strong>{activeScan.stage}</strong>
              </div>
              <div>
                <span>Files scanned</span>
                <strong>{describeFilesScanned(activeScan)}</strong>
              </div>
              <div>
                <span>Findings</span>
                <strong className={activeScan.threatCount > 0 ? "text-critical" : ""}>{activeScan.threatCount}</strong>
              </div>
              <div>
                <span>Elapsed</span>
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
          <div className="metric-head">
            <span>Total Scans</span>
            <strong>{formatNumber(totalScans)}</strong>
          </div>
          <svg viewBox="0 0 200 48" className="sparkline" aria-hidden="true">
            <polyline points={sparklinePoints} />
          </svg>
        </article>

        <article className="metric-card">
          <span>Threats Detected</span>
          <strong className={totalThreats > 0 ? "text-critical" : "text-healthy"}>{formatNumber(totalThreats)}</strong>
          <small>{totalThreats > 0 ? "Open detections require review" : "No active threat detections"}</small>
        </article>

        <article className="metric-card">
          <span>Files Scanned</span>
          <strong>{formatNumber(cumulativeFiles)}</strong>
          <small>Cumulative processed files across recent runs</small>
        </article>

        <article className="metric-card metric-card-ring">
          <div>
            <span>System Health</span>
            <strong>{formatPercent(systemHealthPercent)}</strong>
            <small>{formatPercent(fleet?.agentCoveragePercent)} agent coverage</small>
          </div>
          <ProgressRing value={systemHealthPercent} />
        </article>
      </section>

      <section className="split-grid">
        <div className="panel">
          <div className="section-head">
            <h2>Recent Scans</h2>
          </div>
          {loading ? (
            <TableSkeleton rows={5} columns={6} />
          ) : recentScans.length === 0 ? (
            <EmptyState title="No scans yet" description="Run a scan to populate recent execution history." />
          ) : (
            <div className="table-shell">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>Mode</th>
                    <th>Status</th>
                    <th>Files Scanned</th>
                    <th>Threats</th>
                    <th>Duration</th>
                    <th>Date</th>
                  </tr>
                </thead>
                <tbody>
                  {recentScans.map((scan) => (
                    <tr key={scan.id}>
                      <td>
                        <button className="table-link font-mono" type="button" onClick={() => onFocusScan(scan.id)}>
                          {`SCAN-${String(scan.id).padStart(5, "0")}`}
                        </button>
                      </td>
                      <td>{scan.mode}</td>
                      <td>
                        <span className={`pill pill-${scanStatusTone(scan.status)}`}>{scan.status}</span>
                      </td>
                      <td>{describeFilesScanned(scan)}</td>
                      <td className={scan.threatCount > 0 ? "text-critical" : ""}>{scan.threatCount}</td>
                      <td>{formatCompactDuration(scan)}</td>
                      <td><Timestamp value={scan.completedAt ?? scan.createdAt} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        <div className="panel">
          <div className="section-head">
            <h2>Recent File Events</h2>
          </div>
          {loading ? (
            <TableSkeleton rows={5} columns={5} />
          ) : recentFileEvents.length === 0 ? (
            <EmptyState icon={Shield} title="No recent file events" description="Realtime file telemetry will appear here as the engine observes changes." />
          ) : (
            <div className="table-shell">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>File Path</th>
                    <th>Event Type</th>
                    <th>Status</th>
                    <th>Threat Count</th>
                    <th>Observed</th>
                  </tr>
                </thead>
                <tbody>
                  {recentFileEvents.map((fileEvent) => (
                    <tr key={fileEvent.id}>
                      <td className="path-cell font-mono" title={fileEvent.filePath}>{fileEvent.filePath}</td>
                      <td>{fileEvent.eventType}</td>
                      <td><span className="pill pill-muted">{fileEvent.status}</span></td>
                      <td className={fileEvent.threatCount > 0 ? "text-critical" : ""}>{fileEvent.threatCount}</td>
                      <td><Timestamp value={fileEvent.observedAt} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </section>
    </div>
  );
}
