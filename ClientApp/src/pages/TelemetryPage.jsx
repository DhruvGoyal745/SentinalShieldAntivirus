import { useDeferredValue } from "react";
import { liveScanStatuses } from "../ui/constants";
import { deriveScanProgress, describeFilesScanned, describeScanTarget, fileEventTone, formatDate } from "../ui/presentation";
import ScanSelector from "../components/ScanSelector";

export default function TelemetryPage({
  fileEvents,
  scans,
  telemetryQuery,
  setTelemetryQuery,
  onFocusScan,
  onExportScan,
  onStopScan,
  stoppingScanId,
  analysisClock,
  selectedScanId,
  setSelectedScanId
}) {
  const deferredQuery = useDeferredValue(telemetryQuery);
  const needle = deferredQuery.trim().toLowerCase();

  const filteredFileEvents = !needle
    ? fileEvents
    : fileEvents.filter((fileEvent) =>
        [fileEvent.filePath, fileEvent.notes, fileEvent.eventType, fileEvent.status]
          .filter(Boolean)
          .some((value) => value.toLowerCase().includes(needle))
      );
  const finalFileEvents = selectedScanId
    ? filteredFileEvents.filter((fileEvent) => fileEvent.scanJobId === selectedScanId)
    : filteredFileEvents;

  const filteredScans = !needle
    ? scans
    : scans.filter((scan) =>
        [scan.mode, scan.status, scan.requestedBy, scan.notes, scan.id.toString()]
          .filter(Boolean)
          .some((value) => value.toLowerCase().includes(needle))
      );
  const finalScans = selectedScanId
    ? filteredScans.filter((scan) => scan.id === selectedScanId)
    : filteredScans;

  return (
    <section className="panel page-panel">
      <div className="panel-heading">
        <h2>Endpoint telemetry trail</h2>
        <p>Realtime file events and scan history now live together on one clean investigation page.</p>
      </div>

      <div className="toolbar">
        <ScanSelector scans={scans} selectedScanId={selectedScanId} onChange={setSelectedScanId} />
        <input
          value={telemetryQuery}
          onChange={(event) => setTelemetryQuery(event.target.value)}
          placeholder="Search scans, statuses, file paths, or notes"
        />
      </div>

      <div className="two-column-grid">
        <div className="subpanel">
          <h3>Realtime file events</h3>
          <div className="history-list">
            {finalFileEvents.map((fileEvent) => (
              <article key={fileEvent.id} className="history-card">
                <div className="history-header">
                  <div>
                    <span className="history-mode">{fileEvent.eventType}</span>
                    <h3>{fileEvent.filePath}</h3>
                  </div>
                  <span className={`pill ${fileEventTone(fileEvent.status)}`}>{fileEvent.status}</span>
                </div>
                <div className="history-meta">
                  <span>Threats: {fileEvent.threatCount}</span>
                  <span>Observed: {formatDate(fileEvent.observedAt)}</span>
                  <span>Processed: {formatDate(fileEvent.processedAt)}</span>
                  <span>Hash: {fileEvent.hashSha256 ? `${fileEvent.hashSha256.slice(0, 12)}...` : "Pending"}</span>
                </div>
                <p>{fileEvent.notes || "No notes recorded for this file event."}</p>
                <div className="engine-list">
                  {fileEvent.engineResults?.map((result) => (
                    <span key={`${fileEvent.id}-${result.id}`} className="engine-chip">
                      {result.engineName}: {result.status}
                      {result.signatureName ? ` (${result.signatureName})` : ""}
                    </span>
                  ))}
                </div>
              </article>
            ))}
            {finalFileEvents.length === 0 ? <p className="empty-state">No telemetry events matched this filter.</p> : null}
          </div>
        </div>

        <div className="subpanel">
          <h3>Scan history</h3>
          <div className="history-list">
            {finalScans.map((scan) => (
              <article key={scan.id} className="history-card">
                <div className="history-header">
                  <div>
                    <span className="history-mode">{scan.mode}</span>
                    <h3>Scan PK #{scan.id}</h3>
                  </div>
                  <div className="action-row">
                    <button className="ghost-button compact" type="button" onClick={() => onFocusScan(scan.id)}>
                      Focus
                    </button>
                    <button className="ghost-button compact" type="button" onClick={() => onExportScan(scan.id)}>
                      Export Excel
                    </button>
                    {liveScanStatuses.has(scan.status) ? (
                      <button
                        className="ghost-button compact"
                        type="button"
                        onClick={() => onStopScan(scan.id)}
                        disabled={stoppingScanId === scan.id}
                      >
                        {stoppingScanId === scan.id ? "Stopping..." : "Stop"}
                      </button>
                    ) : null}
                  </div>
                </div>
                <div className="scan-mini-track" aria-hidden="true">
                  <div
                    className={`scan-mini-fill ${scan.status === "Completed" ? "complete" : ""} ${scan.status === "Failed" ? "failed" : ""}`}
                    style={{ width: `${deriveScanProgress(scan, analysisClock)}%` }}
                  />
                </div>
                <div className="history-meta">
                  <span>Primary key: {scan.id}</span>
                  <span>Status: {scan.status}</span>
                  <span>Stage: {scan.stage}</span>
                  <span>Files: {describeFilesScanned(scan)}</span>
                  <span>Threats: {scan.threatCount}</span>
                  <span>Requested by: {scan.requestedBy}</span>
                  <span>Created: {formatDate(scan.createdAt)}</span>
                </div>
                <p>{scan.notes || describeScanTarget(scan)}</p>
              </article>
            ))}
            {finalScans.length === 0 ? <p className="empty-state">No scans matched this filter.</p> : null}
          </div>
        </div>
      </div>
    </section>
  );
}
