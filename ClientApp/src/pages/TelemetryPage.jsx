import { useDeferredValue, useMemo, useState } from "react";
import { File, FileCog, FilePenLine, FilePlus2, FileX2, ShieldAlert } from "lucide-react";
import PageHeader from "../components/PageHeader";
import ScanSelector from "../components/ScanSelector";
import Timestamp from "../components/Timestamp";
import { EmptyState, ErrorState, TableSkeleton } from "../components/States";
import { useDashboardStore } from "../state/useDashboardStore";
import { fileEventTone, formatFileSize, formatEntropy, ransomwareActionTone } from "../ui/presentation";

const iconByEvent = {
  Created: FilePlus2,
  Changed: FilePenLine,
  Renamed: FileCog,
  Deleted: FileX2
};

export default function TelemetryPage({
  fileEvents,
  scans,
  scanProgressEvents,
  ransomwareSignals = [],
  loading,
  error,
  onRefresh,
  lastUpdated
}) {
  const [query, setQuery] = useState("");
  const [expandedEventIds, setExpandedEventIds] = useState([]);
  const selectedScanId = useDashboardStore((state) => state.selectedScanId);
  const deferredQuery = useDeferredValue(query);

  const scanFilteredFileEvents = useMemo(() => {
    if (!selectedScanId) return fileEvents;
    return fileEvents.filter((event) => event.scanJobId === selectedScanId);
  }, [fileEvents, selectedScanId]);

  const filteredFileEvents = useMemo(() => {
    const needle = deferredQuery.trim().toLowerCase();
    return !needle
      ? scanFilteredFileEvents
      : scanFilteredFileEvents.filter((event) =>
          [event.filePath, event.notes, event.eventType, event.status, event.hashSha256]
            .filter(Boolean)
            .some((value) => value.toLowerCase().includes(needle))
        );
  }, [deferredQuery, scanFilteredFileEvents]);

  return (
    <div className="page-stack">
      <PageHeader
        eyebrow="Monitoring"
        title="Activity"
        lastUpdated={lastUpdated}
        actions={
          <div className="header-inline-actions">
            <ScanSelector scans={scans} label="Scan context" id="telemetry-scan-selector" />
            <label className="field field-search">
              <span>Search</span>
              <input
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder="Search by file name or status"
              />
            </label>
          </div>
        }
      />

      {error ? <ErrorState message={error} onRetry={onRefresh} /> : null}

      {ransomwareSignals.length > 0 ? (
        <section className="panel">
          <div className="section-head">
            <h2><ShieldAlert size={18} aria-hidden="true" /> Ransomware Activity</h2>
          </div>
          <div className="telemetry-stream">
            {ransomwareSignals.map((signal, index) => (
              <article key={`ransomware-${index}`} className="telemetry-item ransomware-signal-item">
                <div className="telemetry-summary">
                  <div className="telemetry-path">
                    <ShieldAlert size={18} aria-hidden="true" />
                    <span className="font-mono" title={signal.processPath}>{signal.processPath}</span>
                  </div>
                  <div className="telemetry-badges">
                    <span className={`pill pill-${ransomwareActionTone(signal.recommendedAction)}`}>
                      {signal.recommendedAction}
                    </span>
                    <span className="pill pill-critical">{signal.affectedFileCount} files affected</span>
                  </div>
                  <div className="telemetry-meta">
                    <span className="entropy-indicator">Entropy: {formatEntropy(signal.maxEntropyScore)}</span>
                    <span>{signal.extensionChangeCount} ext changes</span>
                    <Timestamp value={signal.detectedAt} />
                  </div>
                </div>
                {signal.summary ? <p className="card-description">{signal.summary}</p> : null}
              </article>
            ))}
          </div>
        </section>
      ) : null}

      <section className="panel">
        <div className="section-head">
          <h2>File Activity</h2>
        </div>
        {loading ? (
          <TableSkeleton rows={6} columns={5} />
        ) : filteredFileEvents.length === 0 ? (
          <EmptyState title="No file activity yet" description="Files will appear here as Sentinel Shield monitors your system." />
        ) : (
          <div className="telemetry-stream">
            {filteredFileEvents.map((fileEvent) => {
              const Icon = iconByEvent[fileEvent.eventType] ?? File;
              const expanded = expandedEventIds.includes(fileEvent.id);

              return (
                <article key={fileEvent.id} className="telemetry-item">
                  <button
                    className="telemetry-summary"
                    type="button"
                    onClick={() =>
                      setExpandedEventIds((current) =>
                        current.includes(fileEvent.id)
                          ? current.filter((id) => id !== fileEvent.id)
                          : [...current, fileEvent.id]
                      )
                    }
                  >
                    <div className="telemetry-path">
                      <Icon size={18} aria-hidden="true" />
                      <span className="font-mono" title={fileEvent.filePath}>{fileEvent.filePath}</span>
                    </div>
                    <div className="telemetry-badges">
                      <span className={`pill pill-${fileEvent.eventType === "Deleted" ? "critical" : fileEvent.eventType === "Changed" ? "warning" : fileEvent.eventType === "Renamed" ? "active" : "healthy"}`}>
                        {fileEvent.eventType}
                      </span>
                      <span className={`pill pill-${fileEventTone(fileEvent.status)}`}>{fileEvent.status}</span>
                    </div>
                    <div className="telemetry-meta">
                      <span>{formatFileSize(fileEvent.fileSizeBytes)}</span>
                      {fileEvent.threatCount > 0 ? <span className="pill pill-critical">{fileEvent.threatCount} threat{fileEvent.threatCount > 1 ? "s" : ""}</span> : null}
                      <Timestamp value={fileEvent.observedAt} />
                    </div>
                  </button>

                  {expanded ? (
                    <div className="telemetry-expanded">
                      {fileEvent.engineResults?.length ? (
                        <div className="table-shell">
                          <table className="data-table compact-table">
                            <thead>
                              <tr>
                                <th>Engine Name</th>
                                <th>Source</th>
                                <th>Status</th>
                                <th>Signature Name</th>
                                <th>Details</th>
                              </tr>
                            </thead>
                            <tbody>
                              {fileEvent.engineResults.map((result) => (
                                <tr key={result.id}>
                                  <td>{result.engineName}</td>
                                  <td>{result.source}</td>
                                  <td>{result.status}</td>
                                  <td>{result.signatureName ?? "Unavailable"}</td>
                                  <td>{result.details ?? "No details recorded"}</td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      ) : (
                        <EmptyState title="No engine results" description="This file event has no engine result records yet." />
                      )}
                    </div>
                  ) : null}
                </article>
              );
            })}
          </div>
        )}
      </section>

      <section className="panel">
        <div className="section-head">
          <h2>Scan Progress Timeline</h2>
        </div>
        {!scanProgressEvents?.length ? (
          <EmptyState title="No scan progress yet" description="Start a scan to see its progress here." />
        ) : (
          <ul className="timeline-list">
            {[...scanProgressEvents].reverse().map((event, index) => (
              <li key={`${event.scanJobId}-${event.recordedAt}-${index}`} className="timeline-item">
                <div className={`timeline-dot ${event.isSkipped ? "warning" : "active"}`} aria-hidden="true" />
                <div className="timeline-content">
                  <div className="timeline-head">
                    <strong>{event.stage}</strong>
                    <Timestamp value={event.recordedAt} />
                  </div>
                  <span>{`${event.filesScanned} files at this stage${event.totalFiles ? ` of ${event.totalFiles}` : ""}`}</span>
                  {event.isSkipped ? <span className="pill pill-warning">Skipped file event</span> : null}
                  {event.detailMessage ? <p>{event.detailMessage}</p> : null}
                </div>
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}
