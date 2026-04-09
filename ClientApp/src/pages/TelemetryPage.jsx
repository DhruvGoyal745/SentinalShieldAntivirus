import { useDeferredValue, useMemo, useState } from "react";
import { File, FileCog, FilePenLine, FilePlus2, FileX2 } from "lucide-react";
import PageHeader from "../components/PageHeader";
import ScanSelector from "../components/ScanSelector";
import Timestamp from "../components/Timestamp";
import { EmptyState, ErrorState, TableSkeleton } from "../components/States";
import { fileEventTone, formatFileSize } from "../ui/presentation";

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
  loading,
  error,
  onRefresh,
  lastUpdated
}) {
  const [query, setQuery] = useState("");
  const [expandedEventIds, setExpandedEventIds] = useState([]);
  const deferredQuery = useDeferredValue(query);

  const filteredFileEvents = useMemo(() => {
    const needle = deferredQuery.trim().toLowerCase();
    return !needle
      ? fileEvents
      : fileEvents.filter((event) =>
          [event.filePath, event.notes, event.eventType, event.status, event.hashSha256]
            .filter(Boolean)
            .some((value) => value.toLowerCase().includes(needle))
        );
  }, [deferredQuery, fileEvents]);

  return (
    <div className="page-stack">
      <PageHeader
        eyebrow="Real-Time Operations"
        title="Real-Time Telemetry"
        description="A live file-event stream and a scan-stage timeline for fast operational review."
        lastUpdated={lastUpdated}
        actions={
          <div className="header-inline-actions">
            <ScanSelector scans={scans} label="Scan context" id="telemetry-scan-selector" />
            <label className="field field-search">
              <span>Search telemetry</span>
              <input
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder="Search file path, status, note, or hash"
              />
            </label>
          </div>
        }
      />

      {error ? <ErrorState message={error} onRetry={onRefresh} /> : null}

      <section className="panel">
        <div className="section-head">
          <h2>File Security Events</h2>
        </div>
        {loading ? (
          <TableSkeleton rows={6} columns={5} />
        ) : filteredFileEvents.length === 0 ? (
          <EmptyState title="No telemetry events" description="The realtime file event stream is currently empty for this tenant." />
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
                      <code className="font-mono" title={fileEvent.hashSha256 ?? "Hash unavailable"}>
                        {fileEvent.hashSha256 ? `${fileEvent.hashSha256.slice(0, 12)}...` : "Pending"}
                      </code>
                      <span>{formatFileSize(fileEvent.fileSizeBytes)}</span>
                      {fileEvent.threatCount > 0 ? <span className="pill pill-critical">{fileEvent.threatCount}</span> : null}
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
          <EmptyState title="No timeline events" description="Select or start a scan to populate stage transitions and skipped-file activity." />
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
