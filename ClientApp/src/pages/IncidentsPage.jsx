import { Fragment, useState } from "react";
import PageHeader from "../components/PageHeader";
import ScanSelector from "../components/ScanSelector";
import Timestamp from "../components/Timestamp";
import { EmptyState, ErrorState, TableSkeleton } from "../components/States";
import { formatConfidence, incidentStatusTone, severityTone } from "../ui/presentation";

export default function IncidentsPage({ incidents, scans, onResolveIncident, loading, error, onRefresh, lastUpdated }) {
  const [expandedIncidentId, setExpandedIncidentId] = useState(null);
  const openCount = incidents.filter((incident) => incident.status !== "Resolved").length;

  return (
    <div className="page-stack">
      <PageHeader
        eyebrow="Security Operations"
        title="Security Incidents"
        badge={`${openCount} Open`}
        description="Investigate, compare, and contain active incidents without leaving the analyst workflow."
        lastUpdated={lastUpdated}
        actions={<ScanSelector scans={scans} label="Scan context" id="incident-scan-selector" />}
      />

      {error ? <ErrorState message={error} onRetry={onRefresh} /> : null}

      {loading ? (
        <TableSkeleton rows={8} columns={7} />
      ) : incidents.length === 0 ? (
        <EmptyState title="No incidents" description="No open or historical incidents are available for the selected tenant." />
      ) : (
        <div className="table-shell">
          <table className="data-table incidents-table">
            <thead>
              <tr>
                <th>Severity</th>
                <th>Title</th>
                <th>Source</th>
                <th>Primary Artifact</th>
                <th>Status</th>
                <th>Confidence</th>
                <th>Detected</th>
              </tr>
            </thead>
            <tbody>
              {incidents.map((incident) => {
                const expanded = expandedIncidentId === incident.id;
                return (
                  <Fragment key={incident.id}>
                    <tr
                      className={expanded ? "selected-row" : ""}
                      onClick={() => setExpandedIncidentId(expanded ? null : incident.id)}
                    >
                      <td><span className={`pill pill-${severityTone(incident.severity)}`}>{incident.severity}</span></td>
                      <td><strong>{incident.title}</strong></td>
                      <td><span className="pill pill-muted">{incident.source}</span></td>
                      <td className="path-cell font-mono" title={incident.primaryArtifact}>{incident.primaryArtifact}</td>
                      <td><span className={`pill pill-${incidentStatusTone(incident.status)}`}>{incident.status}</span></td>
                      <td>{formatConfidence(incident.confidence)}</td>
                      <td><Timestamp value={incident.updatedAt ?? incident.createdAt} /></td>
                    </tr>
                    {expanded ? (
                      <tr className="detail-row">
                        <td colSpan="7">
                          <div className="incident-detail-grid">
                            <div>
                              <span>Rule ID</span>
                              <strong className="font-mono">{incident.ruleId}</strong>
                            </div>
                            <div>
                              <span>Device ID</span>
                              <strong className="font-mono">{incident.deviceId}</strong>
                            </div>
                            <div className="incident-detail-span">
                              <span>Summary</span>
                              <p>{incident.summary}</p>
                            </div>
                            <div className="incident-detail-span">
                              <span>Remediation notes</span>
                              <p>
                                {incident.status === "Resolved"
                                  ? "The incident has already been resolved and remains available for audit review."
                                  : incident.status === "Contained"
                                    ? "Containment has been applied. Validate endpoint state and review adjacent artifacts."
                                    : "Investigate the primary artifact, validate device state, and contain if the signal is confirmed."}
                              </p>
                            </div>
                            <div className="incident-detail-actions">
                              <button
                                className="button button-secondary button-small"
                                type="button"
                                disabled={incident.status === "Resolved"}
                                onClick={(event) => {
                                  event.stopPropagation();
                                  onResolveIncident(incident.id);
                                }}
                              >
                                {incident.status === "Resolved" ? "Resolved" : "Mark Resolved"}
                              </button>
                            </div>
                          </div>
                        </td>
                      </tr>
                    ) : null}
                  </Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
