import { Fragment, useMemo, useState } from "react";
import PageHeader from "../components/PageHeader";
import ScanSelector from "../components/ScanSelector";
import Timestamp from "../components/Timestamp";
import { EmptyState, ErrorState, TableSkeleton } from "../components/States";
import { useDashboardStore } from "../state/useDashboardStore";
import { formatConfidence, incidentStatusTone, severityTone } from "../ui/presentation";

export default function IncidentsPage({ incidents, scans, onResolveIncident, loading, error, onRefresh, lastUpdated }) {
  const [expandedIncidentId, setExpandedIncidentId] = useState(null);
  const selectedScanId = useDashboardStore((state) => state.selectedScanId);

  const filteredIncidents = useMemo(() => {
    if (!selectedScanId) return incidents;
    return incidents.filter((incident) => incident.scanJobId === selectedScanId);
  }, [incidents, selectedScanId]);

  const openCount = filteredIncidents.filter((incident) => incident.status !== "Resolved").length;

  return (
    <div className="page-stack">
      <PageHeader
        eyebrow="Security"
        title="Alerts"
        badge={`${openCount} Open`}
        lastUpdated={lastUpdated}
        actions={<ScanSelector scans={scans} label="Scan context" id="incident-scan-selector" />}
      />

      {error ? <ErrorState message={error} onRetry={onRefresh} /> : null}

      {loading ? (
        <TableSkeleton rows={8} columns={7} />
      ) : filteredIncidents.length === 0 ? (
        <EmptyState title="No alerts" description="No security alerts to show right now." />
      ) : (
        <div className="table-shell">
          <table className="data-table incidents-table">
            <thead>
              <tr>
                <th>Severity</th>
                <th>Alert</th>
                <th>Source</th>
                <th>File</th>
                <th>Status</th>
                <th>When</th>
              </tr>
            </thead>
            <tbody>
              {filteredIncidents.map((incident) => {
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
                      <td title={incident.primaryArtifact}>{incident.primaryArtifact?.split("\\").pop() ?? incident.primaryArtifact}</td>
                      <td><span className={`pill pill-${incidentStatusTone(incident.status)}`}>{incident.status}</span></td>
                      <td><Timestamp value={incident.updatedAt ?? incident.createdAt} /></td>
                    </tr>
                    {expanded ? (
                      <tr className="detail-row">
                        <td colSpan="6">
                          <div className="incident-detail-grid">
                            <div>
                              <span>Device</span>
                              <strong>{incident.deviceId?.split("-agent")[0] ?? incident.deviceId}</strong>
                            </div>
                            <div className="incident-detail-span">
                              <span>What happened</span>
                              <p>{incident.summary}</p>
                            </div>
                            <div className="incident-detail-span">
                              <span>What to do</span>
                              <p>
                                {incident.status === "Resolved"
                                  ? "This alert has been resolved. No action needed."
                                  : incident.status === "Contained"
                                    ? "The threat has been contained. Check your device to make sure everything looks normal."
                                    : "Review this alert and mark it resolved if you recognize the file, or quarantine it from the Threats page."}
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
