import { formatDate, formatPercent, severityTone } from "../ui/presentation";
import ScanSelector from "../components/ScanSelector";

export default function IncidentsPage({ incidents, handleResolveIncident, scans, selectedScanId, setSelectedScanId }) {
  const filteredIncidents = incidents;

  return (
    <section className="panel page-panel">
      <div className="panel-heading">
        <h2>Active incidents</h2>
        <p>Every open incident now lives on its own page so operators can focus on response work without extra noise.</p>
      </div>

      <div className="toolbar">
        <ScanSelector scans={scans} selectedScanId={selectedScanId} onChange={setSelectedScanId} />
      </div>

      <div className="history-list">
        {filteredIncidents.map((incident) => (
          <article key={incident.id} className="history-card compact-card">
            <div className="history-header">
              <div>
                <span className="history-mode">Incident #{incident.id}</span>
                <h3>{incident.title}</h3>
              </div>
              <span className={`pill ${severityTone(incident.severity)}`}>{incident.status}</span>
            </div>
            <div className="history-meta">
              <span>Device: {incident.deviceId}</span>
              <span>Severity: {incident.severity}</span>
              <span>Rule: {incident.ruleId}</span>
              <span>Confidence: {formatPercent(incident.confidence * 100)}</span>
              <span>Updated: {formatDate(incident.updatedAt)}</span>
            </div>
            <p>{incident.summary}</p>
            <div className="action-row">
              <button
                className="ghost-button compact"
                type="button"
                disabled={incident.status === "Resolved"}
                onClick={() => handleResolveIncident(incident.id)}
              >
                {incident.status === "Resolved" ? "Resolved" : "Resolve"}
              </button>
            </div>
          </article>
        ))}
        {filteredIncidents.length === 0 ? <p className="empty-state">No incidents are currently open for this tenant.</p> : null}
      </div>
    </section>
  );
}
