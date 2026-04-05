import { useDeferredValue } from "react";
import { formatDate, severityTone } from "../ui/presentation";
import ScanSelector from "../components/ScanSelector";

export default function DetectionsPage({ threats, query, setQuery, handleQuarantine, handleReview, scans, selectedScanId, setSelectedScanId }) {
  const deferredQuery = useDeferredValue(query);
  const needle = deferredQuery.trim().toLowerCase();
  const filteredThreats = !needle
    ? threats
    : threats.filter((threat) =>
        [threat.name, threat.resource, threat.category, threat.source]
          .filter(Boolean)
          .some((value) => value.toLowerCase().includes(needle))
      );
  const finalThreats = selectedScanId
    ? filteredThreats.filter((threat) => threat.scanJobId === selectedScanId)
    : filteredThreats;

  return (
    <section className="panel page-panel">
      <div className="panel-heading">
        <h2>Active detections</h2>
        <p>Signals and response actions now have their own page instead of competing with telemetry and fleet data.</p>
      </div>

      <div className="toolbar">
        <ScanSelector scans={scans} selectedScanId={selectedScanId} onChange={setSelectedScanId} />
        <input
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          placeholder="Search by threat, path, category, or source"
        />
      </div>

      <div className="table-shell">
        <table>
          <thead>
            <tr>
              <th>Scan ID</th>
              <th>Signal</th>
              <th>Severity</th>
              <th>Source</th>
              <th>Resource</th>
              <th>Detected</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            {finalThreats.map((threat) => (
              <tr key={`${threat.id}-${threat.detectedAt}`}>
                <td>{threat.scanJobId ?? "Realtime"}</td>
                <td>
                  <div className="stacked">
                    <strong>{threat.name}</strong>
                    <span>{threat.category}</span>
                  </div>
                </td>
                <td>
                  <span className={`pill ${severityTone(threat.severity)}`}>{threat.severity}</span>
                </td>
                <td>{threat.source}</td>
                <td className="resource-cell">{threat.resource ?? "Unavailable"}</td>
                <td>{formatDate(threat.detectedAt)}</td>
                <td className="action-row">
                  <button
                    className="ghost-button compact"
                    type="button"
                    disabled={threat.isQuarantined}
                    onClick={() => handleQuarantine(threat.id)}
                  >
                    {threat.isQuarantined ? "Quarantined" : "Quarantine"}
                  </button>
                  <button className="ghost-button compact" type="button" onClick={() => handleReview(threat)}>
                    Review
                  </button>
                </td>
              </tr>
            ))}
            {finalThreats.length === 0 ? (
              <tr>
                <td colSpan="7" className="empty-state">
                  No detections matched the current filter.
                </td>
              </tr>
            ) : null}
          </tbody>
        </table>
      </div>
    </section>
  );
}
