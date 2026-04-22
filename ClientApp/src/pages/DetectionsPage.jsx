import { useDeferredValue, useMemo, useState } from "react";
import PageHeader from "../components/PageHeader";
import ScanSelector from "../components/ScanSelector";
import { CardGridSkeleton, EmptyState, ErrorState } from "../components/States";
import { useDashboardStore } from "../state/useDashboardStore";
import { parseEvidenceSha, severityTone, isRansomwareDetection } from "../ui/presentation";

export default function DetectionsPage({
  threats,
  scans,
  onQuarantine,
  onReview,
  pendingThreatActionId,
  loading,
  error,
  onRefresh,
  lastUpdated
}) {
  const [query, setQuery] = useState("");
  const [expandedEvidenceIds, setExpandedEvidenceIds] = useState([]);
  const selectedScanId = useDashboardStore((state) => state.selectedScanId);
  const deferredQuery = useDeferredValue(query);

  const filteredThreats = useMemo(() => {
    const needle = deferredQuery.trim().toLowerCase();
    const byQuery = !needle
      ? threats
      : threats.filter((threat) =>
          [threat.name, threat.resource, threat.category, threat.source, threat.engineName, threat.description]
            .filter(Boolean)
            .some((value) => value.toLowerCase().includes(needle))
        );

    return selectedScanId
      ? byQuery.filter((threat) => threat.scanJobId === selectedScanId)
      : byQuery;
  }, [deferredQuery, selectedScanId, threats]);

  return (
    <div className="page-stack">
      <PageHeader
        eyebrow="Protection"
        title="Threats Found"
        badge={`${filteredThreats.length} Active`}
        lastUpdated={lastUpdated}
        actions={
          <div className="header-inline-actions">
            <ScanSelector scans={scans} label="Scan context" id="detection-scan-selector" />
            <label className="field field-search">
              <span>Search detections</span>
              <input
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder="Search by threat name or file"
              />
            </label>
          </div>
        }
      />

      {error ? <ErrorState message={error} onRetry={onRefresh} /> : null}

      {loading ? (
        <CardGridSkeleton cards={6} />
      ) : filteredThreats.length === 0 ? (
        <EmptyState title="No threats found" description="No threats to show. Your system looks clean!" />
      ) : (
        <div className="card-grid">
          {filteredThreats.map((threat) => {
            const evidenceExpanded = expandedEvidenceIds.includes(threat.id);
            const evidenceSha = parseEvidenceSha(threat.evidenceJson);
            const pending = pendingThreatActionId === threat.id;

            return (
              <article key={threat.id} className={`panel-card detection-card${isRansomwareDetection(threat) ? " ransomware-banner" : ""}`}>
                <div className="card-top-row">
                  <div>
                    <strong className="card-title">{threat.name}</strong>
                    <span className="card-subtitle">{threat.category}</span>
                  </div>
                  <span className={`pill pill-${severityTone(threat.severity)}`}>{threat.severity}</span>
                </div>

                {isRansomwareDetection(threat) ? (
                  <div className="ransomware-alert">
                    <strong>Ransomware Activity Detected</strong>
                    {threat.description ? <p>{threat.description}</p> : null}
                  </div>
                ) : null}

                <p className="resource-inline" title={threat.resource ?? ""}>
                  {threat.resource ? threat.resource.split("\\").pop() : ""}
                </p>
                {threat.description ? <p className="card-description">{threat.description}</p> : null}

                <div className="quarantine-state">
                  <span className={threat.isQuarantined ? "text-healthy" : "text-critical"}>
                    {threat.isQuarantined ? "Quarantined" : "Not Quarantined"}
                  </span>
                </div>

                <div className="card-actions">
                  <button
                    className="button button-danger"
                    type="button"
                    onClick={() => onQuarantine(threat.id)}
                    disabled={threat.isQuarantined || pending}
                  >
                    {pending && !threat.isQuarantined ? "Quarantining..." : threat.isQuarantined ? "Quarantined" : "Quarantine"}
                  </button>
                  <button
                    className="button button-secondary"
                    type="button"
                    onClick={() => onReview(threat)}
                    disabled={pending}
                  >
                    {pending ? "Submitting..." : "Mark as False Positive"}
                  </button>
                </div>
              </article>
            );
          })}
        </div>
      )}
    </div>
  );
}
