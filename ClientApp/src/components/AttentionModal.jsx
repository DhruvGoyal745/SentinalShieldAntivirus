import ModalShell from "./ModalShell";
import { formatAbsoluteTime, severityTone } from "../ui/presentation";

function deriveTone(vulnerabilities) {
  if (!Array.isArray(vulnerabilities) || vulnerabilities.length === 0) {
    return "healthy";
  }

  if (vulnerabilities.some((threat) => threat.severity === "High" || threat.severity === "Critical")) {
    return "critical";
  }

  return "warning";
}

export default function AttentionModal({ scan, vulnerabilities, onDismiss, onReview }) {
  if (!scan || !Array.isArray(vulnerabilities)) {
    return null;
  }

  const tone = deriveTone(vulnerabilities);
  const heading = tone === "healthy"
    ? "Run completed successfully and the system looks healthy"
    : tone === "warning"
      ? "Run completed with vulnerabilities identified"
      : "Your system needs attention";

  return (
    <ModalShell titleId="attention-summary-title" onDismiss={onDismiss} tone={tone}>
      <span className="modal-label">Post-Scan Attention Summary</span>
      <h2 id="attention-summary-title">{heading}</h2>
      <p>
        {vulnerabilities.length === 0
          ? "No findings were surfaced during this run."
          : `${vulnerabilities.length} findings were surfaced during this run and are ready for analyst review.`}
      </p>

      <div className="modal-detail-grid">
        <div>
          <span>Scan metadata</span>
          <strong className="font-mono">
            {`SCAN-${String(scan.id).padStart(5, "0")} • ${scan.mode} • ${formatAbsoluteTime(scan.completedAt ?? scan.createdAt)}`}
          </strong>
        </div>
        <div>
          <span>Vulnerability count</span>
          <strong>{vulnerabilities.length}</strong>
        </div>
      </div>

      {vulnerabilities.length > 0 ? (
        <div className="attention-findings">
          {vulnerabilities.map((threat) => (
            <article key={`${scan.id}-${threat.id}`} className="attention-finding">
              <div className="attention-finding-head">
                <strong>{threat.name}</strong>
                <span className={`pill pill-${severityTone(threat.severity)}`}>{threat.severity}</span>
              </div>
              <p>{threat.description || threat.category}</p>
              <code className="font-mono">{threat.resource ?? "Resource unavailable"}</code>
            </article>
          ))}
        </div>
      ) : null}

      <div className="modal-actions">
        <button className="button button-secondary" type="button" onClick={onDismiss}>
          Close
        </button>
        {vulnerabilities.length > 0 ? (
          <button className="button button-primary" type="button" onClick={onReview}>
            Review Detections
          </button>
        ) : null}
      </div>
    </ModalShell>
  );
}
