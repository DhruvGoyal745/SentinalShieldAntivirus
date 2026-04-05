import { formatDate, severityTone } from "../ui/presentation";

function deriveTone(vulnerabilities) {
  if (!Array.isArray(vulnerabilities) || vulnerabilities.length === 0) {
    return "safe";
  }

  if (vulnerabilities.some((threat) => threat.severity === "High" || threat.severity === "Critical")) {
    return "unsafe";
  }

  return "warning";
}

export default function AttentionModal({ scan, vulnerabilities, onDismiss, onReview }) {
  if (!scan || !Array.isArray(vulnerabilities)) {
    return null;
  }

  const tone = deriveTone(vulnerabilities);
  const isUnsafe = tone === "unsafe";
  const title = isUnsafe
    ? "Run completed successfully, but your system needs attention."
    : vulnerabilities.length > 0
      ? "Run completed successfully with vulnerabilities identified."
      : "Run completed successfully and the system looks healthy.";
  const detail = isUnsafe
    ? "High-priority findings were surfaced in this run and should be reviewed immediately."
    : vulnerabilities.length > 0
      ? "The run finished successfully and identified lower-priority vulnerabilities that still deserve review."
      : "No vulnerabilities were identified in this run.";

  return (
    <div className="modal-backdrop" role="presentation" onClick={onDismiss}>
      <div
        className={`modal-card attention-modal ${tone}`}
        role="dialog"
        aria-modal="true"
        aria-labelledby="attention-modal-title"
        onClick={(event) => event.stopPropagation()}
      >
        <span className="history-mode">{isUnsafe ? "System needs attention" : "Run successful"}</span>
        <h3 id="attention-modal-title">{title}</h3>
        <p>{detail}</p>

        <div className="modal-detail-list">
          <div>
            <span>Scan</span>
            <strong>
              #{scan.id} | {scan.mode} | {formatDate(scan.completedAt ?? scan.createdAt)}
            </strong>
          </div>
          <div>
            <span>Vulnerabilities identified</span>
            <strong>
              {vulnerabilities.length === 0
                ? "No vulnerabilities identified"
                : `${vulnerabilities.length} findings surfaced`}
            </strong>
          </div>
        </div>

        {vulnerabilities.length > 0 ? (
          <div className="attention-list">
            {vulnerabilities.map((threat) => (
              <article key={`${scan.id}-${threat.id}-${threat.detectedAt}`} className="attention-item">
                <div className="attention-item-header">
                  <strong>{threat.name}</strong>
                  <span className={`pill ${severityTone(threat.severity)}`}>{threat.severity}</span>
                </div>
                <p>{threat.description || threat.category}</p>
                <small>{threat.resource ?? "Resource unavailable"}</small>
              </article>
            ))}
          </div>
        ) : null}

        <div className="action-row modal-actions">
          <button className="ghost-button compact" type="button" onClick={onDismiss}>
            Close
          </button>
          {vulnerabilities.length > 0 ? (
            <button className="primary-button compact" type="button" onClick={onReview}>
              Review detections
            </button>
          ) : null}
        </div>
      </div>
    </div>
  );
}
