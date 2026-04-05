import { formatDate, formatPercent, reviewStatusTone, sandboxVerdictTone } from "../ui/presentation";
import ScanSelector from "../components/ScanSelector";

export default function GovernancePage({ paritySnapshots, sandboxSubmissions, reviews, scans, selectedScanId, setSelectedScanId }) {
  const filteredParitySnapshots = selectedScanId
    ? paritySnapshots.filter((snapshot) => snapshot.scanId === selectedScanId)
    : paritySnapshots;

  const filteredSandboxSubmissions = selectedScanId
    ? sandboxSubmissions.filter((submission) => submission.scanJobId === selectedScanId)
    : sandboxSubmissions;

  const filteredReviews = selectedScanId
    ? reviews.filter((review) => review.scanId === selectedScanId)
    : reviews;

  return (
    <section className="panel page-panel">
      <div className="panel-heading">
        <h2>Governance and shadow mode</h2>
        <p>Legacy parity, sandbox submissions, and false-positive workflows now sit together on their own operational page.</p>
      </div>

      <div className="toolbar">
        <ScanSelector scans={scans} selectedScanId={selectedScanId} onChange={setSelectedScanId} />
      </div>

      <div className="three-column-grid">
        <div className="subpanel">
          <h3>Legacy parity</h3>
          <div className="history-list">
            {filteredParitySnapshots.map((snapshot) => (
              <article key={`${snapshot.id}-${snapshot.createdAt}`} className="history-card compact-card">
                <div className="history-meta">
                  <span>Device: {snapshot.deviceId}</span>
                  <span>Family: {snapshot.malwareFamily}</span>
                  <span>Recall: {formatPercent(snapshot.detectionRecallPercent)}</span>
                  <span>FP: {formatPercent(snapshot.falsePositiveRatePercent)}</span>
                </div>
              </article>
            ))}
            {filteredParitySnapshots.length === 0 ? <p className="empty-state">No parity snapshots recorded yet.</p> : null}
          </div>
        </div>

        <div className="subpanel">
          <h3>Sandbox queue</h3>
          <div className="history-list">
            {filteredSandboxSubmissions.map((submission) => (
              <article key={`${submission.id}-${submission.correlationId}`} className="history-card compact-card">
                <div className="history-header">
                  <div>
                    <h3>{submission.fileName}</h3>
                    <span className="history-mode">{submission.status}</span>
                  </div>
                  <span className={`pill ${sandboxVerdictTone(submission.verdict)}`}>{submission.verdict}</span>
                </div>
                <div className="history-meta">
                  <span>Family: {submission.familyName || "Unknown"}</span>
                  <span>Device: {submission.deviceId}</span>
                  <span>Updated: {formatDate(submission.updatedAt ?? submission.createdAt)}</span>
                </div>
                <p>{submission.behaviorSummary}</p>
              </article>
            ))}
            {filteredSandboxSubmissions.length === 0 ? <p className="empty-state">No sandbox submissions are queued.</p> : null}
          </div>
        </div>

        <div className="subpanel">
          <h3>False-positive reviews</h3>
          <div className="history-list">
            {filteredReviews.map((review) => (
              <article key={`${review.id}-${review.submittedAt}`} className="history-card compact-card">
                <div className="history-header">
                  <h3>{review.ruleId}</h3>
                  <span className={`pill ${reviewStatusTone(review.status)}`}>{review.status}</span>
                </div>
                <div className="history-meta">
                  <span>Analyst: {review.analyst}</span>
                  <span>Scope: {review.scope}</span>
                  <span>Submitted: {formatDate(review.submittedAt)}</span>
                </div>
                <p>{review.notes}</p>
              </article>
            ))}
            {filteredReviews.length === 0 ? <p className="empty-state">No false-positive reviews have been submitted yet.</p> : null}
          </div>
        </div>
      </div>
    </section>
  );
}
