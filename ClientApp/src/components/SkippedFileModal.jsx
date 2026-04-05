import { formatDate } from "../ui/presentation";

export default function SkippedFileModal({ skipPrompt, onDismiss, onRetry, retryingSkippedFile }) {
  if (!skipPrompt) {
    return null;
  }

  return (
    <div className="modal-backdrop" role="presentation">
      <div className="modal-card" role="dialog" aria-modal="true" aria-labelledby="skipped-file-title">
        <span className="history-mode">Skipped file</span>
        <h3 id="skipped-file-title">The antivirus skipped a file during scan #{skipPrompt.scanJobId}.</h3>
        <p>{skipPrompt.detailMessage || "This file could not be accessed safely, so the scan continued without failing."}</p>

        <div className="modal-detail-list">
          <div>
            <span>File</span>
            <strong>{skipPrompt.currentPath ?? "Unknown path"}</strong>
          </div>
          <div>
            <span>Stage</span>
            <strong>{skipPrompt.stage}</strong>
          </div>
          <div>
            <span>Recorded</span>
            <strong>{formatDate(skipPrompt.recordedAt)}</strong>
          </div>
        </div>

        <div className="action-row modal-actions">
          <button className="ghost-button compact" type="button" onClick={onDismiss}>
            Skip
          </button>
          <button className="primary-button compact" type="button" onClick={onRetry} disabled={retryingSkippedFile}>
            {retryingSkippedFile ? "Retrying..." : "Retry"}
          </button>
        </div>
      </div>
    </div>
  );
}
