import ModalShell from "./ModalShell";
import { formatAbsoluteTime } from "../ui/presentation";

export default function SkippedFileModal({ skipPrompt, onDismiss, onRetry, onSkip, retryingSkippedFile }) {
  if (!skipPrompt) {
    return null;
  }

  const isWaiting = skipPrompt.stage === "WaitingForInput";

  return (
    <ModalShell titleId="skipped-file-title" onDismiss={onDismiss}>
      <span className="modal-label">{isWaiting ? "Action Required" : "Skipped File"}</span>
      <h2 id="skipped-file-title">
        {isWaiting
          ? `Scan #${skipPrompt.scanJobId} is paused — waiting for your decision`
          : `The antivirus skipped a file during scan #${skipPrompt.scanJobId}`}
      </h2>
      <p>{skipPrompt.detailMessage || "The file could not be scanned safely. Choose Retry to try again or Skip to continue the scan."}</p>

      <div className="modal-detail-grid">
        <div>
          <span>File path</span>
          <strong className="font-mono">{skipPrompt.currentPath ?? "Unknown path"}</strong>
        </div>
        <div>
          <span>Stage</span>
          <strong>{skipPrompt.stage}</strong>
        </div>
        <div>
          <span>Recorded timestamp</span>
          <strong className="font-mono">{formatAbsoluteTime(skipPrompt.recordedAt)}</strong>
        </div>
      </div>

      <div className="modal-actions">
        <button className="button button-secondary" type="button" onClick={onSkip || onDismiss}>
          Skip
        </button>
        <button className="button button-primary" type="button" onClick={onRetry} disabled={retryingSkippedFile}>
          {retryingSkippedFile ? "Retrying..." : "Retry"}
        </button>
      </div>
    </ModalShell>
  );
}
