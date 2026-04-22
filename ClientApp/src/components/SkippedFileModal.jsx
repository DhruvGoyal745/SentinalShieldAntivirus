import ModalShell from "./ModalShell";

export default function SkippedFileModal({ skipPrompt, onDismiss, onRetry, onSkip, retryingSkippedFile }) {
  if (!skipPrompt) {
    return null;
  }

  const isWaiting = skipPrompt.stage === "WaitingForInput";
  const fileName = skipPrompt.currentPath?.split("\\").pop() ?? skipPrompt.currentPath;

  return (
    <ModalShell titleId="skipped-file-title" onDismiss={onDismiss}>
      <span className="modal-label">{isWaiting ? "Action Required" : "File Skipped"}</span>
      <h2 id="skipped-file-title">
        {isWaiting
          ? "The scan needs your help with a file"
          : "A file was skipped during the scan"}
      </h2>
      <p>{skipPrompt.detailMessage || "This file couldn't be scanned. You can retry or skip it to continue."}</p>

      <div className="modal-detail-grid">
        <div>
          <span>File</span>
          <strong title={skipPrompt.currentPath ?? ""}>{fileName ?? "Unknown file"}</strong>
        </div>
      </div>

      <div className="modal-actions">
        <button className="button button-secondary" type="button" onClick={onSkip || onDismiss}>
          Skip this file
        </button>
        <button className="button button-primary" type="button" onClick={onRetry} disabled={retryingSkippedFile}>
          {retryingSkippedFile ? "Retrying..." : "Try again"}
        </button>
      </div>
    </ModalShell>
  );
}
