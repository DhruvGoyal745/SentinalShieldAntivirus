import {
  deriveAnalysisDetail,
  deriveAnalysisHeadline,
  describeFilesScanned,
  describeScanTarget,
  formatRuntime,
  scanStatusTone
} from "../ui/presentation";

export default function AnalysisRail({ activeScan, analysisProgress, analysisSteps, onStopScan, stoppingScanId }) {
  const canStop = activeScan && (activeScan.status === "Pending" || activeScan.status === "Running");

  return (
    <div className={`analysis-rail ${activeScan ? "live" : "idle"} ${activeScan?.status === "Failed" ? "failed" : ""}`}>
      <div className="analysis-rail-header">
        <div>
          <span className="history-mode">{activeScan ? `Live analysis | Scan #${activeScan.id}` : "Realtime analysis bar"}</span>
          <h3>{deriveAnalysisHeadline(activeScan)}</h3>
          <p>{deriveAnalysisDetail(activeScan, analysisProgress)}</p>
        </div>
        <div className="analysis-status">
          <span className={`pill ${scanStatusTone(activeScan?.status)}`}>{activeScan?.status ?? "Idle"}</span>
          <strong>{activeScan ? `${analysisProgress}%` : "0%"}</strong>
          {canStop ? (
            <button
              className="ghost-button compact"
              type="button"
              onClick={() => onStopScan(activeScan.id)}
              disabled={stoppingScanId === activeScan.id}
            >
              {stoppingScanId === activeScan.id ? "Stopping..." : "Stop scan"}
            </button>
          ) : null}
        </div>
      </div>

      <div className="analysis-track" aria-label="Realtime scan progress">
        <div
          className={`analysis-fill ${activeScan?.status === "Completed" ? "complete" : ""} ${activeScan?.status === "Failed" ? "failed" : ""}`}
          style={{ width: `${activeScan ? analysisProgress : 0}%` }}
        />
      </div>

      <div className="analysis-stats">
        <div>
          <span>Stage</span>
          <strong>{activeScan?.stage ?? "Awaiting run"}</strong>
        </div>
        <div>
          <span>Runtime</span>
          <strong>{formatRuntime(activeScan)}</strong>
        </div>
        <div>
          <span>Files scanned</span>
          <strong>{describeFilesScanned(activeScan)}</strong>
        </div>
        <div>
          <span>Threats surfaced</span>
          <strong>{activeScan?.threatCount ?? 0}</strong>
        </div>
        <div className="analysis-stat-wide">
          <span>Current target</span>
          <strong>{describeScanTarget(activeScan)}</strong>
        </div>
      </div>

      <div className="analysis-steps">
        {analysisSteps.map((step) => (
          <div key={step.key} className={`analysis-step ${step.state}`}>
            <span className="analysis-step-dot" />
            <span>{step.label}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
