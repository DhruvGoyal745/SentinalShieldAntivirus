import AnalysisRail from "../components/AnalysisRail";
import { scanModeOptions } from "../ui/constants";
import { describeHealthStatus, formatPercent } from "../ui/presentation";

export default function HomePage({
  scanRequest,
  setScanRequest,
  submitting,
  handleScanSubmit,
  handleStopScan,
  stoppingScanId,
  activeScan,
  analysisProgress,
  analysisSteps,
  incidentsCount,
  threatCount,
  quarantinedThreatCount,
  fleet,
  health,
  onNavigate
}) {
  const heroStats = [
    {
      label: "Realtime engine",
      value: health?.realTimeProtectionEnabled && health?.antivirusEnabled ? "Protected" : "Needs attention",
      detail: describeHealthStatus(health)
    },
    {
      label: "Active incidents",
      value: incidentsCount,
      detail: incidentsCount > 0 ? "Prioritize response workflows" : "No open incidents"
    },
    {
      label: "Agent coverage",
      value: formatPercent(fleet?.agentCoveragePercent),
      detail: `${fleet?.activeDeviceCount ?? 0} of ${fleet?.deviceCount ?? 0} endpoints active`
    },
    {
      label: "Quarantined threats",
      value: quarantinedThreatCount,
      detail: `${threatCount} detections tracked in this tenant`
    }
  ];

  return (
    <div className="page-stack">
      <section className="panel panel-form panel-home">
        <div className="panel-heading panel-heading-inline">
          <div>
            <p className="eyebrow">Sentinel Shield Enterprise</p>
            <h2>Choose a scan</h2>
            <p>The home view now starts directly with the scan workflow so the experience feels focused and clean.</p>
          </div>
          <div className="action-row">
            <button className="ghost-button compact" type="button" onClick={() => onNavigate("telemetry")}>
              Review telemetry
            </button>
            <button className="ghost-button compact" type="button" onClick={() => onNavigate("detections")}>
              Review detections
            </button>
            <button className="ghost-button compact" type="button" onClick={() => onNavigate("fleet")}>
              Open fleet
            </button>
          </div>
        </div>

        <section className="hero-stat-grid home-stat-grid">
          {heroStats.map((item) => (
            <article key={item.label} className="metric-card">
              <span>{item.label}</span>
              <strong>{item.value}</strong>
              <small>{item.detail}</small>
            </article>
          ))}
        </section>

        <AnalysisRail
          activeScan={activeScan}
          analysisProgress={analysisProgress}
          analysisSteps={analysisSteps}
          onStopScan={handleStopScan}
          stoppingScanId={stoppingScanId}
        />

        <form className="scan-form" onSubmit={handleScanSubmit}>
          <div className="scan-mode-grid">
            {scanModeOptions.map((option) => (
              <button
                key={option.value}
                type="button"
                className={`scan-mode-card ${scanRequest.mode === option.value ? "active" : ""}`}
                onClick={() => setScanRequest((current) => ({ ...current, mode: option.value }))}
              >
                <span className="scan-mode-eyebrow">{option.eyebrow}</span>
                <strong>{option.label}</strong>
                <p>{option.description}</p>
                <small>{option.eta}</small>
              </button>
            ))}
          </div>

          <div className="scan-input-grid">
            <label>
              Requested by
              <input
                value={scanRequest.requestedBy}
                onChange={(event) =>
                  setScanRequest((current) => ({ ...current, requestedBy: event.target.value }))
                }
                placeholder="enterprise-operator"
              />
            </label>

            <label>
              Custom path
              <input
                value={scanRequest.targetPath}
                onChange={(event) =>
                  setScanRequest((current) => ({ ...current, targetPath: event.target.value }))
                }
                placeholder="C:\\Users\\name\\Downloads"
                disabled={scanRequest.mode !== "Custom"}
              />
            </label>
          </div>

          <label className="toggle-row">
            <input
              type="checkbox"
              checked={scanRequest.runHeuristics}
              onChange={(event) =>
                setScanRequest((current) => ({
                  ...current,
                  runHeuristics: event.target.checked
                }))
              }
            />
            <span>Run compatibility heuristics during the proprietary scan</span>
          </label>

          <div className="scan-submit-row">
            <div className="scan-submit-copy">
              <strong>Focused home experience</strong>
              <span>Launch the scan here, then use the ribbon for incidents, telemetry, governance, and reporting.</span>
            </div>
            <button className="primary-button" type="submit" disabled={submitting}>
              {submitting ? "Submitting..." : "Start enterprise scan"}
            </button>
          </div>
        </form>
      </section>
    </div>
  );
}
