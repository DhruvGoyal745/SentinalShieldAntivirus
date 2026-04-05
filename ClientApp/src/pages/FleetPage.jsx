import { describeHealthStatus, formatDate, formatPercent } from "../ui/presentation";
import ScanSelector from "../components/ScanSelector";

export default function FleetPage({ controlPlane, health, scans, selectedScanId, setSelectedScanId }) {
  const fleet = controlPlane?.fleet;
  const devices = controlPlane?.devices ?? [];
  const packs = controlPlane?.signaturePacks ?? [];

  const filteredDevices = devices;

  return (
    <div className="page-stack">
      <section className="panel page-panel">
        <div className="panel-heading">
          <h2>Fleet posture</h2>
          <p>Tenant posture, rollout state, and endpoint health are grouped here instead of spreading across the whole product.</p>
        </div>

        <div className="toolbar">
          <ScanSelector scans={scans} selectedScanId={selectedScanId} onChange={setSelectedScanId} />
        </div>

        <section className="metrics-grid metrics-grid-enterprise">
          <article className="metric-card">
            <span>Fleet devices</span>
            <strong>{fleet?.deviceCount ?? 0}</strong>
            <small>{fleet?.activeDeviceCount ?? 0} active endpoints reporting heartbeat telemetry</small>
          </article>
          <article className="metric-card">
            <span>Agent coverage</span>
            <strong>{formatPercent(fleet?.agentCoveragePercent)}</strong>
            <small>Enrollment and reporting coverage across this tenant</small>
          </article>
          <article className="metric-card">
            <span>Policy compliance</span>
            <strong>{formatPercent(fleet?.policyCompliancePercent)}</strong>
            <small>Policies aligned with the current tenant baseline</small>
          </article>
          <article className="metric-card">
            <span>Self-protection</span>
            <strong>{formatPercent(fleet?.selfProtectionCoveragePercent)}</strong>
            <small>Process, service, file, and signed-update controls healthy</small>
          </article>
          <article className="metric-card">
            <span>Current pack</span>
            <strong>{fleet?.currentPackVersion ?? "Unavailable"}</strong>
            <small>Legacy shadow mode {fleet?.legacyShadowModeEnabled ? "enabled" : "disabled"}</small>
          </article>
          <article className="metric-card">
            <span>Realtime engine</span>
            <strong>{health?.realTimeProtectionEnabled ? "On" : "Off"}</strong>
            <small>{describeHealthStatus(health)}</small>
          </article>
        </section>
      </section>

      <section className="panel page-panel">
        <div className="panel-heading">
          <h2>Registered endpoints</h2>
          <p>Device inventory, rollout rings, and self-protection posture.</p>
        </div>

        <div className="history-list">
          {filteredDevices.map((device) => (
            <article key={device.deviceId} className="history-card compact-card">
              <div className="history-header">
                <div>
                  <span className="history-mode">{device.operatingSystem}</span>
                  <h3>{device.deviceName}</h3>
                </div>
                <span className={`pill ${device.selfProtection.watchdogHealthy ? "low" : "high"}`}>
                  {device.enrollmentStatus}
                </span>
              </div>
              <div className="history-meta">
                <span>Agent: {device.agentVersion}</span>
                <span>Engine: {device.engineVersion}</span>
                <span>Pack: {device.signaturePackVersion}</span>
                <span>Policy: {device.policyVersion}</span>
                <span>Ring: {device.rolloutRing}</span>
                <span>Last seen: {formatDate(device.lastSeenAt)}</span>
              </div>
              <p>
                Baseline scan {device.baselineScanCompleted ? "completed" : "pending"}.
                Self-protection: {device.selfProtection.processProtectionEnabled ? " process" : ""}
                {device.selfProtection.fileProtectionEnabled ? " file" : ""}
                {device.selfProtection.serviceProtectionEnabled ? " service" : ""}.
              </p>
            </article>
          ))}
          {filteredDevices.length === 0 ? <p className="empty-state">No devices have registered for this tenant yet.</p> : null}
        </div>
      </section>

      <section className="panel page-panel">
        <div className="panel-heading">
          <h2>Pack rollout</h2>
          <p>Release rings, staged pack delivery, and current signature distribution state.</p>
        </div>

        <div className="history-list">
          {packs.map((pack) => (
            <article key={`${pack.id}-${pack.version}`} className="history-card compact-card">
              <div className="history-header">
                <div>
                  <span className="history-mode">{pack.channel}</span>
                  <h3>{pack.version}</h3>
                </div>
                <span className={`pill ${pack.status === "Released" ? "low" : "medium"}`}>{pack.status}</span>
              </div>
              <div className="history-meta">
                <span>Ring: {pack.rolloutRing}</span>
                <span>Signatures: {pack.signatureCount}</span>
                <span>Min agent: {pack.minAgentVersion}</span>
                <span>Released: {formatDate(pack.releasedAt)}</span>
              </div>
            </article>
          ))}
          {packs.length === 0 ? <p className="empty-state">No signature pack records are available yet.</p> : null}
        </div>
      </section>
    </div>
  );
}
