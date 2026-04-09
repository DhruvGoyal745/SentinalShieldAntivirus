import PageHeader from "../components/PageHeader";
import Timestamp from "../components/Timestamp";
import { EmptyState, ErrorState, TableSkeleton } from "../components/States";
import { complianceTone, formatPercent } from "../ui/presentation";

export default function FleetPage({ controlPlane, health, loading, error, onRefresh, lastUpdated }) {
  const fleet = controlPlane?.fleet;
  const devices = controlPlane?.devices ?? [];
  const packs = controlPlane?.signaturePacks ?? [];
  const currentPack = packs[0] ?? null;

  return (
    <div className="page-stack">
      <PageHeader
        eyebrow="Device Posture"
        title="Fleet Posture"
        badge={`${devices.length} Devices`}
        description="Monitor endpoint coverage, compliance, and signature deployment posture across the tenant."
        lastUpdated={lastUpdated}
      />

      {error ? <ErrorState message={error} onRetry={onRefresh} /> : null}

      <section className="stats-grid fleet-stats-grid">
        <article className="metric-card">
          <span>Total Devices</span>
          <strong>{fleet?.deviceCount ?? 0}</strong>
        </article>
        <article className="metric-card">
          <span>Agent Coverage</span>
          <strong>{formatPercent(fleet?.agentCoveragePercent)}</strong>
          <div className="mini-progress">
            <div style={{ width: `${fleet?.agentCoveragePercent ?? 0}%` }} />
          </div>
        </article>
        <article className="metric-card">
          <span>Policy Compliance</span>
          <strong className={`text-${complianceTone(fleet?.policyCompliancePercent)}`}>{formatPercent(fleet?.policyCompliancePercent)}</strong>
        </article>
        <article className="metric-card">
          <span>Self-Protection</span>
          <strong>{health?.engineServiceEnabled ? "Enabled" : "Disabled"}</strong>
          <small>{formatPercent(fleet?.selfProtectionCoveragePercent)} coverage</small>
        </article>
      </section>

      <section className="fleet-layout">
        <div className="panel">
          <div className="section-head">
            <h2>Device Health</h2>
          </div>
          {loading ? (
            <TableSkeleton rows={7} columns={7} />
          ) : devices.length === 0 ? (
            <EmptyState title="No devices" description="No enrolled devices are currently registered for this tenant." />
          ) : (
            <div className="table-shell">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Device ID</th>
                    <th>Antivirus Enabled</th>
                    <th>Real-Time Protection</th>
                    <th>Signature Version</th>
                    <th>Last Updated</th>
                    <th>Quick Scan Age</th>
                    <th>Full Scan Age</th>
                  </tr>
                </thead>
                <tbody>
                  {devices.map((device) => (
                    <tr key={device.deviceId}>
                      <td className="font-mono">{device.deviceId}</td>
                      <td>{health?.antivirusEnabled ? "✓" : "✗"}</td>
                      <td>{health?.realTimeProtectionEnabled ? "✓" : "✗"}</td>
                      <td className="font-mono">{device.signaturePackVersion}</td>
                      <td><Timestamp value={device.lastSeenAt ?? device.createdAt} /></td>
                      <td className={(health?.quickScanAgeDays ?? 0) > 7 ? "text-critical" : ""}>{health?.quickScanAgeDays ?? "n/a"} days</td>
                      <td className={(health?.fullScanAgeDays ?? 0) > 30 ? "text-critical" : ""}>{health?.fullScanAgeDays ?? "n/a"} days</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        <aside className="panel deployment-panel">
          <div className="section-head">
            <h2>Signature Pack Deployment</h2>
          </div>
          <div className="deployment-detail">
            <span>Current version</span>
            <strong className="font-mono">{currentPack?.version ?? fleet?.currentPackVersion ?? "Unavailable"}</strong>
          </div>
          <div className="deployment-detail">
            <span>Channel</span>
            <strong><span className="pill pill-muted">{currentPack?.channel ?? "Stable"}</span></strong>
          </div>
          <div className="stepper">
            <div className="stepper-line" />
            <div className="stepper-node active">Canary</div>
            <div className="stepper-node active">GA</div>
          </div>
          <p className="deployment-note">
            {fleet?.legacyShadowModeEnabled ? "Legacy shadow mode remains enabled during rollout validation." : "Legacy shadow mode is disabled for this tenant."}
          </p>
        </aside>
      </section>
    </div>
  );
}
