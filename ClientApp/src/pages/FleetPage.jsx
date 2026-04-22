import PageHeader from "../components/PageHeader";
import Timestamp from "../components/Timestamp";
import { EmptyState, ErrorState, TableSkeleton } from "../components/States";
import { complianceTone, formatPercent } from "../ui/presentation";

export default function FleetPage({ controlPlane, health, protectedFolders = [], loading, error, onRefresh, lastUpdated }) {
  const fleet = controlPlane?.fleet;
  const devices = controlPlane?.devices ?? [];
  const packs = controlPlane?.signaturePacks ?? [];
  const currentPack = packs[0] ?? null;

  return (
    <div className="page-stack">
      <PageHeader
        eyebrow="Overview"
        title="Devices"
        badge={`${devices.length} Devices`}
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
          <span>Tamper Protection</span>
          <strong>{health?.engineServiceEnabled ? "On" : "Off"}</strong>
        </article>
        <article className="metric-card">
          <span>Ransomware Shield</span>
          <strong className="text-healthy">{protectedFolders.length} folders</strong>
          <small>Protected</small>
        </article>
      </section>

      <section>
        <div className="panel">
          <div className="section-head">
            <h2>Device Health</h2>
          </div>
          {loading ? (
            <TableSkeleton rows={7} columns={7} />
          ) : devices.length === 0 ? (
            <EmptyState title="No devices" description="No devices are connected to Sentinel Shield yet." />
          ) : (
            <div className="table-shell">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Device</th>
                    <th>Antivirus</th>
                    <th>Real-Time Protection</th>
                    <th>Last Seen</th>
                    <th>Quick Scan</th>
                    <th>Full Scan</th>
                    <th>Ransomware Shield</th>
                  </tr>
                </thead>
                <tbody>
                  {devices.map((device) => (
                    <tr key={device.deviceId}>
                      <td>{device.deviceId?.split("-agent")[0] ?? device.deviceId}</td>
                      <td>{health?.antivirusEnabled ? "✓" : "✗"}</td>
                      <td>{health?.realTimeProtectionEnabled ? "✓" : "✗"}</td>
                      <td><Timestamp value={device.lastSeenAt ?? device.createdAt} /></td>
                      <td className={(health?.quickScanAgeDays ?? 0) > 7 ? "text-critical" : ""}>{health?.quickScanAgeDays != null ? `${health.quickScanAgeDays} days ago` : "—"}</td>
                      <td className={(health?.fullScanAgeDays ?? 0) > 30 ? "text-critical" : ""}>{health?.fullScanAgeDays != null ? `${health.fullScanAgeDays} days ago` : "—"}</td>
                      <td className="text-healthy">{protectedFolders.length > 0 ? `✓ (${protectedFolders.length})` : "✗"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </section>
    </div>
  );
}
