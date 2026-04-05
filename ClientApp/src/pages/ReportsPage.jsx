import { formatDate, formatPercent } from "../ui/presentation";

export default function ReportsPage({ scanExports, complianceReports, handleCaptureCompliance, handleExportAllScans }) {
  return (
    <div className="page-stack">
      <section className="panel page-panel">
        <div className="panel-heading panel-heading-inline">
          <div>
            <h2>Reporting</h2>
            <p>Exports and compliance snapshots are separated so reporting work stays clean and audit-friendly.</p>
          </div>
          <div className="action-row">
            <button className="ghost-button compact" type="button" onClick={handleCaptureCompliance}>
              Capture compliance snapshot
            </button>
            <button className="primary-button compact" type="button" onClick={handleExportAllScans}>
              Export all scans to Excel
            </button>
          </div>
        </div>
      </section>

      <section className="panel page-panel">
        <div className="panel-heading">
          <h2>Recent Excel exports</h2>
          <p>Track every scan report that has been generated for this tenant.</p>
        </div>

        <div className="history-list">
          {scanExports.map((scanExport) => (
            <article key={scanExport.id} className="history-card compact-card">
              <div className="history-meta">
                <span>Export #{scanExport.id}</span>
                <span>Scan ID: {scanExport.scanJobId ?? "All scans"}</span>
                <span>Vulnerabilities: {scanExport.vulnerabilityCount}</span>
                <span>By: {scanExport.exportedBy}</span>
              </div>
              <p>{scanExport.fileName} generated at {formatDate(scanExport.exportedAt)}.</p>
            </article>
          ))}
          {scanExports.length === 0 ? <p className="empty-state">No scan reports have been exported yet.</p> : null}
        </div>
      </section>

      <section className="panel page-panel">
        <div className="panel-heading">
          <h2>Compliance snapshots</h2>
          <p>Point-in-time compliance and posture evidence captured for reporting workflows.</p>
        </div>

        <div className="history-list">
          {complianceReports.map((report) => (
            <article key={`${report.id}-${report.reportDate}`} className="history-card compact-card">
              <div className="history-meta">
                <span>Report #{report.id}</span>
                <span>Date: {formatDate(report.reportDate)}</span>
                <span>Type: {report.reportType}</span>
                <span>Coverage: {formatPercent(report.agentCoveragePercent)}</span>
                <span>Baseline: {formatPercent(report.baselineScanCompletionPercent)}</span>
                <span>Self-protection: {formatPercent(report.selfProtectionCoveragePercent)}</span>
              </div>
              <p>
                Signature currency {formatPercent(report.signatureCurrencyPercent)}. Open critical incidents:{" "}
                {report.openCriticalIncidentCount}. Audit findings: {report.auditFindingCount}. Quarantined threats:{" "}
                {report.quarantinedThreatCount}.
              </p>
            </article>
          ))}
          {complianceReports.length === 0 ? <p className="empty-state">No compliance snapshots have been captured yet.</p> : null}
        </div>
      </section>
    </div>
  );
}
