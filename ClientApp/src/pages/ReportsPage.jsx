import { Download } from "lucide-react";
import PageHeader from "../components/PageHeader";
import ScanSelector from "../components/ScanSelector";
import Timestamp from "../components/Timestamp";
import { EmptyState, ErrorState, TableSkeleton } from "../components/States";
import { useDashboardStore } from "../state/useDashboardStore";

export default function ReportsPage({
  scanExports,
  onCaptureCompliance,
  onExportAllScans,
  onExportScan,
  scans,
  loading,
  error,
  onRefresh,
  lastUpdated
}) {
  const selectedScanId = useDashboardStore((state) => state.selectedScanId);
  const filteredExports = selectedScanId
    ? scanExports.filter((scanExport) => scanExport.scanJobId === selectedScanId)
    : scanExports;

  return (
    <div className="page-stack">
      <PageHeader
        eyebrow="Exports"
        title="Scan Reports & Exports"
        description="Manage scan report exports and preserve scan context while generating analyst-ready outputs."
        lastUpdated={lastUpdated}
        actions={
          <div className="header-inline-actions">
            <ScanSelector scans={scans} label="Scan context" id="reports-scan-selector" />
            <button className="button button-primary" type="button" onClick={onExportAllScans}>
              <Download size={16} />
              Export All Scans
            </button>
            <button
              className="button button-secondary"
              type="button"
              onClick={() => onExportScan(selectedScanId)}
              disabled={!selectedScanId}
            >
              Export Selected Scan
            </button>
            <button className="button button-secondary" type="button" onClick={onCaptureCompliance}>
              Capture Snapshot
            </button>
          </div>
        }
      />

      {error ? <ErrorState message={error} onRetry={onRefresh} /> : null}

      {loading ? (
        <TableSkeleton rows={7} columns={6} />
      ) : filteredExports.length === 0 ? (
        <EmptyState title="No exports" description="No scan exports have been generated for the current scan context yet." />
      ) : (
        <div className="table-shell">
          <table className="data-table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Scan ID</th>
                <th>File Name</th>
                <th>Format</th>
                <th>Exported By</th>
                <th>Vulnerability Count</th>
                <th>Exported</th>
              </tr>
            </thead>
            <tbody>
              {filteredExports.map((scanExport) => (
                <tr key={scanExport.id}>
                  <td className="font-mono">{scanExport.id}</td>
                  <td className="font-mono">
                    {scanExport.scanJobId ? `SCAN-${String(scanExport.scanJobId).padStart(5, "0")}` : "All scans"}
                  </td>
                  <td>{scanExport.fileName}</td>
                  <td><span className={`pill ${scanExport.format?.toLowerCase() === "excel" || scanExport.format?.toLowerCase() === "xls" ? "pill-healthy" : "pill-muted"}`}>{scanExport.format}</span></td>
                  <td>{scanExport.exportedBy}</td>
                  <td>{scanExport.vulnerabilityCount}</td>
                  <td><Timestamp value={scanExport.exportedAt} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
