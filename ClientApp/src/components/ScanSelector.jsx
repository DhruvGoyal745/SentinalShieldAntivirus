import { useDashboardStore } from "../state/useDashboardStore";
import { formatCompactDate } from "../ui/presentation";

export default function ScanSelector({ scans, label = "Scan context", id = "scan-context" }) {
  const selectedScanId = useDashboardStore((state) => state.selectedScanId);
  const setSelectedScanId = useDashboardStore((state) => state.setSelectedScanId);

  return (
    <label className="scan-selector" htmlFor={id}>
      <span>{label}</span>
      <select
        id={id}
        value={selectedScanId ?? ""}
        onChange={(event) => setSelectedScanId(event.target.value ? Number(event.target.value) : null)}
      >
        <option value="">All scans</option>
        {scans.map((scan) => (
          <option key={scan.id} value={scan.id}>
            {`SCAN-${String(scan.id).padStart(5, "0")} - ${formatCompactDate(scan.createdAt)}`}
          </option>
        ))}
      </select>
    </label>
  );
}
