export default function ScanSelector({ scans, selectedScanId, onChange }) {
  return (
    <div className="scan-selector">
      <label htmlFor="scan-dropdown">Filter by scan:</label>
      <select
        id="scan-dropdown"
        value={selectedScanId ?? ""}
        onChange={(e) => onChange(e.target.value ? Number(e.target.value) : null)}
      >
        <option value="">All scans</option>
        {scans.map((scan) => (
          <option key={scan.id} value={scan.id}>
            Scan #{scan.id} - {scan.mode} ({scan.status})
          </option>
        ))}
      </select>
    </div>
  );
}
