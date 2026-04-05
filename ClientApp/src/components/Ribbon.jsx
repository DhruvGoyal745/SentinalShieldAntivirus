export default function Ribbon({
  pageDefinitions,
  currentPage,
  onNavigate,
  health,
  fleet,
  openIncidentCount,
  tenantOptions,
  selectedTenant,
  setSelectedTenant,
  onRefresh,
  loading
}) {
  return (
    <header className="ribbon">
      <div className="ribbon-top">
        <div className="brand-lockup">
          <span className="eyebrow">Sentinel Shield</span>
          <strong>Enterprise Antivirus</strong>
          <small className="brand-subline">Threat operations console</small>
        </div>

        <div className="header-status-card">
          <span className={`status-dot ${health?.realTimeProtectionEnabled ? "healthy" : "degraded"}`} />
          <div>
            <strong>{health?.realTimeProtectionEnabled ? "Realtime protection on" : "Protection requires attention"}</strong>
            <span>
              {fleet?.activeDeviceCount ?? 0} active endpoints | {openIncidentCount} open incidents
            </span>
          </div>
        </div>
      </div>

      <div className="ribbon-bottom">
        <nav className="ribbon-nav" aria-label="Primary">
          {pageDefinitions.map((page) => (
            <button
              key={page.key}
              type="button"
              className={`ribbon-link ${currentPage === page.key ? "active" : ""}`}
              onClick={() => onNavigate(page.key)}
            >
              {page.label}
            </button>
          ))}
        </nav>

        <div className="ribbon-actions">
          <label className="tenant-picker tenant-picker-compact">
            <span>Tenant</span>
            <select value={selectedTenant} onChange={(event) => setSelectedTenant(event.target.value)}>
              {tenantOptions.map((tenant) => (
                <option key={tenant.tenantKey} value={tenant.tenantKey}>
                  {tenant.displayName}
                </option>
              ))}
            </select>
          </label>
          <button
            className="ghost-button compact ribbon-refresh"
            type="button"
            onClick={onRefresh}
            disabled={loading}
          >
            {loading ? "Refreshing..." : "Refresh"}
          </button>
        </div>
      </div>
    </header>
  );
}
