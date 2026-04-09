import {
  Activity,
  AlertTriangle,
  ClipboardCheck,
  FileText,
  Home,
  Search,
  Server,
  Shield
} from "lucide-react";

const iconByPage = {
  home: Home,
  incidents: AlertTriangle,
  detections: Search,
  telemetry: Activity,
  fleet: Server,
  governance: ClipboardCheck,
  reports: FileText
};

export default function AppSidebar({ pageDefinitions, currentPage, onNavigate, engineStatus }) {
  return (
    <aside className="sidebar-shell">
      <div className="sidebar-brand">
        <div className="sidebar-brand-icon" aria-hidden="true">
          <Shield size={20} />
        </div>
        <div className="sidebar-brand-copy">
          <strong>Sentinel Shield</strong>
          <span>Antivirus</span>
        </div>
      </div>

      <nav className="sidebar-nav" aria-label="Primary">
        {pageDefinitions.map((page) => {
          const Icon = iconByPage[page.key] ?? Home;
          const isActive = currentPage === page.key;

          return (
            <button
              key={page.key}
              type="button"
              className={`sidebar-link ${isActive ? "active" : ""}`}
              onClick={() => onNavigate(page.key)}
            >
              <Icon size={17} aria-hidden="true" />
              <span>{page.label}</span>
            </button>
          );
        })}
      </nav>

      <footer className="sidebar-footer">
        <div className="engine-indicator">
          <span className={`engine-dot ${engineStatus?.online ? "online" : "offline"}`} aria-hidden="true" />
          <div>
            <strong>Engine {engineStatus?.online ? "Online" : "Offline"}</strong>
            <span>{engineStatus?.daemonTransport || "Awaiting daemon status"}</span>
          </div>
        </div>
      </footer>
    </aside>
  );
}
