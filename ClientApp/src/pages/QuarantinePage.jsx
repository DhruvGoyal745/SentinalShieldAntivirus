import { useMemo, useState } from "react";
import PageHeader from "../components/PageHeader";
import { CardGridSkeleton, EmptyState, ErrorState } from "../components/States";
import { getRetentionDaysRemaining } from "../ui/presentation";

const purgeStateColors = {
  Active: "badge-warning",
  Expired: "badge-muted",
  Purged: "badge-muted",
  Restored: "badge-success"
};

const severityColors = {
  Critical: "badge-critical",
  High: "badge-danger",
  Medium: "badge-warning",
  Low: "badge-info",
  Informational: "badge-muted"
};

function formatBytes(bytes) {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`;
}

function formatDate(dateString) {
  if (!dateString) return "—";
  return new Date(dateString).toLocaleString();
}

export default function QuarantinePage({
  quarantineItems,
  onRestore,
  onPurge,
  onPurgeExpired,
  pendingActionId,
  loading,
  error,
  onRefresh,
  lastUpdated
}) {
  const [query, setQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState("Active");

  const filteredItems = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return quarantineItems
      .filter((item) => !statusFilter || item.purgeState === statusFilter)
      .filter((item) =>
        !needle ||
        [item.originalFileName, item.originalPath, item.threatName, item.hashSha256]
          .filter(Boolean)
          .some((v) => v.toLowerCase().includes(needle))
      );
  }, [quarantineItems, query, statusFilter]);

  const stats = useMemo(() => {
    const active = quarantineItems.filter((i) => i.purgeState === "Active").length;
    const totalSize = quarantineItems
      .filter((i) => i.purgeState === "Active")
      .reduce((sum, i) => sum + (i.fileSizeBytes || 0), 0);
    return { active, totalSize };
  }, [quarantineItems]);

  return (
    <div className="page-stack">
      <PageHeader
        eyebrow="Protection"
        title="Quarantine Vault"
        badge={`${stats.active} Items · ${formatBytes(stats.totalSize)}`}
        lastUpdated={lastUpdated}
        actions={
          <div className="header-inline-actions">
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="field-select"
            >
              <option value="">All States</option>
              <option value="Active">Active</option>
              <option value="Expired">Expired</option>
              <option value="Restored">Restored</option>
              <option value="Purged">Purged</option>
            </select>
            <label className="field field-search">
              <span>Search quarantine</span>
              <input
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Search by file name or threat"
              />
            </label>
            <button
              className="btn btn-sm btn-outline"
              onClick={onPurgeExpired}
              title="Remove expired items permanently"
            >
              Purge Expired
            </button>
          </div>
        }
      />

      {loading && !quarantineItems.length ? (
        <CardGridSkeleton />
      ) : error ? (
        <ErrorState message={error} onRetry={onRefresh} />
      ) : !filteredItems.length ? (
        <EmptyState
          title="Quarantine Empty"
          message={statusFilter ? `No ${statusFilter.toLowerCase()} items found.` : "No quarantined files yet."}
        />
      ) : (
        <div className="card-grid">
          {filteredItems.map((item) => (
            <article key={item.id} className="card">
              <div className="card-header">
                <span className="card-title" title={item.originalPath}>
                  {item.originalFileName}
                </span>
                <span className={`badge ${purgeStateColors[item.purgeState] ?? "badge-muted"}`}>
                  {item.purgeState}
                </span>
              </div>

              <dl className="card-meta">
                <div>
                  <dt>Encryption</dt>
                  <dd>
                    <span className={item.encryptionKeyId ? "badge-encrypted" : "badge-unencrypted"}>
                      {item.encryptionKeyId ? "AES-256 Encrypted" : "Plain"}
                    </span>
                  </dd>
                </div>
                <div>
                  <dt>Threat</dt>
                  <dd>
                    {item.threatName ?? "Unknown"}
                    {item.threatSeverity ? (
                      <span className={`badge badge-sm ${severityColors[item.threatSeverity] ?? ""}`} style={{ marginLeft: 6 }}>
                        {item.threatSeverity}
                      </span>
                    ) : null}
                  </dd>
                </div>
                <div>
                  <dt>Size</dt>
                  <dd>{formatBytes(item.fileSizeBytes)}</dd>
                </div>
                <div>
                  <dt>SHA-256</dt>
                  <dd className="mono" title={item.hashSha256}>
                    {item.hashSha256?.slice(0, 16)}…
                  </dd>
                </div>
                <div>
                  <dt>Quarantined</dt>
                  <dd>{formatDate(item.createdAt)}</dd>
                </div>
                <div>
                  <dt>Expires</dt>
                  <dd>
                    {formatDate(item.retentionExpiresAt)}
                    {item.purgeState === "Active" && item.retentionExpiresAt ? (() => {
                      const days = getRetentionDaysRemaining(item.retentionExpiresAt);
                      return days !== null ? (
                        <span className={`retention-countdown ${days <= 3 ? "text-critical" : days <= 7 ? "text-warning" : ""}`}>
                          {days > 0 ? ` (${days}d remaining)` : " (expired)"}
                        </span>
                      ) : null;
                    })() : null}
                  </dd>
                </div>
                {item.restoredAt ? (
                  <div>
                    <dt>Restored</dt>
                    <dd>{formatDate(item.restoredAt)} by {item.restoredBy ?? "unknown"}</dd>
                  </div>
                ) : null}
                <div>
                  <dt>Original Path</dt>
                  <dd className="mono" title={item.originalPath}>
                    {item.originalPath}
                  </dd>
                </div>
              </dl>

              {item.purgeState === "Active" ? (
                <div className="card-actions">
                  <button
                    className="btn btn-sm btn-outline"
                    onClick={() => onRestore(item.id)}
                    disabled={pendingActionId === item.id}
                  >
                    {pendingActionId === item.id ? "Restoring…" : "Restore"}
                  </button>
                  <button
                    className="btn btn-sm btn-danger"
                    onClick={() => {
                      if (window.confirm(`Permanently purge "${item.originalFileName}"? This cannot be undone.`)) {
                        onPurge(item.id);
                      }
                    }}
                    disabled={pendingActionId === item.id}
                  >
                    {pendingActionId === item.id ? "Purging…" : "Purge"}
                  </button>
                </div>
              ) : null}
            </article>
          ))}
        </div>
      )}
    </div>
  );
}
