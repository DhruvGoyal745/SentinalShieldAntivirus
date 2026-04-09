import { AlertTriangle, LoaderCircle, ShieldCheck } from "lucide-react";

export function EmptyState({ icon: Icon = ShieldCheck, title, description }) {
  return (
    <div className="empty-state">
      <Icon size={22} aria-hidden="true" />
      <strong>{title}</strong>
      <span>{description}</span>
    </div>
  );
}

export function ErrorState({ message, onRetry }) {
  return (
    <div className="error-state" role="alert">
      <AlertTriangle size={18} aria-hidden="true" />
      <span>{message}</span>
      {onRetry ? (
        <button className="button button-secondary button-small" type="button" onClick={onRetry}>
          Retry
        </button>
      ) : null}
    </div>
  );
}

export function TableSkeleton({ rows = 6, columns = 5 }) {
  return (
    <div className="table-shell">
      <table className="data-table">
        <thead>
          <tr>
            {Array.from({ length: columns }).map((_, index) => (
              <th key={index}>
                <span className="skeleton-block skeleton-header" />
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {Array.from({ length: rows }).map((_, rowIndex) => (
            <tr key={rowIndex}>
              {Array.from({ length: columns }).map((__, columnIndex) => (
                <td key={columnIndex}>
                  <span className="skeleton-block" />
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function CardGridSkeleton({ cards = 6 }) {
  return (
    <div className="card-grid">
      {Array.from({ length: cards }).map((_, index) => (
        <article key={index} className="panel-card skeleton-card">
          <LoaderCircle className="spinning" size={18} aria-hidden="true" />
          <span className="skeleton-block skeleton-heading" />
          <span className="skeleton-block" />
          <span className="skeleton-block" />
          <span className="skeleton-block skeleton-short" />
        </article>
      ))}
    </div>
  );
}
