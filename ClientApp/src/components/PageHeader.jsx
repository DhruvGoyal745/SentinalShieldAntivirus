import Timestamp from "./Timestamp";

export default function PageHeader({ eyebrow, title, badge, description, actions, pageKey, lastUpdated }) {
  return (
    <header className="page-header">
      <div className="page-header-copy">
        {eyebrow ? <span className="page-eyebrow">{eyebrow}</span> : null}
        <div className="page-title-row">
          <h1>{title}</h1>
          {badge ? <span className="count-badge">{badge}</span> : null}
        </div>
        {description ? <p>{description}</p> : null}
      </div>
      <div className="page-header-actions">
        {lastUpdated ? (
          <div className="last-updated-pill" data-page={pageKey}>
            Updated <Timestamp value={lastUpdated} />
          </div>
        ) : null}
        {actions}
      </div>
    </header>
  );
}
