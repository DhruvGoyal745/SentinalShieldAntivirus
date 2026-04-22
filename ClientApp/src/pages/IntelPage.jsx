import { useCallback, useEffect, useState } from "react";
import { Search, ShieldAlert, RefreshCcw, Plus, Trash2 } from "lucide-react";
import PageHeader from "../components/PageHeader";
import { EmptyState, ErrorState, TableSkeleton } from "../components/States";
import Timestamp from "../components/Timestamp";
import { api } from "../api";

const TABS = [
  { key: "lookup", label: "Lookup" },
  { key: "iocs", label: "Indicators" },
  { key: "audit", label: "Audit" }
];

const REPUTATION_TYPES = ["Sha256", "Sha1", "Md5", "Ip", "Domain", "Url"];
const IOC_TYPES = ["Sha256", "Sha1", "Md5", "Ip", "Domain", "Url", "PathGlob"];

export default function IntelPage({ lastUpdated }) {
  const [tab, setTab] = useState("lookup");

  return (
    <div className="page-stack">
      <PageHeader
        eyebrow="Threat Intelligence"
        title="Intel"
        lastUpdated={lastUpdated}
        actions={
          <div className="header-inline-actions">
            {TABS.map((t) => (
              <button
                key={t.key}
                type="button"
                className={`tab-button${tab === t.key ? " is-active" : ""}`}
                onClick={() => setTab(t.key)}
              >
                {t.label}
              </button>
            ))}
          </div>
        }
      />

      {tab === "lookup" ? <LookupTab /> : null}
      {tab === "iocs" ? <IocsTab /> : null}
      {tab === "audit" ? <AuditTab /> : null}
    </div>
  );
}

function LookupTab() {
  const [type, setType] = useState("Sha256");
  const [value, setValue] = useState("");
  const [allowCloud, setAllowCloud] = useState(true);
  const [result, setResult] = useState(null);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");

  async function handleSubmit(event) {
    event.preventDefault();
    if (!value.trim()) return;
    setSubmitting(true);
    setError("");
    setResult(null);
    try {
      const res = await api.reputationLookup({ type, value: value.trim(), allowCloud });
      setResult(res);
    } catch (err) {
      setError(err?.message ?? "Lookup failed");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <section className="panel">
      <div className="section-head">
        <h2>
          <Search size={18} aria-hidden="true" /> Reputation Lookup
        </h2>
      </div>
      <form className="form-grid" onSubmit={handleSubmit}>
        <label className="field">
          <span>Type</span>
          <select value={type} onChange={(e) => setType(e.target.value)}>
            {REPUTATION_TYPES.map((t) => (
              <option key={t} value={t}>
                {t}
              </option>
            ))}
          </select>
        </label>
        <label className="field field-grow">
          <span>Value</span>
          <input
            value={value}
            onChange={(e) => setValue(e.target.value)}
            placeholder="hash, ip, domain or url"
          />
        </label>
        <label className="field field-checkbox">
          <input type="checkbox" checked={allowCloud} onChange={(e) => setAllowCloud(e.target.checked)} />
          <span>Allow cloud providers</span>
        </label>
        <button type="submit" className="btn btn-primary" disabled={submitting}>
          {submitting ? "Looking up…" : "Lookup"}
        </button>
      </form>

      {error ? <ErrorState message={error} /> : null}

      {result ? (
        <article className="result-card" data-verdict={result.aggregateVerdict?.toLowerCase?.() ?? "unknown"}>
          <header>
            <h3>
              {result.aggregateVerdict}
              <span className="result-confidence">
                {(Number(result.aggregateConfidence) * 100).toFixed(0)}%
              </span>
            </h3>
            <p className="result-meta">
              Cache: {result.cacheStatus} · Latency: {result.durationMs}ms
              {result.failureReason ? ` · ${result.failureReason}` : ""}
            </p>
          </header>
          {result.localIocMatch ? (
            <div className="callout callout-warn">
              <ShieldAlert size={16} aria-hidden="true" /> Matched local IOC ({result.localIocMatch.source})
            </div>
          ) : null}
          {(result.providerResults ?? []).length > 0 ? (
            <table className="data-table">
              <thead>
                <tr>
                  <th>Provider</th>
                  <th>Verdict</th>
                  <th>Confidence</th>
                  <th>Latency</th>
                  <th>Evidence</th>
                </tr>
              </thead>
              <tbody>
                {result.providerResults.map((p) => (
                  <tr key={p.provider}>
                    <td>{p.provider}</td>
                    <td>
                      {p.verdict}
                      {p.fromCache ? " (cache)" : ""}
                      {p.timedOut ? " (timeout)" : ""}
                      {p.rateLimited ? " (rate-limited)" : ""}
                    </td>
                    <td>{(Number(p.confidence) * 100).toFixed(0)}%</td>
                    <td>{p.latencyMs}ms</td>
                    <td>{p.evidenceSummary}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <EmptyState message="No provider responses." />
          )}
        </article>
      ) : null}
    </section>
  );
}

function IocsTab() {
  const [items, setItems] = useState([]);
  const [stats, setStats] = useState(null);
  const [filters, setFilters] = useState({ type: "", source: "", q: "", active: true });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [creating, setCreating] = useState(false);
  const [draft, setDraft] = useState({ type: "Sha256", value: "", source: "manual", description: "" });

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const [list, s] = await Promise.all([
        api.searchIocs({ ...filters, pageSize: 100 }),
        api.getIocStats()
      ]);
      setItems(list);
      setStats(s);
    } catch (err) {
      setError(err?.message ?? "Failed to load indicators");
    } finally {
      setLoading(false);
    }
  }, [filters]);

  useEffect(() => {
    load();
  }, [load]);

  async function handleCreate(event) {
    event.preventDefault();
    if (!draft.value.trim()) return;
    setCreating(true);
    try {
      await api.createIoc(draft);
      setDraft({ type: "Sha256", value: "", source: "manual", description: "" });
      await load();
    } catch (err) {
      setError(err?.message ?? "Create failed");
    } finally {
      setCreating(false);
    }
  }

  async function handleDelete(id) {
    if (!window.confirm("Delete this indicator?")) return;
    try {
      await api.deleteIoc(id);
      await load();
    } catch (err) {
      setError(err?.message ?? "Delete failed");
    }
  }

  return (
    <>
      <section className="panel">
        <div className="section-head">
          <h2>
            <Plus size={18} aria-hidden="true" /> Add Indicator
          </h2>
        </div>
        <form className="form-grid" onSubmit={handleCreate}>
          <label className="field">
            <span>Type</span>
            <select value={draft.type} onChange={(e) => setDraft({ ...draft, type: e.target.value })}>
              {IOC_TYPES.map((t) => (
                <option key={t} value={t}>
                  {t}
                </option>
              ))}
            </select>
          </label>
          <label className="field field-grow">
            <span>Value</span>
            <input value={draft.value} onChange={(e) => setDraft({ ...draft, value: e.target.value })} />
          </label>
          <label className="field">
            <span>Source</span>
            <input value={draft.source} onChange={(e) => setDraft({ ...draft, source: e.target.value })} />
          </label>
          <label className="field field-grow">
            <span>Description</span>
            <input value={draft.description} onChange={(e) => setDraft({ ...draft, description: e.target.value })} />
          </label>
          <button type="submit" className="btn btn-primary" disabled={creating}>
            {creating ? "Adding…" : "Add"}
          </button>
        </form>
      </section>

      <section className="panel">
        <div className="section-head">
          <h2>Indicators ({stats?.active ?? 0} active / {stats?.total ?? 0} total)</h2>
          <button type="button" className="btn btn-ghost" onClick={load} disabled={loading}>
            <RefreshCcw size={14} aria-hidden="true" /> Refresh
          </button>
        </div>
        <div className="form-grid">
          <label className="field">
            <span>Type</span>
            <select value={filters.type} onChange={(e) => setFilters({ ...filters, type: e.target.value })}>
              <option value="">Any</option>
              {IOC_TYPES.map((t) => (
                <option key={t} value={t}>
                  {t}
                </option>
              ))}
            </select>
          </label>
          <label className="field">
            <span>Source</span>
            <input value={filters.source} onChange={(e) => setFilters({ ...filters, source: e.target.value })} />
          </label>
          <label className="field field-grow">
            <span>Search</span>
            <input value={filters.q} onChange={(e) => setFilters({ ...filters, q: e.target.value })} />
          </label>
        </div>

        {error ? <ErrorState message={error} onRetry={load} /> : null}
        {loading ? <TableSkeleton rows={5} /> : null}
        {!loading && items.length === 0 ? <EmptyState message="No indicators." /> : null}

        {!loading && items.length > 0 ? (
          <table className="data-table">
            <thead>
              <tr>
                <th>Type</th>
                <th>Value</th>
                <th>Source</th>
                <th>Severity</th>
                <th>Conf.</th>
                <th>Created</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {items.map((ioc) => (
                <tr key={ioc.id}>
                  <td>{ioc.type}</td>
                  <td className="cell-mono cell-truncate">{ioc.displayValue || ioc.normalizedValue}</td>
                  <td>{ioc.source}</td>
                  <td>{ioc.severity}</td>
                  <td>{(Number(ioc.confidence) * 100).toFixed(0)}%</td>
                  <td><Timestamp value={ioc.createdAt} /></td>
                  <td>
                    <button type="button" className="btn btn-ghost btn-icon" onClick={() => handleDelete(ioc.id)}>
                      <Trash2 size={14} aria-hidden="true" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : null}
      </section>
    </>
  );
}

function AuditTab() {
  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      setRows(await api.getReputationAudit(200));
    } catch (err) {
      setError(err?.message ?? "Failed to load audit");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  return (
    <section className="panel">
      <div className="section-head">
        <h2>Lookup Audit (last 200)</h2>
        <button type="button" className="btn btn-ghost" onClick={load} disabled={loading}>
          <RefreshCcw size={14} aria-hidden="true" /> Refresh
        </button>
      </div>
      {error ? <ErrorState message={error} onRetry={load} /> : null}
      {loading ? <TableSkeleton rows={6} /> : null}
      {!loading && rows.length === 0 ? <EmptyState message="No audit entries." /> : null}
      {!loading && rows.length > 0 ? (
        <table className="data-table">
          <thead>
            <tr>
              <th>When</th>
              <th>User</th>
              <th>Type</th>
              <th>Value</th>
              <th>Verdict</th>
              <th>Cache</th>
              <th>Local IOC</th>
              <th>Latency</th>
              <th>Providers</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.id}>
                <td><Timestamp value={r.createdAt} /></td>
                <td>{r.callerUser ?? "—"}</td>
                <td>{r.lookupType}</td>
                <td className="cell-mono cell-truncate">{r.redactedValue}</td>
                <td>{r.finalVerdict}</td>
                <td>{r.cacheHit ? "yes" : "no"}</td>
                <td>{r.localIocHit ? "yes" : "no"}</td>
                <td>{r.latencyMs}ms</td>
                <td>{r.providersAttempted}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : null}
    </section>
  );
}
