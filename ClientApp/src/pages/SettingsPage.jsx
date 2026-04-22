import { useCallback, useEffect, useState } from "react";
import { Settings, Save, RefreshCcw, Lock, ShieldCheck, Trash2 } from "lucide-react";
import PageHeader from "../components/PageHeader";
import { EmptyState, ErrorState, TableSkeleton } from "../components/States";
import Timestamp from "../components/Timestamp";
import { api } from "../api";

const TABS = [
  { key: "providers", label: "Providers" },
  { key: "secrets", label: "API Keys" },
  { key: "feeds", label: "Feed Sync Runs" }
];

export default function SettingsPage({ lastUpdated }) {
  const [tab, setTab] = useState("providers");

  return (
    <div className="page-stack">
      <PageHeader
        eyebrow="Settings"
        title="Threat Intel Configuration"
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
      {tab === "providers" ? <ProvidersTab /> : null}
      {tab === "secrets" ? <SecretsTab /> : null}
      {tab === "feeds" ? <FeedsTab /> : null}
    </div>
  );
}

function ProvidersTab() {
  const [settings, setSettings] = useState(null);
  const [health, setHealth] = useState([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const [s, h] = await Promise.all([api.getThreatFeedSettings(), api.getReputationProviderHealth()]);
      setSettings(s);
      setHealth(h);
    } catch (err) {
      setError(err?.message ?? "Failed to load settings");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  function updateProvider(provider, patch) {
    setSettings((prev) => ({
      ...prev,
      providers: prev.providers.map((p) => (p.provider === provider ? { ...p, ...patch } : p))
    }));
  }

  function updateTtl(patch) {
    setSettings((prev) => ({ ...prev, ttl: { ...prev.ttl, ...patch } }));
  }

  async function handleSave() {
    if (!settings) return;
    setSaving(true);
    setError("");
    setMessage("");
    try {
      const updated = await api.updateThreatFeedSettings(settings);
      setSettings(updated);
      setMessage("Saved");
    } catch (err) {
      setError(err?.message ?? "Save failed");
    } finally {
      setSaving(false);
    }
  }

  if (loading) return <TableSkeleton rows={4} />;
  if (error) return <ErrorState message={error} onRetry={load} />;
  if (!settings) return <EmptyState message="No settings loaded." />;

  const healthByProvider = Object.fromEntries(health.map((h) => [h.provider, h]));

  return (
    <>
      <section className="panel">
        <div className="section-head">
          <h2><Settings size={18} aria-hidden="true" /> Cloud Reputation</h2>
          <button type="button" className="btn btn-primary" onClick={handleSave} disabled={saving}>
            <Save size={14} aria-hidden="true" /> {saving ? "Saving…" : "Save"}
          </button>
        </div>
        {message ? <div className="callout callout-ok">{message}</div> : null}

        <label className="field field-checkbox">
          <input
            type="checkbox"
            checked={settings.cloudReputationEnabled}
            onChange={(e) => setSettings({ ...settings, cloudReputationEnabled: e.target.checked })}
          />
          <span>Enable cloud reputation lookups</span>
        </label>
        <label className="field">
          <span>Fan-out timeout (ms)</span>
          <input
            type="number"
            min={250}
            value={settings.cloudFanoutTimeoutMs ?? 1500}
            onChange={(e) => setSettings({ ...settings, cloudFanoutTimeoutMs: Number(e.target.value) })}
          />
        </label>

        <table className="data-table">
          <thead>
            <tr>
              <th>Provider</th>
              <th>Enabled</th>
              <th>Trust</th>
              <th>Rate (req/min)</th>
              <th>Circuit</th>
              <th>Last success</th>
              <th>Last failure</th>
            </tr>
          </thead>
          <tbody>
            {settings.providers.map((p) => {
              const h = healthByProvider[p.provider];
              return (
                <tr key={p.provider}>
                  <td>{p.provider}</td>
                  <td>
                    <input
                      type="checkbox"
                      checked={p.enabled}
                      onChange={(e) => updateProvider(p.provider, { enabled: e.target.checked })}
                    />
                  </td>
                  <td>
                    <input
                      type="number"
                      step="0.05"
                      min={0}
                      max={1}
                      value={p.trustWeight}
                      onChange={(e) => updateProvider(p.provider, { trustWeight: Number(e.target.value) })}
                      style={{ width: "5rem" }}
                    />
                  </td>
                  <td>
                    <input
                      type="number"
                      min={1}
                      value={p.rateLimitPerMinute}
                      onChange={(e) => updateProvider(p.provider, { rateLimitPerMinute: Number(e.target.value) })}
                      style={{ width: "5rem" }}
                    />
                  </td>
                  <td>{h?.circuitState ?? "—"}</td>
                  <td><Timestamp value={h?.lastSuccessAt} /></td>
                  <td>
                    {h?.lastFailureAt ? <Timestamp value={h.lastFailureAt} /> : "—"}
                    {h?.lastFailureReason ? <small> · {h.lastFailureReason}</small> : null}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </section>

      <section className="panel">
        <div className="section-head">
          <h2>Cache TTLs (seconds)</h2>
        </div>
        <div className="form-grid">
          <NumField label="Hash" value={settings.ttl.hashTtlSeconds} onChange={(v) => updateTtl({ hashTtlSeconds: v })} />
          <NumField label="URL" value={settings.ttl.urlTtlSeconds} onChange={(v) => updateTtl({ urlTtlSeconds: v })} />
          <NumField label="IP" value={settings.ttl.ipTtlSeconds} onChange={(v) => updateTtl({ ipTtlSeconds: v })} />
          <NumField label="Domain" value={settings.ttl.domainTtlSeconds} onChange={(v) => updateTtl({ domainTtlSeconds: v })} />
          <NumField label="Negative" value={settings.ttl.negativeTtlSeconds} onChange={(v) => updateTtl({ negativeTtlSeconds: v })} />
        </div>
      </section>
    </>
  );
}

function NumField({ label, value, onChange }) {
  return (
    <label className="field">
      <span>{label}</span>
      <input type="number" min={0} value={value} onChange={(e) => onChange(Number(e.target.value))} />
    </label>
  );
}

function SecretsTab() {
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [draft, setDraft] = useState({ provider: "virustotal", key: "api-key", value: "" });
  const [saving, setSaving] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      setItems(await api.listSecrets());
    } catch (err) {
      setError(err?.message ?? "Failed to load secrets");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  async function handleSave(event) {
    event.preventDefault();
    if (!draft.value.trim()) return;
    setSaving(true);
    try {
      await api.setSecret(draft.provider, draft.key, draft.value);
      setDraft({ ...draft, value: "" });
      await load();
    } catch (err) {
      setError(err?.message ?? "Save failed");
    } finally {
      setSaving(false);
    }
  }

  async function handleDelete(provider, key) {
    if (!window.confirm(`Delete ${provider}/${key}?`)) return;
    try {
      await api.deleteSecret(provider, key);
      await load();
    } catch (err) {
      setError(err?.message ?? "Delete failed");
    }
  }

  return (
    <>
      <section className="panel">
        <div className="section-head">
          <h2><Lock size={18} aria-hidden="true" /> Store API Key</h2>
        </div>
        <form className="form-grid" onSubmit={handleSave}>
          <label className="field">
            <span>Provider</span>
            <select value={draft.provider} onChange={(e) => setDraft({ ...draft, provider: e.target.value })}>
              <option value="virustotal">virustotal</option>
              <option value="hybridanalysis">hybridanalysis</option>
              <option value="misp">misp</option>
              <option value="otx">otx</option>
            </select>
          </label>
          <label className="field">
            <span>Key</span>
            <input value={draft.key} onChange={(e) => setDraft({ ...draft, key: e.target.value })} />
          </label>
          <label className="field field-grow">
            <span>Value</span>
            <input type="password" value={draft.value} onChange={(e) => setDraft({ ...draft, value: e.target.value })} />
          </label>
          <button type="submit" className="btn btn-primary" disabled={saving}>
            {saving ? "Saving…" : "Store"}
          </button>
        </form>
        <p className="hint">
          <ShieldCheck size={14} aria-hidden="true" /> Secrets are encrypted at rest (DPAPI on Windows; AES-256-GCM elsewhere).
          Plaintext is never returned by the API.
        </p>
      </section>

      <section className="panel">
        <div className="section-head">
          <h2>Stored Secrets</h2>
          <button type="button" className="btn btn-ghost" onClick={load} disabled={loading}>
            <RefreshCcw size={14} aria-hidden="true" /> Refresh
          </button>
        </div>
        {error ? <ErrorState message={error} onRetry={load} /> : null}
        {loading ? <TableSkeleton rows={3} /> : null}
        {!loading && items.length === 0 ? <EmptyState message="No secrets stored." /> : null}
        {!loading && items.length > 0 ? (
          <table className="data-table">
            <thead>
              <tr>
                <th>Provider</th>
                <th>Key</th>
                <th>Algorithm</th>
                <th>Updated</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {items.map((s) => (
                <tr key={`${s.provider}/${s.secretKey}`}>
                  <td>{s.provider}</td>
                  <td>{s.secretKey}</td>
                  <td>{s.algorithm}</td>
                  <td><Timestamp value={s.updatedAt} /></td>
                  <td>
                    <button type="button" className="btn btn-ghost btn-icon" onClick={() => handleDelete(s.provider, s.secretKey)}>
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

function FeedsTab() {
  const [runs, setRuns] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [syncing, setSyncing] = useState(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      setRuns(await api.getThreatFeedRuns(undefined, 100));
    } catch (err) {
      setError(err?.message ?? "Failed to load runs");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  async function handleSync(provider) {
    setSyncing(provider);
    try {
      await api.syncThreatFeed(provider);
      await load();
    } catch (err) {
      setError(err?.message ?? "Sync failed");
    } finally {
      setSyncing(null);
    }
  }

  return (
    <section className="panel">
      <div className="section-head">
        <h2>Feed Sync Runs</h2>
        <div className="header-inline-actions">
          <button type="button" className="btn btn-primary" onClick={() => handleSync("otx")} disabled={syncing === "otx"}>
            {syncing === "otx" ? "Syncing…" : "Sync OTX now"}
          </button>
          <button type="button" className="btn btn-ghost" onClick={load} disabled={loading}>
            <RefreshCcw size={14} aria-hidden="true" /> Refresh
          </button>
        </div>
      </div>
      {error ? <ErrorState message={error} onRetry={load} /> : null}
      {loading ? <TableSkeleton rows={4} /> : null}
      {!loading && runs.length === 0 ? <EmptyState message="No sync runs yet." /> : null}
      {!loading && runs.length > 0 ? (
        <table className="data-table">
          <thead>
            <tr>
              <th>Started</th>
              <th>Provider</th>
              <th>Status</th>
              <th>Imported</th>
              <th>Skipped</th>
              <th>Failure</th>
            </tr>
          </thead>
          <tbody>
            {runs.map((r) => (
              <tr key={r.id}>
                <td><Timestamp value={r.startedAt} /></td>
                <td>{r.provider}</td>
                <td>{r.success ? "OK" : "Failed"}</td>
                <td>{r.indicatorsImported}</td>
                <td>{r.indicatorsSkipped}</td>
                <td>{r.failureReason ?? "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : null}
    </section>
  );
}
