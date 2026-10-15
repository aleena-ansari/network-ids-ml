import { useCallback, useEffect, useMemo, useState } from 'react';
import AlertTable from '../components/AlertTable.jsx';
import MetricsPanel from '../components/MetricsPanel.jsx';
import StatCard from '../components/StatCard.jsx';
import TrafficForm from '../components/TrafficForm.jsx';
import { getAlerts, predict } from '../api/alerts.js';
import { fetchMetrics } from '../api/metrics.js';

const tabs = [['all', 'All'], ['new', 'New'], ['reviewed', 'Reviewed'], ['false_positive', 'False positive'], ['escalated', 'Escalated']];

export default function Dashboard() {
  const [alerts, setAlerts] = useState([]);
  const [metrics, setMetrics] = useState(null);
  const [filter, setFilter] = useState('new');
  const [sort, setSort] = useState({ key: 'created_at', direction: 'desc' });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  const refresh = useCallback(async (initial = false) => {
    try {
      const data = await getAlerts();
      const list = Array.isArray(data) ? data : data.alerts || [];
      setAlerts((previous) => {
        const known = new Set(previous.map((item) => String(item.id)));
        return list.map((item) => ({ ...item, fresh: !known.has(String(item.id)) }));
      });
      setError('');
    } catch (err) { setError(err.message || 'Could not connect to the API at localhost:8000.'); }
    finally { if (initial) setLoading(false); }
  }, []);

  useEffect(() => {
    refresh(true);
    fetchMetrics().then(setMetrics).catch(() => setMetrics(null));
    const poll = window.setInterval(() => refresh(false), 5000);
    return () => window.clearInterval(poll);
  }, [refresh]);

  const filteredAlerts = useMemo(() => {
    const list = filter === 'all' ? alerts : alerts.filter((item) => item.status === filter);
    return [...list].sort((a, b) => {
      const av = a[sort.key]; const bv = b[sort.key];
      const order = sort.key === 'created_at' ? new Date(av).getTime() - new Date(bv).getTime() : Number(av) - Number(bv);
      return sort.direction === 'asc' ? order : -order;
    });
  }, [alerts, filter, sort]);

  async function submitTraffic(payload) {
    setBusy(true);
    try {
      const alert = await predict(payload);
      try { sessionStorage.setItem(`sentrynet:features:${alert.id}`, JSON.stringify(payload)); } catch { /* storage may be unavailable */ }
      setAlerts((current) => [{ ...alert, fresh: true }, ...current.filter((item) => item.id !== alert.id)]);
      await refresh(false);
      return alert;
    } finally { setBusy(false); }
  }

  function toggleSort(key) {
    setSort((current) => ({ key, direction: current.key === key && current.direction === 'desc' ? 'asc' : 'desc' }));
  }

  const total = alerts.length;
  const newCount = alerts.filter((item) => item.status === 'new').length;
  const attacks = alerts.filter((item) => item.label === 'attack').length;
  const normals = total - attacks;

  return <>
    <section className="page-intro"><div><div className="eyebrow"><span className="pulse-dot" /> NETWORK OPERATIONS / OVERVIEW</div><h1>Threat <em>monitor</em></h1><p>Live network detections and analyst triage.</p></div><div className="stream-state"><span className="pulse-dot" /> LIVE STREAM <small>5s refresh</small></div></section>
    {error && <div className="connection-banner"><span>!</span><div><strong>Backend unavailable</strong><p>{error}. Start the FastAPI service to receive live alerts.</p></div><button className="button subtle" onClick={() => refresh(false)}>Retry</button></div>}
    <div className="overview-grid"><div className="overview-left">
      <div className="stats-grid">
        <StatCard label="Total alerts" value={total} note="All detections" />
        <StatCard label="Needs review" value={newCount} note="Active triage queue" tone="amber" />
        <StatCard label="Attack / normal" value={<>{attacks}<span className="split-slash"> / </span>{normals}</>} note="Across all events" tone="red" />
      </div>
      {metrics && <MetricsPanel data={metrics} />}
    </div><TrafficForm onSubmit={submitTraffic} busy={busy} /></div>
    <section className="panel queue-panel"><div className="queue-heading"><div><span className="eyebrow">DETECTION LOG</span><h2>Alert triage</h2></div><span className="queue-count">{filteredAlerts.length} <span>events</span></span></div>
      <div className="filter-tabs" role="tablist">{tabs.map(([key, label]) => <button key={key} role="tab" aria-selected={filter === key} className={filter === key ? 'active' : ''} onClick={() => setFilter(key)}>{label}{key === 'new' && <span>{newCount}</span>}</button>)}</div>
      <AlertTable alerts={filteredAlerts} sort={sort} onSort={toggleSort} loading={loading} />
      <div className="table-footer"><span className="muted small"><span className="pulse-dot" /> Polling every 5 seconds</span><span className="muted small">Analyst review only</span></div>
    </section>
  </>;
}
