import { useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { getAlert, updateStatus } from '../api/alerts.js';
import { RiskBadge, StatusBadge } from '../components/Badges.jsx';
import { featureFields } from '../data/features.js';

export default function AlertDetail() {
  const { id } = useParams();
  const [alert, setAlert] = useState(null);
  const [features, setFeatures] = useState(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  async function load() {
    try {
      const data = await getAlert(id);
      setAlert(data);
      setError('');
      try { setFeatures(JSON.parse(sessionStorage.getItem(`sentrynet:features:${id}`) || 'null')); } catch { setFeatures(null); }
    } catch (err) { setError(err.message || 'Could not load this alert.'); }
  }

  useEffect(() => { load(); }, [id]);

  async function changeStatus(status) {
    setAlert((current) => ({ ...current, status }));
    setBusy(true);
    try { await updateStatus(id, status); await load(); }
    catch (err) { setError(err.message || 'Could not update alert status.'); await load(); }
    finally { setBusy(false); }
  }

  if (error && !alert) return <section className="panel detail-error"><Link className="back-link" to="/">← Dashboard</Link><h1>Alert unavailable</h1><p>{error}</p></section>;
  if (!alert) return <div className="empty-state"><span className="pulse-dot" /> Loading alert details…</div>;

  const fields = [['Alert ID', `#${alert.id}`], ['Source IP', alert.src_ip], ['Destination IP', alert.dst_ip], ['MAC address', alert.mac_address || 'Not on local network'],
    ['Label', alert.label], ['Category', alert.category], ['Risk score', <RiskBadge score={alert.risk_score} />], ['Status', <StatusBadge status={alert.status} />],
    ['Created at', new Date(alert.created_at).toLocaleString()]];

  return <>
    <div className="breadcrumbs"><Link to="/">← Dashboard</Link><span>/</span><span>Investigation</span><span>/</span><span className="mono">#{alert.id}</span></div>
    <section className="page-intro detail-intro"><div><div className="eyebrow">INCIDENT INVESTIGATION / #{alert.id}</div><h1>Alert <em>detail</em></h1><p>Review the detection and update its triage status.</p></div><div className="detail-status"><StatusBadge status={alert.status} /><RiskBadge score={alert.risk_score} /></div></section>
    {error && <div className="inline-error">{error}</div>}
    <div className="detail-grid"><section className="panel detail-panel"><div className="panel-heading"><div><span className="eyebrow">DETECTION RECORD</span><h2>Event summary</h2></div><span className={`label-pill ${alert.label}`}>{alert.label}</span></div>
      <div className="detail-fields">{fields.map(([label, value]) => <div className="detail-field" key={label}><span>{label}</span><strong className={['Source IP', 'Destination IP', 'Created at'].includes(label) ? 'mono' : ''}>{value}</strong></div>)}</div>
      <div className="action-section"><div><span className="eyebrow">ANALYST ACTIONS</span><p className="muted small">Record a triage outcome for this event.</p></div>
        <div className="action-buttons"><button className="button subtle" disabled={busy} onClick={() => changeStatus('reviewed')}>✓ Mark reviewed</button>
          <button className="button subtle" disabled={busy} onClick={() => changeStatus('false_positive')}>⊘ False positive</button>
          <button className="button escalate" disabled={busy} onClick={() => changeStatus('escalated')}>↑ Escalate</button></div>
      </div>
    </section>
    <section className="panel features-panel"><div className="panel-heading"><div><span className="eyebrow">MODEL INPUT</span><h2>Raw traffic features</h2></div><span className="feature-count">{features ? '41 FIELDS' : 'UNAVAILABLE'}</span></div>
      {features ? <div className="features-list">{featureFields.map(([key]) => <div key={key}><span>{key}</span><strong className="mono">{String(features[key] ?? '—')}</strong></div>)}</div>
        : <div className="feature-empty"><span className="empty-icon">⌘</span><strong>No raw feature snapshot</strong><p>Raw features are only retained in this browser for alerts submitted during this session. Historical alerts do not include feature values.</p></div>}
    </section></div>
  </>;
}
