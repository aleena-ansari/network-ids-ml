import { useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { getAlert, updateStatus } from '../api/alerts.js';
import { RiskBadge, StatusBadge } from '../components/Badges.jsx';

const sourceText = {
  random_forest: 'Random Forest (attack alert)',
  isolation_forest_flag: 'Isolation Forest flag only (not a confirmed attack)',
  none: 'No detector flagged this flow',
};

export default function AlertDetail() {
  const { id } = useParams();
  const [alert, setAlert] = useState(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  async function load() {
    try {
      const data = await getAlert(id);
      setAlert(data);
      setError('');
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

  if (error && !alert) return <section className="panel detail-error"><Link className="back-link" to="/">&larr; Dashboard</Link><h1>Alert unavailable</h1><p>{error}</p></section>;
  if (!alert) return <div className="empty-state"><span className="pulse-dot" /> Loading alert details&hellip;</div>;

  const p = alert.attack_probability;
  const macText = alert.mac_address || alert.mac_note || 'Not available';
  const family = alert.label === 'attack' ? 'Unknown (no CICIDS2017 family classifier)' : '\u2014';
  const fields = [
    ['Alert ID', `#${alert.id}`], ['Source IP', alert.src_ip], ['Destination IP', alert.dst_ip], ['MAC address', macText],
    ['Label', alert.label], ['Attack family', family], ['Risk score', <RiskBadge score={alert.risk_score} />], ['Status', <StatusBadge status={alert.status} />],
    ['Created at', new Date(alert.created_at).toLocaleString()],
    ['Data origin', alert.origin === 'simulated' ? 'Simulated replay (recorded CICIDS2017 flow, made-up IP/MAC)' : 'Submitted via API'],
  ];
  const evidence = [
    ['Random Forest attack probability', p == null ? '\u2014' : `${(p * 100).toFixed(1)}%`],
    ['Detection source', sourceText[alert.detection_source] || alert.detection_source || '\u2014'],
    ['Isolation Forest score', alert.anomaly_score == null ? '\u2014' : String(alert.anomaly_score)],
    ['Unusual-traffic flag', alert.anomaly_detected ? 'Yes (review; not a confirmed attack)' : 'No'],
  ];

  return <>
    <div className="breadcrumbs"><Link to="/">&larr; Dashboard</Link><span>/</span><span>Investigation</span><span>/</span><span className="mono">#{alert.id}</span></div>
    <section className="page-intro detail-intro"><div><div className="eyebrow">INCIDENT INVESTIGATION / #{alert.id}</div><h1>Alert <em>detail</em></h1><p>Review the detection and update its triage status.</p></div><div className="detail-status"><StatusBadge status={alert.status} /><RiskBadge score={alert.risk_score} /></div></section>
    {error && <div className="inline-error">{error}</div>}
    <div className="detail-grid"><section className="panel detail-panel"><div className="panel-heading"><div><span className="eyebrow">DETECTION RECORD</span><h2>Event summary</h2></div><span><span className={`label-pill ${alert.label}`}>{alert.label}</span>{alert.anomaly_detected && <span className="label-pill"> unusual traffic</span>}</span></div>
      <div className="detail-fields">{fields.map(([label, value]) => <div className="detail-field" key={label}><span>{label}</span><strong className={['Source IP', 'Destination IP', 'Created at'].includes(label) ? 'mono' : ''}>{value}</strong></div>)}</div>
      <div className="action-section"><div><span className="eyebrow">ANALYST ACTIONS</span><p className="muted small">Record a triage outcome for this event. SentryNet never blocks traffic.</p></div>
        <div className="action-buttons"><button className="button subtle" disabled={busy} onClick={() => changeStatus('reviewed')}>&#10003; Mark reviewed</button>
          <button className="button subtle" disabled={busy} onClick={() => changeStatus('false_positive')}>&#8856; False positive</button>
          <button className="button escalate" disabled={busy} onClick={() => changeStatus('escalated')}>&#8593; Escalate</button></div>
      </div>
    </section>
    <section className="panel features-panel"><div className="panel-heading"><div><span className="eyebrow">MODEL EVIDENCE</span><h2>Why this alert</h2></div><span className="feature-count">RF + IF</span></div>
      <div className="features-list">{evidence.map(([key, value]) => <div key={key}><span>{key}</span><strong className="mono">{value}</strong></div>)}</div>
      <p className="muted small">Risk score = Random Forest attack probability &times; 100. It is a heuristic for ordering analyst review, not a calibrated probability. The Isolation Forest only marks unusual traffic; it does not confirm an attack or identify its family.</p>
    </section></div>
  </>;
}