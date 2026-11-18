import { useState } from 'react';
import { BASE_URL } from '../api/client.js';

export default function SimulatePanel({ onDone }) {
  const [count, setCount] = useState(10);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [summary, setSummary] = useState(null);

  async function run() {
    const n = Math.min(100, Math.max(1, Number(count) || 1));
    setBusy(true);
    setError('');
    try {
      const response = await fetch(`${BASE_URL}/simulate?count=${n}`, { method: 'POST' });
      if (!response.ok) {
        let detail = '';
        try { detail = (await response.json()).detail; } catch { /* ignore */ }
        throw new Error(detail || `Request failed (${response.status})`);
      }
      const body = await response.json();
      const list = body.alerts || [];
      const isRealAttack = (a) => Boolean(a.true_label) && a.true_label !== 'BENIGN';
      setSummary({
        total: list.length,
        realAttacks: list.filter(isRealAttack).length,
        caught: list.filter((a) => isRealAttack(a) && a.label === 'attack').length,
        falseAlarms: list.filter((a) => !isRealAttack(a) && a.label === 'attack').length,
        unusual: list.filter((a) => a.anomaly_detected).length,
      });
      if (onDone) await onDone();
    } catch (err) {
      setError(err.message || 'Simulation failed. Is the backend running?');
    } finally {
      setBusy(false);
    }
  }

  return <section className="panel">
    <div className="panel-heading"><div><span className="eyebrow">DEMO INGESTION</span><h2>Simulate traffic</h2></div><span className="sample-tag">REPLAY</span></div>
    <p className="muted small">Replays recorded CICIDS2017 Friday flows through the models, using made-up IP and MAC addresses. This is a demo, not live capture.</p>
    <div className="toolbar-actions">
      <label className="field"><span>Flows to replay (1-100)</span>
        <input type="number" min="1" max="100" value={count} onChange={(e) => setCount(e.target.value)} />
      </label>
      <button className="button subtle" type="button" disabled={busy} onClick={run}>{busy ? 'Running...' : 'Simulate flows'}</button>
    </div>
    {error && <div className="inline-error">{error}</div>}
    {summary && <div>
      <p className="muted small">Replayed {summary.total} flows. The dataset labels {summary.realAttacks} of them as attacks; SentryNet alerted on {summary.caught} of those.</p>
      <p className="muted small">False alarms among benign flows: {summary.falseAlarms}. Unusual-traffic flags (review only): {summary.unusual}.</p>
      <p className="muted small">Missed attacks are expected: PortScan and Bot were not in the training data.</p>
    </div>}
  </section>;
}