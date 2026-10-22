import { useRef, useState } from 'react';
import { featureFields, parseCsvRow, sampleRows } from '../data/features.js';

export default function TrafficForm({ onSubmit, busy }) {
  const [form, setForm] = useState({ src_ip: '192.168.1.15', dst_ip: '10.0.0.5', ...sampleRows[0] });
  const [message, setMessage] = useState('');
  const [source, setSource] = useState('Manual entry');
  const inputRef = useRef(null);

  function setFields(values, label) {
    setForm((current) => ({ ...current, ...values }));
    setSource(label);
    setMessage('');
  }

  async function randomSample() {
    try {
      const response = await fetch('/data/test.csv');
      if (!response.ok) throw new Error('NSL-KDD test data is unavailable.');
      const lines = (await response.text()).split(/\r?\n/).filter(Boolean);
      const row = parseCsvRow(lines[Math.floor(Math.random() * lines.length)]);
      setFields(row, 'Random row from data/test.csv');
    } catch {
      const row = sampleRows[Math.floor(Math.random() * sampleRows.length)];
      setFields({ ...row }, 'Built-in demo sample (CSV unavailable)');
    }
  }

  async function loadCsv(file) {
    if (!file) return;
    try {
      const content = await file.text();
      const lines = content.split(/\r?\n/).filter(Boolean);
      if (lines.length < 2) throw new Error('CSV needs a header and at least one row.');
      const hasHeader = lines[0].split(',').some((v) => v.trim() === 'duration');
      const row = parseCsvRow(lines[hasHeader ? 1 : 0]);
      setFields({ ...row }, `Loaded ${file.name}`);
    } catch (error) { setMessage(error.message || 'Could not read CSV.'); }
  }

  async function submit(event) {
    event.preventDefault();
    setMessage('');
    try {
      const result = await onSubmit(form);
      setMessage(`Prediction saved as alert #${result.id}.`);
    } catch (error) { setMessage(error.message || 'Prediction failed. Check that the backend is running.'); }
  }

  return <details className="panel traffic-panel">
    <summary><div><span className="eyebrow">INGESTION</span><h2>Analyze traffic</h2></div><span className="summary-meta">41 NSL-KDD features <b>＋</b></span></summary>
    <div className="traffic-toolbar"><p className="muted">Submit a traffic record to the model and add its prediction to the live alert feed.</p>
      <div className="toolbar-actions"><button className="button subtle" type="button" onClick={randomSample}>↻ Random test row</button>
        <button className="button subtle" type="button" onClick={() => inputRef.current?.click()}>↑ Load CSV</button>
        <input ref={inputRef} type="file" accept=".csv,text/csv" hidden onChange={(e) => loadCsv(e.target.files?.[0])} />
      </div>
    </div>
    <form onSubmit={submit}>
      <div className="form-grid identity-grid">
        {[['src_ip', 'Source IP'], ['dst_ip', 'Destination IP']].map(([key, label]) => <label className="field" key={key}>{label}
          <input required value={form[key] || ''} onChange={(e) => setForm({ ...form, [key]: e.target.value })} />
        </label>)}
      </div>
      <div className="form-grid feature-grid">{featureFields.map(([key, type]) => <label className="field" key={key}>{key}
        <input type={type === 'number' ? 'number' : 'text'} step={type === 'number' ? 'any' : undefined}
          value={form[key] ?? (type === 'number' ? 0 : '')} onChange={(e) => setForm({ ...form, [key]: type === 'number' ? Number(e.target.value) : e.target.value })} />
      </label>)}</div>
      <div className="form-footer"><span className="muted small">{source}</span><div className="form-response" role="status">{message}</div>
        <button className="button primary" disabled={busy}>{busy ? 'Analyzing…' : 'Run prediction'} <span>↗</span></button>
      </div>
    </form>
  </details>;
}
