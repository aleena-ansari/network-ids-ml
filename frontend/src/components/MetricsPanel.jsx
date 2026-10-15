const metrics = [
  ['precision', 'Precision'], ['recall', 'Recall'], ['false_positive_rate', 'False positive'], ['auc', 'ROC AUC'],
];

export default function MetricsPanel({ data }) {
  return <section className="panel metrics-panel">
    <div className="panel-heading"><div><span className="eyebrow">MODEL TELEMETRY</span><h2>Performance</h2></div><span className="sample-tag">SAMPLE DATA</span></div>
    <div className="metric-grid">{metrics.map(([key, label]) => <div className="metric" key={key}>
      <span>{label}</span><strong>{(data[key] * 100).toFixed(1)}<small>%</small></strong>
      <div className="metric-track"><i style={{ width: `${data[key] * 100}%` }} /></div>
    </div>)}</div>
    <p className="muted small">{data.source}</p>
  </section>;
}
