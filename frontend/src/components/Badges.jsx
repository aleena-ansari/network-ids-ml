export function RiskBadge({ score = 0 }) {
  const level = score > 70 ? 'high' : score >= 30 ? 'medium' : 'low';
  return <span className={`risk-badge ${level}`}>{Number(score).toFixed(1)}<small> risk</small></span>;
}

export function StatusBadge({ status = 'new' }) {
  const labels = { false_positive: 'False positive', reviewed: 'Reviewed', escalated: 'Escalated', new: 'New' };
  return <span className={`status-badge ${status}`}>{labels[status] || status}</span>;
}
