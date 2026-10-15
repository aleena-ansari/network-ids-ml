export default function StatCard({ label, value, note, tone = '' }) {
  return <div className={`stat-card ${tone}`}><span className="eyebrow">{label}</span><strong>{value}</strong><span className="muted small">{note}</span></div>;
}
