import { Link } from 'react-router-dom';
import { RiskBadge, StatusBadge } from './Badges.jsx';

export default function AlertTable({ alerts, sort, onSort, loading }) {
  const heading = (label, key) => <button className="sort-button" onClick={() => onSort(key)}>{label}<span>{sort.key === key ? (sort.direction === 'asc' ? '↑' : '↓') : '↕'}</span></button>;
  if (loading && alerts.length === 0) return <div className="empty-state"><span className="pulse-dot" /> Connecting to alert stream…</div>;
  if (!alerts.length) return <div className="empty-state"><span className="empty-icon">⌁</span><strong>No alerts in this view</strong><span>New detections will appear here as traffic is analyzed.</span></div>;
  return <div className="table-scroll"><table><thead><tr>
    <th>{heading('Event time', 'created_at')}</th><th>Source → destination</th><th>MAC address</th><th>Detection</th><th>{heading('Risk score', 'risk_score')}</th><th>Status</th><th />
  </tr></thead><tbody>{alerts.map((alert) => <tr key={alert.id} className={alert.fresh ? 'fresh-row' : ''}>
    <td className="mono timestamp">{new Date(alert.created_at).toLocaleString()}</td>
    <td><div className="ip-pair"><span className="mono">{alert.src_ip}</span><span className="arrow">→</span><span className="mono">{alert.dst_ip}</span></div></td>
    <td className="mono muted">{alert.mac_address || '—'}</td>
    <td><div className="detection"><span className={`label-dot ${alert.label}`} /><span className={alert.label === 'attack' ? 'attack-text' : 'normal-text'}>{alert.label}</span><span className="category-tag">{alert.category}</span></div></td>
    <td><RiskBadge score={alert.risk_score} /></td><td><StatusBadge status={alert.status} /></td>
    <td><Link className="view-link" to={`/alerts/${alert.id}`}>View <span>↗</span></Link></td>
  </tr>)}</tbody></table></div>;
}
