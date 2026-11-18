import { Link } from 'react-router-dom';
import { RiskBadge, StatusBadge } from './Badges.jsx';

export default function AlertTable({ alerts, sort, onSort, loading }) {
  const heading = (label, key) => <button className="sort-button" onClick={() => onSort(key)}>{label}<span>{sort.key === key ? (sort.direction === 'asc' ? '\u2191' : '\u2193') : '\u2195'}</span></button>;
  if (loading && alerts.length === 0) return <div className="empty-state"><span className="pulse-dot" /> Connecting to alert stream&hellip;</div>;
  if (!alerts.length) return <div className="empty-state"><span className="empty-icon">&#8961;</span><strong>No alerts in this view</strong><span>Use Simulate traffic to replay flows through the models.</span></div>;
  return <div className="table-scroll"><table><thead><tr>
    <th>{heading('Event time', 'created_at')}</th><th>Source &rarr; destination</th><th>MAC address</th><th>Detection</th><th>{heading('Risk score', 'risk_score')}</th><th>Status</th><th />
  </tr></thead><tbody>{alerts.map((alert) => <tr key={alert.id} className={alert.fresh ? 'fresh-row' : ''}>
    <td className="mono timestamp">{new Date(alert.created_at).toLocaleString()}</td>
    <td><div className="ip-pair"><span className="mono">{alert.src_ip}</span><span className="arrow">&rarr;</span><span className="mono">{alert.dst_ip}</span></div></td>
    <td className="mono muted" title={alert.mac_note || ''}>{alert.mac_address || '\u2014'}</td>
    <td><div className="detection"><span className={`label-dot ${alert.label}`} /><span className={alert.label === 'attack' ? 'attack-text' : 'normal-text'}>{alert.label}</span>
      {alert.label === 'attack' && <span className="category-tag">family unknown</span>}
      {alert.anomaly_detected && <span className="category-tag" title="Isolation Forest flag: review, not a confirmed attack">unusual traffic</span>}
      {alert.origin === 'simulated' && <span className="category-tag">simulated</span>}
    </div></td>
    <td><RiskBadge score={alert.risk_score} /></td><td><StatusBadge status={alert.status} /></td>
    <td><Link className="view-link" to={`/alerts/${alert.id}`}>View <span>&#8599;</span></Link></td>
  </tr>)}</tbody></table></div>;
}