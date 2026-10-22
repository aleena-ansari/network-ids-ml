import { Link, NavLink, Route, Routes } from 'react-router-dom';
import Dashboard from './pages/Dashboard.jsx';
import AlertDetail from './pages/AlertDetail.jsx';

export default function App() {
  return <div className="app-shell"><header className="topbar"><Link to="/" className="brand"><span className="brand-mark">S</span><span>SENTRY<span className="brand-light">NET</span><small>NETWORK DEFENSE</small></span></Link>
    <nav><NavLink to="/" end>Operations</NavLink></nav><div className="header-right"><span className="system-indicator"><i /> ANALYST CONSOLE</span><span className="avatar">A</span></div></header>
    <main className="main-content"><Routes><Route path="/" element={<Dashboard />} /><Route path="/alerts/:id" element={<AlertDetail />} /><Route path="*" element={<section className="panel detail-error"><h1>Page not found</h1><Link to="/">Return to dashboard</Link></section>} /></Routes></main>
    <footer className="app-footer"><span>© SENTRYNET <span className="footer-dot">·</span> SOC OPERATIONS</span><span>LOCAL ENVIRONMENT <i /></span></footer>
  </div>;
}
