import { StoreProvider, useStore } from './lib/store';
import { Shell } from './components/Shell';
import Dashboard from './pages/Dashboard';
import Explorer from './pages/Explorer';
import Alerts from './pages/Alerts';
import Incidents from './pages/Incidents';
import Cases from './pages/Cases';
import Playbooks from './pages/Playbooks';
import Vulnerabilities from './pages/Vulnerabilities';
import Assets from './pages/Assets';
import Portal from './pages/Portal';
import Login from './pages/Login';
import Correlation from './pages/Correlation';
import Investigation from './pages/Investigation';
import Connectors from './pages/Connectors';
import Sla from './pages/Sla';
import Admin from './pages/Admin';
import Ingestion from './pages/Ingestion';
import { ReportsPage } from './pages/AuditReports';
import Audit from './pages/Audit';
import { Icon } from './components/ui';

function Router() {
  const { s } = useStore();
  switch (s.route) {
    case 'explorer': return <Explorer />;
    case 'ingestion': return <Ingestion />;
    case 'alerts': return <Alerts />;
    case 'correlation': return <Correlation />;
    case 'investigation': return <Investigation />;
    case 'connectors': return <Connectors />;
    case 'sla': return <Sla />;
    case 'admin': return <Admin />;
    case 'incidents': return <Incidents />;
    case 'cases': return <Cases />;
    case 'playbooks': return <Playbooks />;
    case 'vulns': return <Vulnerabilities />;
    case 'assets': return <Assets />;
    case 'reports': return <ReportsPage />;
    case 'audit': return <Audit />;
    case 'portal': return <Portal />;
    default: return <Dashboard />;
  }
}

function Gate() {
  const { s } = useStore();
  if (s.backend === 'checking') {
    return (
      <div className="relative z-10 flex h-full items-center justify-center">
        <div className="ambient" />
        <div className="a-up flex flex-col items-center gap-4">
          <div className="relative flex h-14 w-14 items-center justify-center rounded-xl border border-teal/40 bg-teal/10 text-teal">
            <Icon name="shieldCheck" size={28} strokeWidth={1.8} />
            <svg className="sweep absolute inset-0" viewBox="0 0 56 56">
              <circle cx="28" cy="28" r="25" fill="none" stroke="url(#swg2)" strokeWidth="1.5" />
              <defs>
                <linearGradient id="swg2" x1="0" y1="0" x2="1" y2="0">
                  <stop offset="0%" stopColor="#2fd6a5" stopOpacity="0" />
                  <stop offset="100%" stopColor="#2fd6a5" stopOpacity="0.9" />
                </linearGradient>
              </defs>
            </svg>
          </div>
          <div className="font-display text-lg font-bold tracking-[0.2em] text-ink">SOPIR</div>
          <div className="font-mono text-[11px] text-faint">estabelecendo canal seguro…</div>
        </div>
      </div>
    );
  }
  if (!s.user) return <Login />;
  return (
    <Shell>
      <Router />
    </Shell>
  );
}

export default function App() {
  return (
    <StoreProvider>
      <Gate />
    </StoreProvider>
  );
}
