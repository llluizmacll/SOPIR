import { useEffect, useMemo, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import { useNow, useStore, fmtClock, permsFor } from '../lib/store';
import type { Route } from '../lib/store';
import { routesForPerms } from '../data/perms';
import { Avatar, Icon, Pill, ToastHost } from './ui';
import type { IconName } from './icons';
import AccountDrawer from './AccountDrawer';

const NAV: { group: string; items: { route: Route; label: string; icon: IconName }[] }[] = [
  {
    group: 'Operação',
    items: [
      { route: 'dashboard', label: 'Visão Geral', icon: 'dashboard' },
      { route: 'explorer', label: 'Event Explorer', icon: 'radar' },
      { route: 'ingestion', label: 'Centro de Ingestão', icon: 'database' },
      { route: 'alerts', label: 'Central de Alertas', icon: 'bell' },
      { route: 'correlation', label: 'Correlação', icon: 'crosshair' },
      { route: 'investigation', label: 'Investigação', icon: 'network' },
      { route: 'incidents', label: 'Incidentes', icon: 'flame' },
      { route: 'cases', label: 'Cases', icon: 'folder' },
    ],
  },
  { group: 'Resposta', items: [{ route: 'playbooks', label: 'Playbooks & SOAR', icon: 'zap' }] },
  {
    group: 'Postura',
    items: [
      { route: 'vulns', label: 'Vulnerabilidades', icon: 'bug' },
      { route: 'assets', label: 'Ativos', icon: 'server' },
    ],
  },
  { group: 'Integrações', items: [{ route: 'connectors', label: 'Connectors', icon: 'layers' }] },
  {
    group: 'Gestão',
    items: [
      { route: 'sla', label: 'SLA & Performance', icon: 'clock' },
      { route: 'reports', label: 'Relatórios', icon: 'file' },
      { route: 'audit', label: 'Auditoria', icon: 'history' },
    ],
  },
  { group: 'Administração', items: [{ route: 'admin', label: 'Administração', icon: 'users' }] },
  { group: 'Cliente', items: [{ route: 'portal', label: 'Portal do Cliente', icon: 'globe' }] },
];

// null = todas as rotas; perfis customizados caem em routesForPerms(permsFor(role))
const ROLE_ROUTES: Record<string, Route[] | null> = {
  Admin: null,
  'SOC Manager': ['dashboard', 'explorer', 'alerts', 'correlation', 'investigation', 'incidents', 'cases', 'playbooks', 'vulns', 'assets', 'connectors', 'sla', 'reports', 'audit', 'portal'],
  'SOC Analyst': ['dashboard', 'explorer', 'ingestion', 'alerts', 'correlation', 'investigation', 'incidents', 'cases', 'playbooks', 'assets', 'connectors', 'sla', 'portal'],
  'Security Engineer': ['dashboard', 'vulns', 'assets', 'investigation', 'reports', 'audit', 'portal'],
  Customer: ['portal'],
};

const PAGE_TITLES: Record<Route, { title: string; sub: string }> = {
  dashboard: { title: 'Centro de Operações', sub: 'Detecção consolidada em tempo real' },
  explorer: { title: 'Event Explorer', sub: 'Pesquisa e correlação sobre o modelo normalizado' },
  ingestion: { title: 'Centro de Ingestão', sub: 'Pipeline de eventos — coleta, normalização, dedup e correlação' },
  alerts: { title: 'Central de Alertas', sub: 'Triagem, classificação e escalonamento' },
  correlation: { title: 'Detection & Correlation', sub: 'Regras, risco e agrupamento — alertas por padrão' },
  investigation: { title: 'Investigation Graph', sub: 'IP → usuário → endpoint → processo → IOC → incidente' },
  connectors: { title: 'Connectors', sub: 'Integrações por cliente — Wazuh, FortiSIEM e push' },
  sla: { title: 'SLA & Performance', sub: 'Conformidade, MTTR e políticas por severidade' },
  admin: { title: 'Administração', sub: 'Usuários, perfis de acesso e clientes (tenants)' },
  incidents: { title: 'Incident Response', sub: 'Ciclo de vida completo do incidente' },
  cases: { title: 'Case Management', sub: 'O centro da operação do SOC' },
  playbooks: { title: 'Response Engine', sub: 'Automação com aprovação e auditoria' },
  vulns: { title: 'Vulnerability Management', sub: 'Findings, risco e remediação' },
  assets: { title: 'Asset Management', sub: 'Inventário correlacionado à operação' },
  reports: { title: 'Relatórios', sub: 'Geração e exportação executiva' },
  audit: { title: 'Auditoria', sub: 'Trilha imutável de ações' },
  portal: { title: 'Portal do Cliente', sub: 'Postura de segurança do ambiente' },
};

const DIAS = ['dom', 'seg', 'ter', 'qua', 'qui', 'sex', 'sáb'];
const MESES = ['jan', 'fev', 'mar', 'abr', 'mai', 'jun', 'jul', 'ago', 'set', 'out', 'nov', 'dez'];

function GlobalSearch() {
  const { s, nav } = useStore();
  const [q, setQ] = useState('');
  const boxRef = useRef<HTMLDivElement>(null);

  const results = useMemo(() => {
    const query = q.trim().toLowerCase();
    if (query.length < 2) return null;
    const match = (...fields: string[]) => fields.some(f => f.toLowerCase().includes(query));
    return {
      alerts: s.alerts.filter(a => match(a.id, a.title, a.host, a.srcIp, a.rule)).slice(0, 3),
      incidents: s.incidents.filter(i => match(i.id, i.title, i.asset ?? '')).slice(0, 3),
      vulns: s.vulns.filter(v => match(v.cve, v.title, v.asset)).slice(0, 3),
      assets: s.assets.filter(a => match(a.name, a.ip, a.os)).slice(0, 3),
    };
  }, [q, s.alerts, s.incidents, s.vulns, s.assets]);

  const total = results ? results.alerts.length + results.incidents.length + results.vulns.length + results.assets.length : 0;
  const go = (route: Route, type: string, id: string) => { nav(route, { type, id }); setQ(''); };

  return (
    <div className="relative hidden md:block w-[300px]" ref={boxRef}>
      <span className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-faint"><Icon name="search" size={14} /></span>
      <input
        className="input w-full pl-9 pr-14 font-mono text-[12px]"
        placeholder="Buscar em toda a plataforma…"
        value={q}
        onChange={e => setQ(e.target.value)}
      />
      <span className="absolute right-2.5 top-1/2 -translate-y-1/2 kbd">global</span>
      {q.trim().length >= 2 && (
        <>
          <div className="fixed inset-0 z-40" onClick={() => setQ('')} />
          <div className="a-pop absolute left-0 right-0 top-[calc(100%+6px)] z-50 panel max-h-[420px] overflow-y-auto shadow-[0_24px_60px_rgba(0,0,0,.55)]">
            {total === 0 && <div className="px-4 py-5 text-[12px] text-faint">Nenhum resultado para <span className="font-mono text-sub">"{q}"</span></div>}
            {results && results.alerts.length > 0 && (
              <div className="p-1.5">
                <div className="lbl px-2.5 py-1.5">Alertas</div>
                {results.alerts.map(a => (
                  <button key={a.id} className="flex w-full items-center gap-2.5 rounded-md px-2.5 py-2 text-left hover:bg-raise transition-colors" onClick={() => go('alerts', 'alert', a.id)}>
                    <span className="text-bell text-med"><Icon name="bell" size={13} /></span>
                    <span className="font-mono text-[11px] text-faint">{a.id}</span>
                    <span className="truncate text-[12px] text-ink/90">{a.title}</span>
                  </button>
                ))}
              </div>
            )}
            {results && results.incidents.length > 0 && (
              <div className="p-1.5 border-t border-line">
                <div className="lbl px-2.5 py-1.5">Incidentes</div>
                {results.incidents.map(i => (
                  <button key={i.id} className="flex w-full items-center gap-2.5 rounded-md px-2.5 py-2 text-left hover:bg-raise transition-colors" onClick={() => go('incidents', 'incident', i.id)}>
                    <span className="text-crit"><Icon name="flame" size={13} /></span>
                    <span className="font-mono text-[11px] text-faint">{i.id}</span>
                    <span className="truncate text-[12px] text-ink/90">{i.title}</span>
                  </button>
                ))}
              </div>
            )}
            {results && results.vulns.length > 0 && (
              <div className="p-1.5 border-t border-line">
                <div className="lbl px-2.5 py-1.5">Vulnerabilidades</div>
                {results.vulns.map(v => (
                  <button key={v.id} className="flex w-full items-center gap-2.5 rounded-md px-2.5 py-2 text-left hover:bg-raise transition-colors" onClick={() => go('vulns', 'vuln', v.id)}>
                    <span className="text-high"><Icon name="bug" size={13} /></span>
                    <span className="font-mono text-[11px] text-faint">{v.cve}</span>
                    <span className="truncate text-[12px] text-ink/90">{v.title}</span>
                  </button>
                ))}
              </div>
            )}
            {results && results.assets.length > 0 && (
              <div className="p-1.5 border-t border-line">
                <div className="lbl px-2.5 py-1.5">Ativos</div>
                {results.assets.map(a => (
                  <button key={a.id} className="flex w-full items-center gap-2.5 rounded-md px-2.5 py-2 text-left hover:bg-raise transition-colors" onClick={() => go('assets', 'asset', a.id)}>
                    <span className="text-cyan"><Icon name="server" size={13} /></span>
                    <span className="font-mono text-[11px] text-faint">{a.ip}</span>
                    <span className="truncate text-[12px] text-ink/90">{a.name}</span>
                  </button>
                ))}
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}

export function Shell({ children }: { children: ReactNode }) {
  const { s, nav, setTenant, setEnv, tenantEnvs, me, logout, ingest, backend } = useStore();
  const [userMenu, setUserMenu] = useState(false);
  const [accountOpen, setAccountOpen] = useState(false);
  const now = useNow(1000);
  const dt = new Date(now);
  // perfis embutidos usam a lista fixa; customizados derivam das permissões
  const allowed = s.role in ROLE_ROUTES ? ROLE_ROUTES[s.role] : (routesForPerms(permsFor(s.role)) as Route[]);

  // motor de fluxo contínuo — só em modo demo (online, o backend gera o fluxo)
  const ingestRef = useRef(ingest);
  ingestRef.current = ingest;
  useEffect(() => {
    if (s.paused || s.backend !== 'demo') return;
    const t = setInterval(() => ingestRef.current(), 2700);
    return () => clearInterval(t);
  }, [s.paused, s.backend]);

  const visibleNav = NAV.map(g => ({ ...g, items: g.items.filter(i => !allowed || allowed.includes(i.route)) }))
    .filter(g => g.items.length > 0);

  const connectorRows: { name: string; on: boolean; right: string; err: string | null }[] = s.connectors.length
    ? [
        ...s.connectors.map(c => ({
          name: c.name,
          on: c.configured || c.status === 'coletando',
          right: !c.configured ? 'não config.' : c.status === 'erro' ? 'erro' : `${c.collected} ev`,
          err: c.status === 'erro' ? (c.lastError ?? 'falha na coleta') : null,
        })),
        { name: 'MS Defender', on: false, right: 'planejado', err: null },
        { name: 'CrowdStrike', on: false, right: 'planejado', err: null },
      ]
    : [
        { name: 'Wazuh', on: true, right: 'simulação', err: null },
        { name: 'FortiSIEM', on: true, right: 'simulação', err: null },
        { name: 'MS Defender', on: false, right: 'planejado', err: null },
        { name: 'CrowdStrike', on: false, right: 'planejado', err: null },
      ];

  return (
    <div className="relative z-10 flex h-full">
      <div className="ambient" />

      {/* ── sidebar ── */}
      <aside className="flex w-[228px] shrink-0 flex-col border-r border-line bg-[#0a1120]/85">
        <div className="flex items-center gap-3 px-4 py-[18px]">
          <div className="relative flex h-9 w-9 items-center justify-center rounded-lg border border-teal/40 bg-teal/10 text-teal">
            <Icon name="shieldCheck" size={19} strokeWidth={2} />
            <svg className="sweep absolute inset-0" viewBox="0 0 36 36">
              <circle cx="18" cy="18" r="16" fill="none" stroke="url(#swg)" strokeWidth="1.2" />
              <defs>
                <linearGradient id="swg" x1="0" y1="0" x2="1" y2="0">
                  <stop offset="0%" stopColor="#2fd6a5" stopOpacity="0" />
                  <stop offset="100%" stopColor="#2fd6a5" stopOpacity="0.8" />
                </linearGradient>
              </defs>
            </svg>
          </div>
          <div>
            <div className="font-display text-[17px] font-bold leading-none tracking-[0.08em] text-ink">SOPIR</div>
            <div className="mt-1 text-[9px] font-mono uppercase tracking-[0.14em] text-faint">SecOps · IR Platform</div>
          </div>
        </div>

        <nav className="flex-1 overflow-y-auto px-3 pb-3">
          {visibleNav.map(g => (
            <div key={g.group} className="mt-3 first:mt-0">
              <div className="lbl px-3 pb-1.5 pt-1">{g.group}</div>
              <div className="flex flex-col gap-0.5">
                {g.items.map(i => (
                  <button key={i.route} className={`navlink ${s.route === i.route ? 'on' : ''}`} onClick={() => nav(i.route)}>
                    <Icon name={i.icon} size={15} />
                    {i.label}
                    {i.route === 'alerts' && (
                      <span className="ml-auto rounded bg-crit/15 px-1.5 py-0.5 font-mono text-[10px] font-semibold text-crit">
                        {s.alerts.filter(a => a.status === 'novo' && (s.tenant === 'all' || a.tenant === s.tenant)).length}
                      </span>
                    )}
                  </button>
                ))}
              </div>
            </div>
          ))}
        </nav>

        <div className="border-t border-line px-4 py-3.5">
          <div className="lbl mb-2.5">Connectors</div>
          {connectorRows.map(c => (
            <div key={c.name} className="flex items-center gap-2 py-[3px]" title={c.err ?? undefined}>
              <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${c.err ? 'bg-crit dot-crit' : c.on ? 'bg-teal dot-live' : 'bg-faint/40'}`} />
              <span className={`text-[11.5px] ${c.on ? 'text-sub' : 'text-faint/60'}`}>{c.name}</span>
              <span className={`ml-auto font-mono text-[10px] ${c.err ? 'text-crit' : 'text-faint'}`}>{c.right}</span>
            </div>
          ))}
          <div className="mt-3 rounded-md border border-line bg-panel px-2.5 py-2 text-[10px] font-mono text-faint">
            {backend === 'online' ? 'sopir-api · coletores ativos' : 'v0.9.2 · normalização ativa'}
          </div>
        </div>
      </aside>

      {/* ── área principal ── */}
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex h-[58px] shrink-0 items-center gap-4 border-b border-line bg-[#0a1120]/70 px-5">
          <div className="min-w-0">
            <h1 className="font-display text-[15px] font-semibold leading-tight text-ink">{PAGE_TITLES[s.route].title}</h1>
            <p className="text-[10.5px] text-faint leading-tight truncate">{PAGE_TITLES[s.route].sub}</p>
          </div>

          <div className="ml-auto flex items-center gap-3">
            <GlobalSearch />

            <div className="hidden lg:flex items-center gap-2 rounded-lg border border-line bg-panel px-3 py-1.5">
              <Icon name="globe" size={13} className="text-faint" />
              <select className="bg-transparent text-[12px] text-ink outline-none cursor-pointer max-w-[150px]"
                value={s.tenant} onChange={e => setTenant(e.target.value)} title="Tenant (multi-cliente)">
                {s.tenants.map(t => <option key={t.id} value={t.id} className="bg-panel">{t.name}</option>)}
                <option value="all" className="bg-panel">MSSP — todos</option>
              </select>
            </div>

            {s.tenant !== 'all' && tenantEnvs.length > 0 && (
              <div className="hidden xl:flex items-center gap-2 rounded-lg border border-line bg-panel px-3 py-1.5"
                title="Ambiente (isolamento lógico dentro do cliente)">
                <Icon name="layers" size={13} className="text-teal/70" />
                <select className="bg-transparent text-[12px] text-ink outline-none cursor-pointer max-w-[140px]"
                  value={s.env} onChange={e => setEnv(e.target.value)}>
                  <option value="all" className="bg-panel">Todos os ambientes</option>
                  {tenantEnvs.map(e => (
                    <option key={e.id} value={e.id} className="bg-panel">
                      {e.name}{e.kind === 'producao' ? '' : ` · ${e.kind}`}
                    </option>
                  ))}
                </select>
              </div>
            )}

            <div
              className={`hidden md:flex items-center gap-2 rounded-lg border px-3 py-1.5 font-mono text-[11px] ${
                backend === 'online' ? 'border-teal/40 text-teal' : backend === 'checking' ? 'border-line text-faint' : 'border-high/40 text-high'}`}
              title={backend === 'online' ? 'Conectado à sopir-api — dados persistidos em PostgreSQL' : backend === 'checking' ? 'Tentando conectar à sopir-api…' : 'API indisponível — simulação local ativa'}>
              <span className={`h-1.5 w-1.5 rounded-full ${backend === 'online' ? 'bg-teal dot-live' : backend === 'checking' ? 'bg-faint blink' : 'bg-high'}`} />
              {backend === 'online' ? 'sopir-api · PostgreSQL' : backend === 'checking' ? 'conectando…' : 'modo demonstração'}
            </div>

            <div className={`hidden sm:flex items-center gap-2 rounded-lg border px-3 py-1.5 font-mono text-[12px] tabular-nums ${s.paused ? 'border-high/40 text-high' : 'border-line text-sub'}`}>
              <span className={`h-1.5 w-1.5 rounded-full ${s.paused ? 'bg-high' : 'bg-teal dot-live'}`} />
              {fmtClock(now)}
            </div>

            <div className="relative flex items-center">
              <button onClick={() => setUserMenu(v => !v)}
                className="flex items-center gap-2.5 rounded-lg border border-line bg-panel py-1 pl-1 pr-2.5 transition-colors hover:border-line2">
                <Avatar name={me} size={30} />
                <span className="hidden min-w-0 text-left sm:block">
                  <span className="block max-w-[130px] truncate text-[12px] font-semibold leading-tight text-ink">{me}</span>
                  <span className="block text-[9.5px] font-mono uppercase tracking-wide leading-tight text-teal">{s.role}</span>
                </span>
                <Icon name="chevronDown" size={12} className="text-faint" />
              </button>

              {userMenu && (
                <>
                  <div className="fixed inset-0 z-40" onClick={() => setUserMenu(false)} />
                  <div className="a-pop absolute right-0 top-[calc(100%+8px)] z-50 w-[240px] panel overflow-hidden shadow-[0_24px_60px_rgba(0,0,0,.55)]">
                    <div className="border-b border-line px-3.5 py-3">
                      <div className="truncate text-[12.5px] font-semibold text-ink">{me}</div>
                      <div className="truncate font-mono text-[10px] text-faint">@{s.user?.username}</div>
                    </div>
                    <div className="p-1.5">
                      <button className="flex w-full items-center gap-2.5 rounded-md px-2.5 py-2 text-left text-[12.5px] text-sub transition-colors hover:bg-raise hover:text-ink"
                        onClick={() => { setUserMenu(false); setAccountOpen(true); }}>
                        <Icon name="key" size={14} /> Minha conta
                        <span className="ml-auto flex items-center gap-1">
                          {s.user?.mfaEnabled
                            ? <Pill label="MFA on" color="#2fd6a5" sm />
                            : <Pill label="MFA off" color="#8fa3c8" sm />}
                        </span>
                      </button>
                      <button className="flex w-full items-center gap-2.5 rounded-md px-2.5 py-2 text-left text-[12.5px] text-crit transition-colors hover:bg-crit/10"
                        onClick={() => { setUserMenu(false); logout(); }}>
                        <Icon name="power" size={14} /> Encerrar sessão
                      </button>
                    </div>
                  </div>
                </>
              )}
            </div>
          </div>
        </header>

        <main className="min-h-0 flex-1 overflow-hidden">
          <div className="dt-hidden hidden">{dt.getDate()} {MESES[dt.getMonth()]} · {DIAS[dt.getDay()]}</div>
          {children}
        </main>
      </div>

      <AccountDrawer open={accountOpen} onClose={() => setAccountOpen(false)} />
      <ToastHost />
    </div>
  );
}
