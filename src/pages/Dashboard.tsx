import { useMemo } from 'react';
import { fmtDT, securityScore, slaInfo, timeAgo, useNow, useStore } from '../lib/store';
import type { AlertStatus } from '../data/mock';
import { ALERT_STATUS_META, INC_STATUS_META, SEV_META, SEV_ORDER } from '../data/mock';
import { AreaChart, Donut, Gauge, HBars, SLABar, Spark } from '../components/charts';
import { Avatar, Icon, Panel, Pill, SevBadge, SLAChip } from '../components/ui';
import type { IconName } from '../components/icons';

const AUDIT_ICON: Record<string, IconName> = { auth: 'lock', triage: 'filter', response: 'zap', data: 'layers', system: 'cpu' };

function Stat({ label, value, icon, color = '#e8eefb', sub, spark, delay = 0 }: {
  label: string; value: string; icon: IconName; color?: string; sub: React.ReactNode; spark?: number[]; delay?: number;
}) {
  return (
    <div className="panel a-up flex flex-col justify-between p-4" style={{ animationDelay: `${delay}ms` }}>
      <div className="flex items-center justify-between">
        <span className="lbl">{label}</span>
        <span style={{ color: color + 'aa' }}><Icon name={icon} size={15} /></span>
      </div>
      <div className="mt-2 font-mono text-[27px] font-bold leading-none tabular-nums" style={{ color }}>{value}</div>
      <div className="mt-2 flex items-end justify-between gap-2">
        <span className="text-[11px] text-faint">{sub}</span>
        {spark && <Spark data={spark} color={color} w={72} h={24} />}
      </div>
    </div>
  );
}

export default function Dashboard() {
  const { s, scope, nav, togglePause, tenantName } = useStore();
  const now = useNow(1000);

  const events = useMemo(() => scope(s.events), [s.events, s.tenant]); // eslint-disable-line react-hooks/exhaustive-deps
  const alerts = useMemo(() => scope(s.alerts), [s.alerts, s.tenant]); // eslint-disable-line react-hooks/exhaustive-deps
  const incidents = useMemo(() => scope(s.incidents), [s.incidents, s.tenant]); // eslint-disable-line react-hooks/exhaustive-deps
  const vulns = useMemo(() => scope(s.vulns), [s.vulns, s.tenant]); // eslint-disable-line react-hooks/exhaustive-deps
  const assets = useMemo(() => scope(s.assets), [s.assets, s.tenant]); // eslint-disable-line react-hooks/exhaustive-deps

  const { score, factors } = useMemo(
    () => securityScore({ alerts, incidents, vulns, assets }),
    [alerts, incidents, vulns, assets],
  );

  const series24h = useMemo(() => {
    const buckets = new Array(24).fill(0);
    const hourMs = 3_600_000;
    for (const ev of events) {
      const diff = now - ev.ts;
      if (diff < 0 || diff > 24 * hourMs) continue;
      buckets[23 - Math.floor(diff / hourMs)] += 1;
    }
    return buckets;
  }, [events, now]);

  const openAlerts = alerts.filter(a => !['fechado', 'falso_positivo', 'escalado'].includes(a.status));
  const newAlerts = alerts.filter(a => a.status === 'novo');
  const activeInc = incidents.filter(i => !['resolvido', 'fechado'].includes(i.status));
  const openVulns = vulns.filter(v => !['resolvida', 'aceita'].includes(v.status));
  const slaOk = incidents.filter(i => ['resolvido', 'fechado'].includes(i.status));
  const slaPct = incidents.length ? Math.round((slaOk.length / incidents.length) * 100) : 100;

  const sevBars = SEV_ORDER.filter(sv => sv !== 'info').map(sv => ({
    label: SEV_META[sv].label, value: openAlerts.filter(a => a.severity === sv).length, color: SEV_META[sv].color,
  }));

  const statusSegs = (['novo', 'reconhecido', 'investigando', 'escalado', 'fechado'] as AlertStatus[]).map(st => ({
    value: alerts.filter(a => (st === 'fechado' ? ['fechado', 'falso_positivo'].includes(a.status) : a.status === st)).length,
    color: ALERT_STATUS_META[st].color,
  }));

  const topHosts = useMemo(() => {
    const map = new Map<string, number>();
    events.forEach(e => map.set(e.host, (map.get(e.host) ?? 0) + 1));
    return [...map.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5);
  }, [events]);

  const iocCount = useMemo(() => {
    const map = new Map<string, number>();
    incidents.forEach(i => i.iocs.forEach(ioc => map.set(ioc, (map.get(ioc) ?? 0) + 1)));
    alerts.forEach(a => { if (a.srcIp !== '—' && /\d+\.\d+\.\d+\.\d+/.test(a.srcIp) && !a.srcIp.startsWith('10.') && !a.srcIp.startsWith('172.')) map.set(a.srcIp, (map.get(a.srcIp) ?? 0) + 1); });
    return [...map.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5);
  }, [incidents, alerts]);

  const epsWazuh = s.eps?.Wazuh ?? events.filter(e => e.source === 'Wazuh' && now - e.ts < 60_000).length;
  const epsForti = s.eps?.FortiSIEM ?? events.filter(e => e.source === 'FortiSIEM' && now - e.ts < 60_000).length;

  const watchlist = activeInc
    .map(i => ({ i, sla: slaInfo(i, now) }))
    .sort((a, b) => a.sla.left - b.sla.left)
    .slice(0, 4);

  const dtFmt = new Date(now);
  const MESES = ['jan', 'fev', 'mar', 'abr', 'mai', 'jun', 'jul', 'ago', 'set', 'out', 'nov', 'dez'];

  return (
    <div className="h-full overflow-y-auto">
      <div className="mx-auto flex max-w-[1560px] flex-col gap-4 p-5">

        {/* cabeçalho */}
        <div className="a-up flex flex-wrap items-end justify-between gap-3">
          <div>
            <div className="lbl mb-1 flex items-center gap-2">
              <span className="inline-block h-1.5 w-1.5 rounded-full bg-teal dot-live" />
              operação em tempo real · {tenantName}
            </div>
            <h2 className="font-display text-[22px] font-bold tracking-tight text-ink">
              Centro de Operações de Segurança
              <span className="ml-3 align-middle font-mono text-[11px] font-medium text-faint">
                {String(dtFmt.getDate()).padStart(2, '0')} {MESES[dtFmt.getMonth()]} {dtFmt.getFullYear()}
              </span>
            </h2>
          </div>
          <div className="flex items-center gap-2">
            <button className={`btn ${s.paused ? 'btn-primary' : ''}`} onClick={togglePause}>
              <Icon name={s.paused ? 'play' : 'pause'} size={13} />
              {s.paused ? 'Retomar fluxo' : 'Pausar fluxo'}
            </button>
            <button className="btn" onClick={() => nav('explorer')}>
              <Icon name="radar" size={13} /> Explorer
            </button>
            <button className="btn btn-primary" onClick={() => nav('incidents', { type: 'new', id: '' })}>
              <Icon name="plus" size={13} /> Novo incidente
            </button>
          </div>
        </div>

        {/* KPIs */}
        <div className="grid grid-cols-2 gap-4 xl:grid-cols-6">
          <div className="panel a-up col-span-2 flex items-center gap-5 p-4">
            <Gauge value={score} size={158} />
            <div className="min-w-0">
              <div className="lbl">Security Score</div>
              <div className="mt-1 text-[13px] font-medium text-ink/90">
                {score >= 80 ? 'Postura sólida' : score >= 60 ? 'Postura em atenção' : 'Postura crítica'}
              </div>
              <div className="mt-1 text-[11px] text-teal">▲ +4 pts vs. semana anterior</div>
              <button className="btn btn-xs mt-3" onClick={() => nav('portal')}>
                <Icon name="globe" size={12} /> Portal do cliente
              </button>
            </div>
          </div>
          <Stat label="Eventos 24h" value={series24h.reduce((a, b) => a + b, 0).toLocaleString('pt-BR')} icon="activity"
            color="#56c4ff" sub={`${epsWazuh + epsForti} ev/min agora`} spark={series24h.slice(12)} delay={60} />
          <Stat label="Alertas abertos" value={String(openAlerts.length)} icon="bell"
            color={newAlerts.length ? '#ff4d5e' : '#2fd6a5'} sub={<>{newAlerts.length} novos · {alerts.filter(a => a.severity === 'critical' && a.status !== 'fechado').length} críticos</>}
            spark={[3, 5, 4, 7, 6, 8, openAlerts.length + 2, openAlerts.length]} delay={120} />
          <Stat label="Incidentes ativos" value={String(activeInc.length)} icon="flame" color="#ff9142"
            sub={`${activeInc.filter(i => i.severity === 'critical').length} críticos em curso`} delay={180} />
          <Stat label="Vulns abertas" value={String(openVulns.length)} icon="bug" color="#ffc53d"
            sub={`${openVulns.filter(v => v.severity === 'critical').length} críticas · SLA ${slaPct}%`} delay={240} />
        </div>

        {/* gráficos principais */}
        <div className="grid grid-cols-12 gap-4">
          <Panel title="Volume de eventos — últimas 24h" icon="activity" className="col-span-12 xl:col-span-8" delay={80} live
            right={<span className="font-mono text-[10.5px] text-faint">fontes: Wazuh + FortiSIEM</span>}>
            <AreaChart data={series24h} height={190} />
          </Panel>

          <Panel title="Central de alertas" icon="bell" className="col-span-12 md:col-span-6 xl:col-span-4" delay={140}>
            <div className="flex items-center gap-5">
              <Donut segments={statusSegs} size={128} thick={13} center={String(alerts.length)} sub="total" />
              <div className="flex-1 min-w-0">
                {(['novo', 'reconhecido', 'investigando', 'escalado', 'fechado'] as AlertStatus[]).map(st => (
                  <div key={st} className="flex items-center gap-2 py-[3px] text-[11.5px]">
                    <span className="h-2 w-2 rounded-sm" style={{ background: ALERT_STATUS_META[st].color }} />
                    <span className="text-sub">{ALERT_STATUS_META[st].label}</span>
                    <span className="ml-auto font-mono text-ink/80">
                      {alerts.filter(a => (st === 'fechado' ? ['fechado', 'falso_positivo'].includes(a.status) : a.status === st)).length}
                    </span>
                  </div>
                ))}
              </div>
            </div>
            <div className="mt-4 border-t border-line pt-3.5">
              <div className="lbl mb-2.5">Abertos por severidade</div>
              <HBars items={sevBars} />
            </div>
          </Panel>

          {/* feed ao vivo */}
          <Panel title="Fluxo de eventos" icon="radar" className="col-span-12 md:col-span-6 xl:col-span-4" delay={100} live pad={false}
            right={
              <button className="btn btn-ghost btn-xs" onClick={() => nav('explorer')}>
                abrir explorer <Icon name="arrowUpRight" size={11} />
              </button>
            }>
            <div className="max-h-[292px] overflow-y-auto px-1.5 py-1.5">
              {events.slice(0, 26).map((ev, idx) => (
                <button key={ev.id}
                  className={`${idx === 0 ? 'flash-new' : ''} a-row flex w-full items-center gap-2.5 rounded-md px-2.5 py-[7px] text-left hover:bg-raise transition-colors`}
                  style={{ animationDelay: `${Math.min(idx, 8) * 30}ms` }}
                  onClick={() => nav('explorer', { type: 'event', id: ev.ruleId })}>
                  <span className="font-mono text-[10px] text-faint tabular-nums w-[52px] shrink-0">
                    {new Date(ev.ts).toTimeString().slice(0, 8)}
                  </span>
                  <span className="h-1.5 w-1.5 shrink-0 rounded-full" style={{ background: SEV_META[ev.severity].color, boxShadow: `0 0 6px ${SEV_META[ev.severity].color}` }} />
                  <span className="truncate text-[11.5px] text-ink/85">{ev.rule}</span>
                  <span className="ml-auto shrink-0 font-mono text-[10px] text-faint">{ev.host}</span>
                </button>
              ))}
            </div>
          </Panel>

          {/* SLA watchlist */}
          <Panel title="SLA sob risco" icon="clock" className="col-span-12 md:col-span-6 xl:col-span-4" delay={160}>
            {watchlist.length === 0 && <div className="py-6 text-center text-[12px] text-faint">Nenhum incidente ativo no tenant.</div>}
            <div className="flex flex-col gap-3.5">
              {watchlist.map(({ i, sla }) => (
                <button key={i.id} className="group text-left" onClick={() => nav('incidents', { type: 'incident', id: i.id })}>
                  <div className="mb-1.5 flex items-center gap-2">
                    <span className="font-mono text-[11px] text-teal group-hover:underline">{i.id}</span>
                    <span className="truncate text-[12px] text-ink/90">{i.title}</span>
                  </div>
                  <SLABar pct={sla.pct} breached={sla.breached} />
                  <div className="mt-1.5"><SLAChip left={sla.left} breached={sla.breached} /></div>
                </button>
              ))}
            </div>
          </Panel>

          {/* conectores */}
          <Panel title="Connectors & normalização" icon="layers" className="col-span-12 md:col-span-6 xl:col-span-4" delay={220}>
            <div className="flex flex-col gap-2">
              {[
                { name: 'Wazuh', eps: epsWazuh, total: events.filter(e => e.source === 'Wazuh').length, on: true, ver: 'v4.8.2' },
                { name: 'FortiSIEM', eps: epsForti, total: events.filter(e => e.source === 'FortiSIEM').length, on: true, ver: 'v7.3.1' },
                { name: 'FortiGate', eps: 0, total: 0, on: false, ver: 'roadmap' },
                { name: 'Microsoft Defender', eps: 0, total: 0, on: false, ver: 'roadmap' },
                { name: 'CrowdStrike', eps: 0, total: 0, on: false, ver: 'roadmap' },
              ].map(c => (
                <div key={c.name} className={`flex items-center gap-3 rounded-lg border border-line/70 px-3 py-2 ${c.on ? '' : 'opacity-45'}`}>
                  <span className={`h-2 w-2 rounded-full ${c.on ? 'bg-teal dot-live' : 'bg-faint/50'}`} />
                  <div className="min-w-0">
                    <div className="text-[12px] font-medium text-ink/90">{c.name}</div>
                    <div className="font-mono text-[10px] text-faint">{c.ver}</div>
                  </div>
                  <div className="ml-auto text-right">
                    <div className="font-mono text-[12px] text-teal tabular-nums">{c.on ? `${c.eps} ev/min` : '—'}</div>
                    <div className="font-mono text-[10px] text-faint">{c.on ? `${c.total.toLocaleString('pt-BR')} ev` : ''}</div>
                  </div>
                </div>
              ))}
            </div>
          </Panel>

          {/* top hosts + IOCs */}
          <Panel title="Top hosts & IOCs" icon="target" className="col-span-12 md:col-span-6 xl:col-span-4" delay={280}>
            <div className="lbl mb-2">Hosts com mais eventos</div>
            <div className="flex flex-col gap-1">
              {topHosts.map(([host, count]) => (
                <button key={host} className="flex items-center gap-2.5 rounded-md px-2 py-[5px] hover:bg-raise transition-colors"
                  onClick={() => nav('assets', { type: 'assetname', id: host })}>
                  <Icon name="server" size={12} className="text-cyan" />
                  <span className="font-mono text-[11.5px] text-ink/90">{host}</span>
                  <span className="ml-auto font-mono text-[11px] text-faint">{count}</span>
                  <div className="h-[4px] w-16 overflow-hidden rounded-sm bg-[#0a1322]">
                    <div className="h-full bg-cyan/70" style={{ width: `${(count / (topHosts[0]?.[1] ?? 1)) * 100}%` }} />
                  </div>
                </button>
              ))}
            </div>
            <div className="lbl mb-2 mt-4">IOCs em investigação</div>
            <div className="flex flex-col gap-1.5">
              {iocCount.length === 0 && <div className="text-[11.5px] text-faint">Nenhum IOC no escopo.</div>}
              {iocCount.map(([ioc, count]) => (
                <div key={ioc} className="flex items-center gap-2.5">
                  <span className="h-1.5 w-1.5 rounded-full bg-high" />
                  <span className="truncate font-mono text-[11px] text-ink/80" title={ioc}>{ioc}</span>
                  <span className="ml-auto shrink-0 font-mono text-[10px] text-faint">{count}× </span>
                </div>
              ))}
            </div>
          </Panel>

          {/* incidentes ativos */}
          <Panel title="Incidentes ativos" icon="flame" className="col-span-12 xl:col-span-6" delay={200} pad={false}
            right={<button className="btn btn-ghost btn-xs" onClick={() => nav('incidents')}>ver todos <Icon name="chevronRight" size={11} /></button>}>
            {activeInc.length === 0 && <div className="py-8 text-center text-[12px] text-faint">Nenhum incidente ativo. Operação sob controle.</div>}
            <div>
              {activeInc.slice(0, 5).map(i => {
                const sla = slaInfo(i, now);
                return (
                  <button key={i.id} className="flex w-full items-center gap-3 border-t border-line/60 px-4 py-2.5 text-left first:border-t-0 hover:bg-raise transition-colors"
                    onClick={() => nav('incidents', { type: 'incident', id: i.id })}>
                    <SevBadge sev={i.severity} sm />
                    <span className="font-mono text-[11px] text-teal">{i.id}</span>
                    <span className="min-w-0 flex-1 truncate text-[12.5px] text-ink/90">{i.title}</span>
                    <span className="hidden md:block"><Avatar name={i.assignee} size={22} /></span>
                    <Pill label={INC_STATUS_META[i.status].label} color={INC_STATUS_META[i.status].color} sm />
                    <span className="hidden lg:block"><SLAChip left={sla.left} breached={sla.breached} /></span>
                  </button>
                );
              })}
            </div>
          </Panel>

          {/* atividade recente */}
          <Panel title="Atividade recente — auditoria" icon="history" className="col-span-12 xl:col-span-6" delay={260} pad={false}
            right={<button className="btn btn-ghost btn-xs" onClick={() => nav('audit')}>trilha completa <Icon name="chevronRight" size={11} /></button>}>
            <div>
              {s.audit.slice(0, 7).map(a => (
                <div key={a.id} className="flex items-center gap-3 border-t border-line/60 px-4 py-[9px] first:border-t-0">
                  <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-md border border-line bg-panel2 text-sub">
                    <Icon name={AUDIT_ICON[a.kind] ?? 'activity'} size={12} />
                  </span>
                  <div className="min-w-0 flex-1 text-[12px] leading-snug">
                    <span className="font-medium text-ink/90">{a.actor}</span>
                    <span className="text-sub"> {a.action} </span>
                    <span className="font-mono text-[11px] text-teal/90">{a.target}</span>
                  </div>
                  <span className="shrink-0 font-mono text-[10px] text-faint" title={fmtDT(a.ts)}>{timeAgo(a.ts)}</span>
                </div>
              ))}
            </div>
          </Panel>

          {/* rodapé técnico */}
          <div className="a-up col-span-12 flex flex-wrap items-center gap-x-5 gap-y-1 rounded-lg border border-line/60 bg-panel/50 px-4 py-2.5 font-mono text-[10.5px] text-faint" style={{ animationDelay: '320ms' }}>
            <span className="text-teal">● pipeline: collect → normalize → correlate → respond</span>
            <span>tenants: {s.tenants.length} isolados</span>
            <span>regras ativas: 1.284</span>
            <span>MITRE ATT&amp;CK mapeado</span>
            <span className="ml-auto">baseline inicial · build local</span>
          </div>
        </div>
      </div>
    </div>
  );
}
