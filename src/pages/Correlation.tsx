import { useCallback, useEffect, useMemo, useState } from 'react';
import type { Severity } from '../data/mock';
import { SEV_META, SEV_ORDER } from '../data/mock';
import { can, timeAgo, useNow, useStore } from '../lib/store';
import type { Route } from '../lib/store';
import { api as srv } from '../lib/api';
import type { AggRow, BacktestResult, CorrPolicy, CorrPolicyInput, RiskScore } from '../lib/api';
import { EmptyState, Field, Icon, Modal, Panel, Pill, SevBadge } from '../components/ui';

const TABS = [
  { id: 'regras', label: 'Regras', icon: 'crosshair' },
  { id: 'agrupamento', label: 'Agrupamento', icon: 'layers' },
  { id: 'risco', label: 'Risco', icon: 'target' },
  { id: 'disparos', label: 'Disparos', icon: 'zap' },
] as const;
type Tab = typeof TABS[number]['id'];

const GROUP_FIELDS = [
  { id: 'host', label: 'host' },
  { id: 'srcIp', label: 'IP origem' },
  { id: 'dstIp', label: 'IP destino' },
  { id: 'user', label: 'usuário' },
  { id: 'ruleId', label: 'regra' },
];

const EMPTY_FORM: CorrPolicyInput = {
  name: '', description: '', severity: 'high', windowSec: 300, threshold: 5,
  groupBy: ['host'], mode: 'count', mitre: '',
  match: { ruleIdContains: '', ruleContains: '', source: '', minSeverity: '', dstExternal: false },
};

function scoreColor(v: number) {
  return v >= 70 ? '#ff4d5e' : v >= 45 ? '#ff9142' : v >= 25 ? '#ffc53d' : '#2fd6a5';
}

const SEV_W = { critical: 15, high: 8, medium: 3, low: 1, info: 0 } as Record<string, number>;
const AL_W = { critical: 20, high: 10, medium: 4, low: 1, info: 0 } as Record<string, number>;

export default function Correlation() {
  const { s, scope, nav, toggleCorrelation, backend, refresh, toast } = useStore();
  const now = useNow(15000);
  const online = backend === 'online';
  const canUpdate = can(s.role, 'correlations.update') || s.role === 'Admin';

  const [tab, setTab] = useState<Tab>('regras');

  // ── regras ──
  const [policies, setPolicies] = useState<CorrPolicy[]>([]);
  const loadPolicies = useCallback(async () => {
    if (online) { const r = await srv.correlations(); if (r) setPolicies(r); }
    else setPolicies(s.correlations);
  }, [online, s.correlations]);
  useEffect(() => { void loadPolicies(); }, [loadPolicies]);

  const [modal, setModal] = useState<CorrPolicy | 'new' | null>(null);
  const [bt, setBt] = useState<BacktestResult | null>(null);
  const [btLoading, setBtLoading] = useState(false);

  // ── agrupamento ──
  const [aggBy, setAggBy] = useState('host');
  const [aggHours, setAggHours] = useState(24);
  const [agg, setAgg] = useState<AggRow[]>([]);
  const [aggLoading, setAggLoading] = useState(false);
  useEffect(() => {
    if (!online || tab !== 'agrupamento') return;
    let alive = true; setAggLoading(true);
    srv.aggregate(aggBy, aggHours, s.tenant).then(r => { if (alive && r) { setAgg(r); setAggLoading(false); } });
    return () => { alive = false; };
  }, [online, tab, aggBy, aggHours, s.tenant]);

  // ── risco ──
  const [riskType, setRiskType] = useState('host');
  const [risk, setRisk] = useState<RiskScore[]>([]);
  const [riskLoading, setRiskLoading] = useState(false);
  useEffect(() => {
    if (!online || tab !== 'risco') return;
    let alive = true; setRiskLoading(true);
    srv.riskScores(riskType).then(r => { if (alive && r) { setRisk(r); setRiskLoading(false); } });
    return () => { alive = false; };
  }, [online, tab, riskType]);

  const fires = useMemo(
    () => scope(s.alerts).filter(a => a.source === 'Correlação').sort((a, b) => b.ts - a.ts),
    [s.alerts, s.tenant], // eslint-disable-line react-hooks/exhaustive-deps
  );
  const active = policies.filter(p => p.enabled).length;

  // ── fallback de demonstração (client-side) para risco & agrupamento ──
  const demoRisk = useMemo<RiskScore[]>(() => {
    if (online) return [];
    const key = (e: { host: string; srcIp: string; user: string }) =>
      riskType === 'host' ? e.host : riskType === 'srcIp' ? e.srcIp : e.user;
    const map = new Map<string, RiskScore>();
    const bump = (entity: string): RiskScore => {
      if (!map.has(entity)) map.set(entity, {
        entity, score: 0,
        factors: { eventos24h: 0, alertasAbertos: 0, incidentes: 0, vulnsCriticas: 0 },
        detail: { criticalEvents: 0, highEvents: 0, openAlerts: 0, activeIncidents: 0, criticalVulns: 0 },
      });
      return map.get(entity)!;
    };
    for (const e of scope(s.events)) {
      if (now - e.ts > 86_400_000) continue;
      const k = key(e); if (!k || k === '—') continue;
      const r = bump(k);
      r.factors.eventos24h += SEV_W[e.severity] ?? 0;
      if (e.severity === 'critical') r.detail.criticalEvents++;
      if (e.severity === 'high') r.detail.highEvents++;
    }
    for (const a of scope(s.alerts)) {
      if (['fechado', 'falso_positivo'].includes(a.status)) continue;
      const k = key(a); if (!k || k === '—') continue;
      const r = bump(k);
      r.factors.alertasAbertos += AL_W[a.severity] ?? 0;
      r.detail.openAlerts++;
    }
    if (riskType === 'host') {
      for (const i of scope(s.incidents)) {
        if (['resolvido', 'fechado'].includes(i.status) || !i.asset) continue;
        const r = bump(i.asset); r.factors.incidentes += 25; r.detail.activeIncidents++;
      }
      for (const v of scope(s.vulns)) {
        if (v.severity !== 'critical' || ['resolvida', 'aceita'].includes(v.status) || v.asset === '—') continue;
        const r = bump(v.asset); r.factors.vulnsCriticas += 15; r.detail.criticalVulns++;
      }
    }
    return [...map.values()].map(r => ({
      ...r, score: Math.max(0, Math.min(100, Math.round(r.factors.eventos24h + r.factors.alertasAbertos + r.factors.incidentes + r.factors.vulnsCriticas))),
    })).sort((a, b) => b.score - a.score).slice(0, 50);
  }, [online, riskType, now, s.events, s.alerts, s.incidents, s.vulns, s.tenant, scope]);

  const demoAgg = useMemo<AggRow[]>(() => {
    if (online) return [];
    const key = (e: { host: string; srcIp: string; user: string; rule: string }) =>
      aggBy === 'host' ? e.host : aggBy === 'srcIp' ? e.srcIp : aggBy === 'user' ? e.user : e.rule;
    const map = new Map<string, AggRow>();
    for (const e of scope(s.events)) {
      if (now - e.ts > aggHours * 3_600_000) continue;
      const k = key(e); if (!k || k === '—') continue;
      if (!map.has(k)) map.set(k, { entity: k, total: 0, critical: 0, high: 0, medium: 0, low: 0, firstTs: e.ts, lastTs: e.ts });
      const r = map.get(k)!;
      r.total++;
      if (e.severity === 'critical') r.critical++;
      else if (e.severity === 'high') r.high++;
      else if (e.severity === 'medium') r.medium++;
      else r.low++;
      r.firstTs = Math.min(r.firstTs, e.ts); r.lastTs = Math.max(r.lastTs, e.ts);
    }
    return [...map.values()].sort((a, b) => b.total - a.total).slice(0, 40);
  }, [online, aggBy, aggHours, now, s.events, s.tenant, scope]);

  const openEdit = (p: CorrPolicy | 'new') => { setBt(null); setModal(p); };

  const del = async (p: CorrPolicy) => {
    const msg = p.builtin
      ? `"${p.name}" (${p.id}) é uma regra NATIVA do sistema. Remover mesmo assim? Você pode recriá-la depois pelo botão "Restaurar padrão".`
      : `Remover a regra "${p.name}" (${p.id})?`;
    if (!window.confirm(msg)) return;
    const r = await srv.deleteCorrelation(p.id);
    if (r?.ok) { toast('ok', `Regra ${p.id} removida`); await loadPolicies(); refresh(); }
    else toast('err', r?.error ?? 'Falha ao remover');
  };

  const restore = async (p: CorrPolicy) => {
    if (!window.confirm(`Restaurar "${p.name}" (${p.id}) ao padrão de fábrica? Isso desfaz qualquer edição feita nela.`)) return;
    const r = await srv.restoreCorrelation(p.id);
    if (r?.ok) { toast('ok', `Regra ${p.id} restaurada ao padrão`); await loadPolicies(); refresh(); }
    else toast('err', r?.error ?? 'Falha ao restaurar');
  };

  const restoreMissing = async () => {
    const r = await srv.restoreMissingCorrelations();
    if (r?.ok) {
      if (r.restored.length) { toast('ok', `${r.restored.length} regra(s) nativa(s) restaurada(s): ${r.restored.join(', ')}`); await loadPolicies(); refresh(); }
      else toast('ok', 'Todas as regras nativas já estão presentes');
    } else toast('err', 'Falha ao restaurar regras nativas');
  };

  return (
    <div className="h-full overflow-y-auto">
      <div className="mx-auto flex max-w-[1400px] flex-col gap-4 p-5">

        {/* cabeçalho */}
        <div className="a-up flex flex-wrap items-end justify-between gap-3">
          <div>
            <div className="lbl mb-1 flex items-center gap-2">
              <span className="inline-block h-1.5 w-1.5 rounded-full bg-teal dot-live" />
              detection & correlation
            </div>
            <h2 className="font-display text-[22px] font-bold tracking-tight text-ink">
              Regras, risco e agrupamento — eventos viram alertas por <span className="text-teal">padrão</span>
            </h2>
          </div>
          <div className="flex items-center gap-4">
            <div className="text-right">
              <div className="font-mono text-[22px] font-bold text-teal">{active}/{policies.length}</div>
              <div className="lbl">regras ativas</div>
            </div>
            <div className="h-9 w-px bg-line" />
            <div className="text-right">
              <div className="font-mono text-[22px] font-bold text-high">{fires.length}</div>
              <div className="lbl">disparos recentes</div>
            </div>
          </div>
        </div>

        {/* abas */}
        <div className="a-up flex items-center gap-1 border-b border-line" style={{ animationDelay: '40ms' }}>
          {TABS.map(t => (
            <button key={t.id} onClick={() => setTab(t.id)}
              className={`relative flex items-center gap-2 px-4 py-2.5 text-[13px] font-medium transition-colors ${tab === t.id ? 'text-teal' : 'text-faint hover:text-sub'}`}>
              <Icon name={t.icon} size={14} /> {t.label}
              {t.id === 'disparos' && fires.length > 0 && (
                <span className="rounded-full bg-high/15 px-1.5 font-mono text-[10px] text-high">{fires.length}</span>
              )}
              {tab === t.id && <span className="absolute inset-x-3 -bottom-px h-[2px] rounded-full bg-teal" style={{ boxShadow: '0 0 8px rgba(47,214,165,.6)' }} />}
            </button>
          ))}
          {tab === 'regras' && (
            <div className="ml-auto mb-1.5 flex items-center gap-1.5">
              <button className="btn btn-xs" disabled={!canUpdate || !online}
                title={!online ? 'requer sopir-api conectada' : 'recria nativas removidas, sem afetar as existentes'}
                onClick={restoreMissing}>
                <Icon name="refresh" size={12} /> Restaurar padrão
              </button>
              <button className="btn btn-primary btn-xs" disabled={!canUpdate || !online}
                title={!online ? 'requer sopir-api conectada' : undefined} onClick={() => openEdit('new')}>
                <Icon name="plus" size={12} /> Nova regra
              </button>
            </div>
          )}
        </div>

        {/* ── REGRAS ── */}
        {tab === 'regras' && (
          <div className="a-up grid grid-cols-12 gap-4">
            <Panel title="Regras de correlação" icon="crosshair" className="col-span-12" pad={false}
              right={!canUpdate ? <span className="flex items-center gap-1 font-mono text-[10px] text-faint"><Icon name="lock" size={10} /> leitura</span> : undefined}>
              <div className="overflow-x-auto">
                <table className="tbl min-w-[760px]">
                  <thead>
                    <tr>
                      <th>Regra</th>
                      <th>Sev.</th>
                      <th>MITRE</th>
                      <th>Janela</th>
                      <th>Threshold</th>
                      <th>Grupo</th>
                      <th>Disparos</th>
                      <th className="text-right pr-5">Ações</th>
                    </tr>
                  </thead>
                  <tbody>
                    {policies.map((p, i) => (
                      <tr key={p.id} className="a-row" style={{ animationDelay: `${i * 35}ms` }}>
                        <td>
                          <div className="flex items-center gap-2.5">
                            <button onClick={() => canUpdate && toggleCorrelation(p.id)} disabled={!canUpdate}
                              className={`relative inline-flex h-[20px] w-[36px] shrink-0 items-center rounded-full border transition-colors ${p.enabled ? 'border-teal/60 bg-teal/25' : 'border-line2 bg-panel2'} ${canUpdate ? 'cursor-pointer' : 'cursor-not-allowed opacity-50'}`}
                              title={p.enabled ? 'Desativar' : 'Ativar'}>
                              <span className={`absolute h-[14px] w-[14px] rounded-full transition-all ${p.enabled ? 'left-[18px] bg-teal' : 'left-[3px] bg-faint'}`}
                                style={p.enabled ? { boxShadow: '0 0 8px rgba(47,214,165,.6)' } : undefined} />
                            </button>
                            <div>
                              <div className="flex items-center gap-2 text-[12.5px] font-semibold text-ink/90">{p.name}
                                <Pill label={p.builtin ? 'nativa' : 'custom'} color={p.builtin ? '#8fa3c8' : '#56c4ff'} sm />
                              </div>
                              <div className="mt-0.5 max-w-[360px] text-[10.5px] leading-snug text-faint">{p.logic}</div>
                            </div>
                          </div>
                        </td>
                        <td><SevBadge sev={p.severity as Severity} sm /></td>
                        <td>{p.mitre ? <span className="font-mono text-[10.5px] text-cyan/90">{p.mitre}</span> : <span className="text-faint">—</span>}</td>
                        <td className="font-mono text-[11px] text-sub">{p.windowSec}s</td>
                        <td className="font-mono text-[11px] text-sub">≥{p.threshold}</td>
                        <td className="font-mono text-[10.5px] text-faint">{p.groupByLabel}</td>
                        <td>
                          <span className="font-mono text-[12px] font-semibold text-ink/90">{p.fires}</span>
                          {p.lastFire && <span className="ml-1.5 font-mono text-[9.5px] text-faint">{timeAgo(p.lastFire)}</span>}
                        </td>
                        <td className="text-right pr-5">
                          <div className="flex items-center justify-end gap-1">
                            <button className="btn btn-ghost btn-xs" title="Backtest (testar contra eventos recentes)"
                              onClick={async () => {
                                setBtLoading(true); setTab('regras');
                                const def = p.matchDef
                                  ? { name: p.name, severity: p.severity, windowSec: p.windowSec, threshold: p.threshold, groupBy: p.groupBy, mode: p.mode ?? 'count', match: p.matchDef, mitre: p.mitre ?? undefined }
                                  : { name: p.name, severity: p.severity, windowSec: p.windowSec, threshold: p.threshold, groupBy: p.groupBy, mode: p.mode ?? 'count', mitre: p.mitre ?? undefined };
                                const r = await srv.backtest(def);
                                if (r) setBt(r); else toast('err', 'Backtest requer a sopir-api conectada');
                                setBtLoading(false);
                              }}>
                              <Icon name="radar" size={12} /> testar
                            </button>
                            <button className="btn btn-ghost btn-xs" title="Editar" disabled={!canUpdate || !online} onClick={() => openEdit(p)}><Icon name="edit" size={12} /></button>
                            {p.builtin && (
                              <button className="btn btn-ghost btn-xs" title="Restaurar ao padrão de fábrica" disabled={!canUpdate || !online} onClick={() => restore(p)}>
                                <Icon name="refresh" size={12} />
                              </button>
                            )}
                            <button className="btn btn-ghost btn-xs hover:text-crit!" title="Remover" disabled={!canUpdate || !online} onClick={() => del(p)}><Icon name="trash" size={12} /></button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <div className="border-t border-line px-5 py-3 font-mono text-[10px] text-faint">
                o motor mantém uma janela deslizante por grupo e dispara ao atingir o threshold · cooldown evita disparos repetidos
              </div>
            </Panel>
          </div>
        )}

        {/* ── AGRUPAMENTO ── */}
        {tab === 'agrupamento' && (
          <div className="a-up grid grid-cols-12 gap-4">
            <Panel title="Agrupamento de eventos" icon="layers" className="col-span-12" pad={false}
              right={
                <div className="flex items-center gap-2">
                  <select className="select py-1! text-[11px]" value={aggBy} onChange={e => setAggBy(e.target.value)}>
                    <option value="host">por host</option>
                    <option value="srcIp">por IP origem</option>
                    <option value="user">por usuário</option>
                    <option value="rule">por regra</option>
                  </select>
                  <select className="select py-1! text-[11px]" value={aggHours} onChange={e => setAggHours(Number(e.target.value))}>
                    <option value={1}>última 1h</option>
                    <option value={24}>últimas 24h</option>
                    <option value={72}>últimos 3 dias</option>
                  </select>
                </div>
              }>
              {!online && demoAgg.length === 0 ? (
                <EmptyState icon="layers" title="Sem eventos no período" sub="Sem eventos no escopo para agrupar." />
              ) : !online ? (
                <AggTable rows={demoAgg} aggBy={aggBy} nav={nav} />
              ) : aggLoading ? (
                <div className="py-10 text-center text-[12px] text-faint">agregando…</div>
              ) : agg.length === 0 ? (
                <EmptyState icon="layers" title="Sem eventos no período" />
              ) : (
                <AggTable rows={agg} aggBy={aggBy} nav={nav} />
              )}
            </Panel>
          </div>
        )}

        {/* ── RISCO ── */}
        {tab === 'risco' && (
          <div className="a-up grid grid-cols-12 gap-4">
            <Panel title="Risco por entidade (24h)" icon="target" className="col-span-12 xl:col-span-8" pad={false}
              right={
                <select className="select py-1! text-[11px]" value={riskType} onChange={e => setRiskType(e.target.value)}>
                  <option value="host">hosts</option>
                  <option value="srcIp">IPs de origem</option>
                  <option value="user">usuários</option>
                </select>
              }>
              {!online && demoRisk.length === 0 ? (
                <EmptyState icon="target" title="Sem dados de risco" sub="Sem eventos/alertas no escopo para pontuar." />
              ) : !online ? (
                <RiskList rows={demoRisk} riskType={riskType} nav={nav} />
              ) : riskLoading ? (
                <div className="py-10 text-center text-[12px] text-faint">calculando risco…</div>
              ) : risk.length === 0 ? (
                <EmptyState icon="target" title="Sem dados de risco" />
              ) : (
                <RiskList rows={risk} riskType={riskType} nav={nav} />
              )}
            </Panel>

            <Panel title="Como o risco é calculado" icon="cpu" className="col-span-12 xl:col-span-4">
              <div className="flex flex-col gap-2.5 text-[12px]">
                {[
                  { k: 'Eventos 24h', v: 'peso por severidade (C=15 · A=8 · M=3)', c: '#56c4ff' },
                  { k: 'Alertas abertos', v: 'peso por severidade (C=20 · A=10)', c: '#ffc53d' },
                  { k: 'Incidentes ativos', v: '+25 por incidente (hosts)', c: '#ff9142' },
                  { k: 'Vulns críticas', v: '+15 por finding aberto (hosts)', c: '#ff4d5e' },
                ].map(f => (
                  <div key={f.k} className="flex items-start gap-2.5 rounded-md border border-line/70 bg-panel px-3 py-2.5">
                    <span className="mt-1 h-2 w-2 shrink-0 rounded-sm" style={{ background: f.c }} />
                    <div>
                      <div className="font-semibold text-ink/90">{f.k}</div>
                      <div className="font-mono text-[10px] text-faint">{f.v}</div>
                    </div>
                  </div>
                ))}
                <p className="mt-1 text-[11px] leading-relaxed text-faint">
                  O score é a soma dos fatores limitada a 100. Entidades com risco alto merecem investigação prioritária — clique para abrir o grafo.
                </p>
              </div>
            </Panel>
          </div>
        )}

        {/* ── DISPAROS ── */}
        {tab === 'disparos' && (
          <div className="a-up grid grid-cols-12 gap-4">
            <Panel title="Disparos recentes (alertas de correlação)" icon="zap" className="col-span-12" pad={false} live>
              {fires.length === 0 ? (
                <EmptyState icon="crosshair" title="Nenhum disparo no escopo" sub="Quando uma regra atingir o threshold, o alerta correlacionado aparece aqui." />
              ) : (
                <div>
                  {fires.map((f, i) => (
                    <button key={f.id} onClick={() => nav('alerts', { type: 'alert', id: f.id })}
                      className="a-row flex w-full items-start gap-3 border-t border-line/60 px-5 py-3 text-left first:border-t-0 hover:bg-raise transition-colors"
                      style={{ animationDelay: `${i * 45}ms` }}>
                      <span className="mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-md border border-high/40 bg-high/10 text-high">
                        <Icon name="zap" size={13} />
                      </span>
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-[10px] text-teal">{f.ruleId}</span>
                          <SevBadge sev={f.severity} sm />
                          <span className="ml-auto font-mono text-[9.5px] text-faint">{timeAgo(f.ts)}</span>
                        </div>
                        <div className="mt-1 text-[12.5px] font-medium leading-snug text-ink/90">{f.title}</div>
                        <div className="mt-1 flex items-center gap-2">
                          <Pill label={`via ${f.rule}`} color="#56c4ff" sm />
                          {f.host !== '—' && <span className="font-mono text-[10px] text-faint">{f.host}</span>}
                        </div>
                      </div>
                      <Icon name="arrowUpRight" size={13} className="mt-1 shrink-0 text-faint" />
                    </button>
                  ))}
                </div>
              )}
            </Panel>
          </div>
        )}

        {/* como funciona */}
        <div className="a-up col-span-12 rounded-xl border border-line bg-panel/60 p-5" style={{ animationDelay: '160ms' }}>
          <div className="lbl mb-3">Como o motor decide</div>
          <div className="flex flex-wrap items-center gap-1.5 font-mono text-[10.5px]">
            {['Evento normalizado', 'Janela deslizante', 'Regras ativas', 'Agrupamento', 'Threshold', 'Cooldown', 'Alerta de correlação'].map((st, i, arr) => (
              <span key={st} className="flex items-center gap-1.5">
                <span className={`rounded border px-2 py-1 ${st.includes('Alerta') ? 'border-high/50 text-high' : st.includes('Threshold') ? 'border-teal/50 text-teal' : 'border-line text-sub'}`}>{st}</span>
                {i < arr.length - 1 && <Icon name="chevronRight" size={11} className="text-faint" />}
              </span>
            ))}
          </div>
        </div>
      </div>

      {/* modal de regra + backtest */}
      {modal && (
        <RuleModal
          policy={modal === 'new' ? null : modal}
          onClose={() => setModal(null)}
          bt={bt} btLoading={btLoading}
          onBacktest={async (def) => { setBtLoading(true); const r = await srv.backtest(def); if (r) setBt(r); else toast('err', 'Backtest requer a sopir-api'); setBtLoading(false); }}
          onSave={async (def) => {
            if (modal === 'new') {
              const r = await srv.createCorrelation(def);
              if (r?.code) { toast('ok', `Regra ${r.code} criada`); setModal(null); await loadPolicies(); refresh(); }
              else toast('err', 'Falha ao criar regra');
            } else {
              const r = await srv.updateCorrelation(modal.id, def);
              if (r?.ok) { toast('ok', `Regra ${modal.id} atualizada`); setModal(null); await loadPolicies(); refresh(); }
              else toast('err', r?.error ?? 'Falha ao atualizar');
            }
          }}
        />
      )}
    </div>
  );
}

// ── tabela de agrupamento (usada online e demo) ──────────────
function AggTable({ rows, aggBy, nav }: { rows: AggRow[]; aggBy: string; nav: (r: Route) => void }) {
  return (
    <div className="overflow-x-auto">
      <table className="tbl min-w-[700px]">
        <thead>
          <tr>
            <th>{aggBy === 'host' ? 'Host' : aggBy === 'srcIp' ? 'IP origem' : aggBy === 'user' ? 'Usuário' : 'Regra'}</th>
            <th>Total</th>
            <th className="w-[300px]">Distribuição por severidade</th>
            <th>Último evento</th>
            <th className="text-right pr-5">Ação</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((a, i) => {
            const max = rows[0]?.total ?? 1;
            return (
              <tr key={a.entity} className="a-row" style={{ animationDelay: `${i * 30}ms` }}>
                <td className="font-mono text-[11.5px] text-ink/90">{a.entity}</td>
                <td>
                  <span className="font-mono text-[12px] font-semibold text-ink/90">{a.total}</span>
                  <div className="mt-1 h-[4px] w-24 overflow-hidden rounded-sm bg-input-bg">
                    <div className="h-full bg-cyan/70" style={{ width: `${(a.total / max) * 100}%` }} />
                  </div>
                </td>
                <td>
                  <div className="flex h-[10px] w-full overflow-hidden rounded-sm bg-input-bg">
                    {a.critical > 0 && <div style={{ width: `${(a.critical / a.total) * 100}%`, background: SEV_META.critical.color }} title={`${a.critical} críticos`} />}
                    {a.high > 0 && <div style={{ width: `${(a.high / a.total) * 100}%`, background: SEV_META.high.color }} title={`${a.high} altos`} />}
                    {a.medium > 0 && <div style={{ width: `${(a.medium / a.total) * 100}%`, background: SEV_META.medium.color }} title={`${a.medium} médios`} />}
                    {a.low > 0 && <div style={{ width: `${(a.low / a.total) * 100}%`, background: SEV_META.low.color }} title={`${a.low} baixos`} />}
                  </div>
                  <div className="mt-1 font-mono text-[9px] text-faint">
                    <span style={{ color: SEV_META.critical.color }}>{a.critical}C</span> · <span style={{ color: SEV_META.high.color }}>{a.high}A</span> · <span style={{ color: SEV_META.medium.color }}>{a.medium}M</span> · <span style={{ color: SEV_META.low.color }}>{a.low}B</span>
                  </div>
                </td>
                <td className="font-mono text-[10.5px] text-faint">{timeAgo(a.lastTs)}</td>
                <td className="text-right pr-5">
                  <button className="btn btn-ghost btn-xs" onClick={() => nav(aggBy === 'rule' ? 'explorer' : 'investigation')}>
                    <Icon name="arrowUpRight" size={12} /> {aggBy === 'rule' ? 'explorer' : 'investigar'}
                  </button>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

// ── lista de risco (usada online e demo) ─────────────────────
function RiskList({ rows, riskType, nav }: { rows: RiskScore[]; riskType: string; nav: (r: Route) => void }) {
  return (
    <div className="p-4">
      {rows.map((r, i) => (
        <button key={r.entity} onClick={() => nav('investigation')}
          className="a-row group mb-2.5 flex w-full items-center gap-4 rounded-lg border border-line bg-panel px-4 py-3 text-left transition-all hover:border-line2 hover:translate-x-[2px]"
          style={{ animationDelay: `${i * 35}ms` }}>
          <div className="w-[46px] text-center">
            <div className="font-mono text-[20px] font-bold leading-none tabular-nums" style={{ color: scoreColor(r.score) }}>{r.score}</div>
            <div className="mt-0.5 text-[8.5px] font-mono uppercase text-faint">risco</div>
          </div>
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2">
              <span className="truncate font-mono text-[12.5px] font-semibold text-ink/90">{r.entity}</span>
              <span className="ml-auto font-mono text-[9.5px] text-faint">
                {r.detail.criticalEvents}C · {r.detail.highEvents}A ev / {r.detail.openAlerts} alertas{riskType === 'host' ? ` / ${r.detail.activeIncidents} inc · ${r.detail.criticalVulns} vuln` : ''}
              </span>
            </div>
            <div className="mt-1.5 h-[6px] w-full overflow-hidden rounded-sm bg-input-bg">
              <div className="h-full rounded-sm transition-all duration-700" style={{ width: `${r.score}%`, background: `linear-gradient(90deg, ${scoreColor(r.score)}88, ${scoreColor(r.score)})` }} />
            </div>
          </div>
          <Icon name="chevronRight" size={14} className="shrink-0 text-faint group-hover:text-teal" />
        </button>
      ))}
    </div>
  );
}

// ── modal de regra (criar/editar + backtest) ─────────────────
function RuleModal({ policy, onClose, onSave, onBacktest, bt, btLoading }: {
  policy: CorrPolicy | null; onClose: () => void;
  onSave: (def: CorrPolicyInput) => void;
  onBacktest: (def: CorrPolicyInput) => void;
  bt: BacktestResult | null; btLoading: boolean;
}) {
  const init: CorrPolicyInput = policy
    ? {
        name: policy.name, description: policy.logic, severity: policy.severity,
        windowSec: policy.windowSec, threshold: policy.threshold, groupBy: policy.groupBy,
        mode: policy.mode ?? 'count', mitre: policy.mitre ?? '',
        match: (policy.matchDef ?? {}) as CorrPolicyInput['match'],
      }
    : { ...EMPTY_FORM, match: { ...EMPTY_FORM.match } };
  const [f, setF] = useState(init);
  const set = (patch: Partial<CorrPolicyInput>) => setF(p => ({ ...p, ...patch }));
  const setMatch = (patch: Record<string, unknown>) => setF(p => ({ ...p, match: { ...p.match, ...patch } }));

  // regras nativas podem usar critérios avançados (ruleIdIn / ruleRegex / conditions
  // de modo "sequência") que este formulário não edita — preservamos como estão.
  const advancedMatch = policy?.matchDef
    ? Object.fromEntries(Object.entries(policy.matchDef).filter(([k]) =>
        ['ruleIdIn', 'ruleRegex', 'conditions'].includes(k)))
    : {};
  const hasAdvancedMatch = Object.keys(advancedMatch).length > 0;

  const cleanDef = (): CorrPolicyInput => ({
    ...f,
    mitre: f.mitre?.trim() || undefined,
    match: {
      ...advancedMatch,
      ruleIdContains: (f.match?.ruleIdContains as string)?.trim() || undefined,
      ruleContains: (f.match?.ruleContains as string)?.trim() || undefined,
      source: (f.match?.source as string) || undefined,
      minSeverity: (f.match?.minSeverity as string) || undefined,
      dstExternal: !!(f.match?.dstExternal) || undefined,
    },
  });

  const toggleGroup = (g: string) =>
    set({ groupBy: f.groupBy.includes(g) ? f.groupBy.filter(x => x !== g) : [...f.groupBy, g] });

  return (
    <Modal open onClose={onClose} width={640}
      title={<span className="flex items-center gap-2"><Icon name="crosshair" size={15} className="text-teal" /> {policy ? `Editar regra ${policy.id}` : 'Nova regra de correlação'}</span>}
      footer={
        <>
          <button className="btn btn-xs" onClick={onClose}>Cancelar</button>
          <button className="btn btn-xs" disabled={btLoading} onClick={() => onBacktest(cleanDef())}>
            <Icon name="radar" size={12} /> {btLoading ? 'Testando…' : 'Backtest'}
          </button>
          <button className="btn btn-primary btn-xs" disabled={!f.name.trim() || !f.groupBy.length} onClick={() => onSave(cleanDef())}>
            <Icon name="check" size={12} /> {policy ? 'Salvar' : 'Criar regra'}
          </button>
        </>
      }>
      <div className="flex flex-col gap-3.5">
        <div className="grid grid-cols-2 gap-3">
          <Field label="Nome da regra">
            <input className="input w-full" placeholder="Ex.: Várias falhas de login" value={f.name} onChange={e => set({ name: e.target.value })} autoFocus />
          </Field>
          <Field label="Técnica MITRE ATT&CK (opcional)">
            <input className="input w-full font-mono" placeholder="T1110" value={f.mitre ?? ''} onChange={e => set({ mitre: e.target.value })} />
          </Field>
        </div>
        <Field label="Descrição / lógica">
          <input className="input w-full" placeholder="O que esta regra detecta" value={f.description ?? ''} onChange={e => set({ description: e.target.value })} />
        </Field>

        <div className="grid grid-cols-3 gap-3">
          <Field label="Severidade">
            <select className="select w-full" value={f.severity} onChange={e => set({ severity: e.target.value })}>
              {SEV_ORDER.filter(sv => sv !== 'info').map(sv => <option key={sv} value={sv}>{SEV_META[sv].label}</option>)}
            </select>
          </Field>
          <Field label="Janela (segundos)">
            <input type="number" className="input w-full font-mono" min={30} value={f.windowSec} onChange={e => set({ windowSec: Number(e.target.value) || 300 })} />
          </Field>
          <Field label="Threshold (≥ eventos)">
            <input type="number" className="input w-full font-mono" min={1} value={f.threshold} onChange={e => set({ threshold: Number(e.target.value) || 1 })} />
          </Field>
        </div>

        <div className="grid grid-cols-2 gap-3">
          <Field label="Agrupar por (chave do padrão)">
            <div className="flex flex-wrap gap-1.5">
              {GROUP_FIELDS.map(g => (
                <button key={g.id} onClick={() => toggleGroup(g.id)}
                  className={`chip ${f.groupBy.includes(g.id) ? 'on' : ''} font-mono`}>{g.label}</button>
              ))}
            </div>
          </Field>
          <Field label="Modo de qualificação">
            <select className="select w-full" value={f.mode} onChange={e => set({ mode: e.target.value })}>
              <option value="count">contagem de eventos ≥ threshold</option>
              <option value="distinct">regras distintas ≥ threshold (cadeia)</option>
            </select>
          </Field>
        </div>

        {hasAdvancedMatch && (
          <div className="rounded-lg border p-3" style={{ borderColor: '#ffc53d66', background: '#ffc53d0f' }}>
            <div className="flex items-center gap-2 text-[12px] text-ink/90">
              <span style={{ color: '#ffc53d' }}><Icon name="lock" size={12} /></span>
              Esta regra nativa usa critérios avançados (múltiplos IDs/regex{policy?.matchDef?.conditions ? ' · modo sequência' : ''}) que este formulário não edita — eles serão mantidos como estão. Para reverter tudo, use "Restaurar padrão".
            </div>
          </div>
        )}
        <div className="rounded-lg border border-line bg-panel p-3.5">
          <div className="lbl mb-2.5">Condições de casamento (match)</div>
          <div className="grid grid-cols-2 gap-3">
            <Field label="Regra ID contém">
              <input className="input w-full font-mono" placeholder="5551" value={(f.match?.ruleIdContains as string) ?? ''} onChange={e => setMatch({ ruleIdContains: e.target.value })} />
            </Field>
            <Field label="Nome da regra contém">
              <input className="input w-full" placeholder="brute" value={(f.match?.ruleContains as string) ?? ''} onChange={e => setMatch({ ruleContains: e.target.value })} />
            </Field>
            <Field label="Fonte">
              <select className="select w-full" value={(f.match?.source as string) ?? ''} onChange={e => setMatch({ source: e.target.value })}>
                <option value="">qualquer</option>
                <option value="Wazuh">Wazuh</option>
                <option value="FortiSIEM">FortiSIEM</option>
              </select>
            </Field>
            <Field label="Severidade mínima">
              <select className="select w-full" value={(f.match?.minSeverity as string) ?? ''} onChange={e => setMatch({ minSeverity: e.target.value })}>
                <option value="">qualquer</option>
                {SEV_ORDER.map(sv => <option key={sv} value={sv}>{SEV_META[sv].label}</option>)}
              </select>
            </Field>
          </div>
          <label className="mt-2.5 flex items-center gap-2 text-[12px] text-sub">
            <input type="checkbox" className="accent-[#2fd6a5]" checked={!!f.match?.dstExternal} onChange={e => setMatch({ dstExternal: e.target.checked })} />
            apenas destino externo (fora das redes privadas)
          </label>
        </div>

        {bt && (
          <div className="a-pop rounded-lg border border-cyan/40 bg-cyan/[.06] p-3.5">
            <div className="flex items-center gap-2">
              <Icon name="radar" size={14} className="text-cyan" />
              <span className="text-[12.5px] font-semibold text-ink/90">Backtest: {bt.firedCount} grupo(s) teriam disparado</span>
              <span className="ml-auto font-mono text-[10px] text-faint">{bt.evaluated} eventos avaliados · janela {bt.windowSec}s</span>
            </div>
            {bt.fired.length > 0 && (
              <div className="mt-2 flex flex-col gap-1">
                {bt.fired.slice(0, 5).map((g, i) => (
                  <div key={i} className="flex items-center gap-2 font-mono text-[10.5px] text-sub">
                    <span className="h-1 w-1 rounded-full bg-cyan" />
                    <span className="truncate">{g.title}</span>
                  </div>
                ))}
                {bt.firedCount > 5 && <span className="font-mono text-[9.5px] text-faint">+ {bt.firedCount - 5} outros…</span>}
              </div>
            )}
          </div>
        )}
      </div>
    </Modal>
  );
}
