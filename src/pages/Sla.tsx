import { useCallback, useEffect, useMemo, useState } from 'react';
import type { Severity } from '../data/mock';
import { SEV_META, SEV_ORDER, SLA_POLICY_DEMO } from '../data/mock';
import { can, slaInfo, timeAgo, useNow, useStore } from '../lib/store';
import { api as srv } from '../lib/api';
import type { SlaMetrics, SlaPolicy } from '../lib/api';
import { EmptyState, Icon, Panel, Pill, SevBadge } from '../components/ui';
import { SLABar } from '../components/charts';

function fmtMin(min: number | null): string {
  if (min == null) return '—';
  if (min < 60) return `${min}min`;
  const h = Math.floor(min / 60);
  const m = min % 60;
  if (h < 24) return m ? `${h}h ${m}min` : `${h}h`;
  return `${Math.floor(h / 24)}d ${h % 24}h`;
}

function pctColor(p: number): string {
  return p >= 95 ? '#2fd6a5' : p >= 85 ? '#ffc53d' : '#ff4d5e';
}

/** Métricas de conformidade calculadas localmente (modo demo). */
function demoMetrics(incidents: ReturnType<typeof useStore>['s']['incidents'], now: number): SlaMetrics {
  let respOk = 0, respTotal = 0, resOk = 0, resTotal = 0;
  let respSum = 0, respN = 0, resSum = 0, resN = 0;
  const activeBreaches: SlaMetrics['activeBreaches'] = [];
  const bySeverity: SlaMetrics['bySeverity'] = {};

  for (const i of incidents) {
    const sla = slaInfo(i, now);
    const open = !['resolvido', 'fechado'].includes(i.status);
    const bucket = bySeverity[i.severity] ?? (bySeverity[i.severity] = { total: 0, respBreached: 0, resBreached: 0 });
    bucket.total += 1;

    respTotal += 1;
    if (!sla.resp.breached) respOk += 1; else bucket.respBreached += 1;
    if (sla.resp.at != null) { respSum += sla.resp.actualMin ?? 0; respN += 1; }

    resTotal += 1;
    if (!sla.breached) resOk += 1;
    else {
      bucket.resBreached += 1;
      if (open) activeBreaches.push({ code: i.id, severity: i.severity, status: i.status, overMin: Math.round(-sla.left / 60_000) });
    }
    if (sla.at != null) { resSum += sla.actualMin ?? 0; resN += 1; }
  }

  return {
    compliance: {
      response: respTotal ? Math.round((respOk / respTotal) * 100) : 100,
      resolution: resTotal ? Math.round((resOk / resTotal) * 100) : 100,
    },
    mttr: {
      responseMin: respN ? Math.round(respSum / respN) : null,
      resolutionMin: resN ? Math.round(resSum / resN) : null,
    },
    total: incidents.length,
    activeBreaches: activeBreaches.sort((a, b) => b.overMin - a.overMin),
    bySeverity,
  };
}

export default function Sla() {
  const { s, scope, nav, backend, tenantName, toast } = useStore();
  const now = useNow(15000);
  const online = backend === 'online';
  const canEdit = can(s.role, 'sla.update') || s.role === 'Admin';
  const tenant = s.tenant === 'all' ? 'vetra' : s.tenant;

  const incidents = useMemo(() => scope(s.incidents), [s.incidents, s.tenant, s.env]); // eslint-disable-line react-hooks/exhaustive-deps

  const [metrics, setMetrics] = useState<SlaMetrics | null>(null);
  const [loading, setLoading] = useState(false);
  const loadMetrics = useCallback(async () => {
    if (online) {
      setLoading(true);
      const m = await srv.slaMetrics(s.tenant === 'all' ? undefined : tenant);
      if (m) setMetrics(m);
      setLoading(false);
    } else {
      setMetrics(demoMetrics(incidents, now));
    }
  }, [online, tenant, s.tenant, incidents, now]);
  useEffect(() => { void loadMetrics(); }, [loadMetrics]);

  const [policies, setPolicies] = useState<SlaPolicy[] | null>(null);
  const loadPolicies = useCallback(async () => {
    if (online) {
      const p = await srv.slaPolicies(tenant);
      if (p) setPolicies(p);
    } else {
      setPolicies(SEV_ORDER.map(sev => ({ tenant, severity: sev, responseMin: SLA_POLICY_DEMO[sev].responseMin, resolutionMin: SLA_POLICY_DEMO[sev].resolutionMin })));
    }
  }, [online, tenant]);
  useEffect(() => { void loadPolicies(); }, [loadPolicies]);

  // rascunho de edição da política
  const [draft, setDraft] = useState<Record<string, { responseMin: string; resolutionMin: string }>>({});
  const [saving, setSaving] = useState<string | null>(null);

  const startEdit = (p: SlaPolicy) => setDraft(d => ({ ...d, [p.severity]: { responseMin: String(p.responseMin), resolutionMin: String(p.resolutionMin) } }));
  const cancelEdit = (sev: string) => setDraft(d => { const n = { ...d }; delete n[sev]; return n; });
  const savePolicy = async (p: SlaPolicy) => {
    const d = draft[p.severity];
    if (!d) return;
    const rm = Number(d.responseMin), sm = Number(d.resolutionMin);
    if (!rm || !sm || rm < 1 || sm < 1) { toast('err', 'Valores devem ser números ≥ 1 (minutos)'); return; }
    setSaving(p.severity);
    if (online) {
      const r = await srv.updateSlaPolicy(tenant, p.severity, rm, sm);
      if (r?.ok) { toast('ok', `SLA ${p.severity} atualizado: resposta ${rm}min / resolução ${sm}min`); await loadPolicies(); }
      else toast('err', r?.error ?? 'Falha ao salvar política');
    } else {
      setPolicies(pl => pl ? pl.map(x => x.severity === p.severity ? { ...x, responseMin: rm, resolutionMin: sm } : x) : pl);
      toast('ok', `SLA ${p.severity} atualizado (modo demonstração)`);
    }
    setSaving(null);
    cancelEdit(p.severity);
  };

  const m = metrics;
  const open = incidents.filter(i => !['resolvido', 'fechado'].includes(i.status));
  const aging = open
    .map(i => ({ i, sla: slaInfo(i, now) }))
    .sort((a, b) => a.sla.left - b.sla.left);

  return (
    <div className="h-full overflow-y-auto">
      <div className="mx-auto flex max-w-[1500px] flex-col gap-4 p-5">

        {/* cabeçalho com os dois grandes números de conformidade */}
        <div className="a-up flex flex-wrap items-end justify-between gap-4">
          <div>
            <div className="lbl mb-1 flex items-center gap-2">
              <span className="inline-block h-1.5 w-1.5 rounded-full bg-teal dot-live" />
              incident management · {tenantName}
            </div>
            <h2 className="font-display text-[22px] font-bold tracking-tight text-ink">
              SLA de <span className="text-teal">resposta</span> e <span className="text-high">resolução</span> em tempo real
            </h2>
          </div>

          {m && (
            <div className="flex items-stretch gap-3">
              <div className="panel flex flex-col items-center justify-center px-6 py-3">
                <div className="font-mono text-[34px] font-bold leading-none tabular-nums" style={{ color: pctColor(m.compliance.response) }}>{m.compliance.response}%</div>
                <div className="lbl mt-1.5">conformidade resposta</div>
              </div>
              <div className="panel flex flex-col items-center justify-center px-6 py-3">
                <div className="font-mono text-[34px] font-bold leading-none tabular-nums" style={{ color: pctColor(m.compliance.resolution) }}>{m.compliance.resolution}%</div>
                <div className="lbl mt-1.5">conformidade resolução</div>
              </div>
              <div className="panel flex flex-col items-center justify-center px-6 py-3">
                <div className="font-mono text-[34px] font-bold leading-none tabular-nums text-ink">{m.total}</div>
                <div className="lbl mt-1.5">incidentes</div>
              </div>
            </div>
          )}
        </div>

        {loading && !m && <div className="py-10 text-center text-[12px] text-faint">calculando conformidade…</div>}

        {m && (
          <>
            {/* MTTR / MTTA + violações ativas */}
            <div className="grid grid-cols-12 gap-4">
              <Panel title="Tempo médio (MTTA / MTTR)" icon="clock" className="col-span-12 md:col-span-5" delay={60}>
                <div className="grid grid-cols-2 gap-4">
                  <div className="rounded-lg border border-line bg-panel p-4 text-center">
                    <div className="font-mono text-[26px] font-bold text-cyan tabular-nums">{fmtMin(m.mttr.responseMin)}</div>
                    <div className="lbl mt-1">MTTA · 1ª resposta</div>
                    <div className="mt-1 text-[10.5px] text-faint">abertura → primeiro movimento</div>
                  </div>
                  <div className="rounded-lg border border-line bg-panel p-4 text-center">
                    <div className="font-mono text-[26px] font-bold text-teal tabular-nums">{fmtMin(m.mttr.resolutionMin)}</div>
                    <div className="lbl mt-1">MTTR · resolução</div>
                    <div className="mt-1 text-[10.5px] text-faint">abertura → resolvido</div>
                  </div>
                </div>
                <p className="mt-3.5 text-[11px] leading-relaxed text-faint">
                  MTTA mede a agilidade da triagem; MTTR, a capacidade de resolver. Ambos caem quando o
                  playbook automatiza a contenção e a política de SLA é realista por severidade.
                </p>
              </Panel>

              <Panel title="Violações de resolução em curso" icon="alertTriangle" className="col-span-12 md:col-span-7" delay={100} pad={false}>
                {m.activeBreaches.length === 0 ? (
                  <EmptyState icon="check" title="Nenhuma violação ativa" sub="Todos os incidentes abertos estão dentro do SLA de resolução." />
                ) : (
                  <div>
                    {m.activeBreaches.slice(0, 6).map((b, i) => (
                      <button key={b.code} onClick={() => nav('incidents', { type: 'incident', id: b.code })}
                        className="a-row flex w-full items-center gap-3 border-t border-line/60 px-5 py-2.5 text-left first:border-t-0 hover:bg-raise transition-colors"
                        style={{ animationDelay: `${i * 40}ms` }}>
                        <SevBadge sev={b.severity as Severity} sm />
                        <span className="font-mono text-[11px] text-teal">{b.code}</span>
                        <Pill label={b.status} color="#ff9142" sm />
                        <span className="ml-auto flex items-center gap-1.5 font-mono text-[11px] font-semibold text-crit">
                          <Icon name="clock" size={12} /> +{fmtMin(b.overMin)} além do SLA
                        </span>
                        <Icon name="arrowUpRight" size={12} className="text-faint" />
                      </button>
                    ))}
                  </div>
                )}
              </Panel>
            </div>

            {/* envelhecimento dos abertos — barra dupla resposta/resolução */}
            <Panel title="Incidentes abertos — envelhecimento (resposta · resolução)" icon="activity" delay={140} pad={false}>
              {aging.length === 0 ? (
                <EmptyState icon="flame" title="Nenhum incidente aberto" sub="Fila vazia — operação em dia." />
              ) : (
                <div className="overflow-x-auto">
                  <table className="tbl min-w-[760px]">
                    <thead>
                      <tr>
                        <th>Incidente</th>
                        <th className="w-[80px]">Sev / Pri</th>
                        <th className="w-[240px]">SLA resposta</th>
                        <th className="w-[240px]">SLA resolução</th>
                        <th className="w-[90px]">Aberto há</th>
                      </tr>
                    </thead>
                    <tbody>
                      {aging.map(({ i, sla }, idx) => (
                        <tr key={i.id} className="a-row cursor-pointer" style={{ animationDelay: `${idx * 35}ms` }}
                          onClick={() => nav('incidents', { type: 'incident', id: i.id })}>
                          <td>
                            <div className="font-mono text-[11px] text-teal">{i.id}</div>
                            <div className="max-w-[280px] truncate text-[12px] text-ink/90">{i.title}</div>
                          </td>
                          <td>
                            <div className="flex flex-col gap-1 items-start">
                              <SevBadge sev={i.severity} sm />
                              {i.priority && <Pill label={i.priority} color={i.priority === 'P1' ? '#ff4d5e' : i.priority === 'P2' ? '#ff9142' : i.priority === 'P3' ? '#ffc53d' : '#5aa2ff'} sm />}
                            </div>
                          </td>
                          <td>
                            {sla.resp.done ? (
                              <span className="flex items-center gap-1.5 font-mono text-[10.5px] text-teal"><Icon name="check" size={11} /> respondido em {fmtMin(sla.resp.actualMin)}</span>
                            ) : (
                              <>
                                <SLABar pct={sla.resp.pct} breached={sla.resp.breached} />
                                <div className="mt-1 font-mono text-[9.5px]" style={{ color: sla.resp.breached ? '#ff4d5e' : '#93a6c9' }}>
                                  {sla.resp.breached ? `estourado há ${fmtMin(Math.round(-sla.resp.left / 60_000))}` : `${fmtMin(Math.round(sla.resp.left / 60_000))} restantes`}
                                </div>
                              </>
                            )}
                          </td>
                          <td>
                            <SLABar pct={sla.pct} breached={sla.breached} />
                            <div className="mt-1 font-mono text-[9.5px]" style={{ color: sla.breached ? '#ff4d5e' : '#93a6c9' }}>
                              {sla.breached ? `estourado há ${fmtMin(Math.round(-sla.left / 60_000))}` : `${fmtMin(Math.round(sla.left / 60_000))} restantes`}
                            </div>
                          </td>
                          <td className="font-mono text-[10.5px] text-faint">{timeAgo(i.ts)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </Panel>

            <div className="grid grid-cols-12 gap-4">
              {/* conformidade por severidade */}
              <Panel title="Conformidade por severidade" icon="layers" className="col-span-12 md:col-span-5" delay={180}>
                <div className="flex flex-col gap-3">
                  {SEV_ORDER.filter(sv => m.bySeverity[sv]).map(sv => {
                    const b = m.bySeverity[sv];
                    const resPct = b.total ? Math.round(((b.total - b.resBreached) / b.total) * 100) : 100;
                    const respPct = b.total ? Math.round(((b.total - b.respBreached) / b.total) * 100) : 100;
                    return (
                      <div key={sv}>
                        <div className="mb-1 flex items-center gap-2">
                          <span className="h-2 w-2 rounded-sm" style={{ background: SEV_META[sv].color }} />
                          <span className="text-[12px] font-medium text-ink/90">{SEV_META[sv].label}</span>
                          <span className="font-mono text-[10px] text-faint">{b.total} inc</span>
                          <span className="ml-auto font-mono text-[10.5px]" style={{ color: pctColor(resPct) }}>{resPct}%</span>
                        </div>
                        <div className="flex gap-1">
                          <div className="flex-1">
                            <SLABar pct={respPct / 100} breached={respPct < 85} />
                          </div>
                          <div className="flex-1">
                            <SLABar pct={resPct / 100} breached={resPct < 85} />
                          </div>
                        </div>
                        <div className="mt-0.5 flex justify-between font-mono text-[8.5px] text-faint">
                          <span>resposta {respPct}%</span><span>resolução {resPct}%</span>
                        </div>
                      </div>
                    );
                  })}
                  {Object.keys(m.bySeverity).length === 0 && <span className="text-[11.5px] text-faint">Sem incidentes no escopo.</span>}
                </div>
              </Panel>

              {/* editor de políticas */}
              <Panel title={`Políticas de SLA — ${tenantName}`} icon="settings" className="col-span-12 md:col-span-7" delay={220} pad={false}
                right={!canEdit ? <span className="flex items-center gap-1 font-mono text-[10px] text-faint"><Icon name="lock" size={10} /> leitura</span> : undefined}>
                {!policies ? (
                  <div className="py-10 text-center text-[12px] text-faint">carregando políticas…</div>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="tbl min-w-[560px]">
                      <thead>
                        <tr>
                          <th>Severidade</th>
                          <th className="w-[150px]">SLA resposta</th>
                          <th className="w-[150px]">SLA resolução</th>
                          <th className="text-right pr-5 w-[120px]">Ação</th>
                        </tr>
                      </thead>
                      <tbody>
                        {policies.map((p, i) => {
                          const editing = !!draft[p.severity];
                          return (
                            <tr key={p.severity} className="a-row" style={{ animationDelay: `${i * 35}ms` }}>
                              <td><SevBadge sev={p.severity as Severity} /></td>
                              <td>
                                {editing ? (
                                  <input type="number" min={1} className="input w-full py-1! font-mono text-[11px]"
                                    value={draft[p.severity].responseMin}
                                    onChange={e => setDraft(d => ({ ...d, [p.severity]: { ...d[p.severity], responseMin: e.target.value } }))} />
                                ) : (
                                  <span className="font-mono text-[11.5px] text-ink/90">{fmtMin(p.responseMin)}</span>
                                )}
                              </td>
                              <td>
                                {editing ? (
                                  <input type="number" min={1} className="input w-full py-1! font-mono text-[11px]"
                                    value={draft[p.severity].resolutionMin}
                                    onChange={e => setDraft(d => ({ ...d, [p.severity]: { ...d[p.severity], resolutionMin: e.target.value } }))} />
                                ) : (
                                  <span className="font-mono text-[11.5px] text-ink/90">{fmtMin(p.resolutionMin)}</span>
                                )}
                              </td>
                              <td className="text-right pr-5">
                                {canEdit && (editing ? (
                                  <span className="inline-flex gap-1.5">
                                    <button className="btn btn-primary btn-xs" disabled={saving === p.severity} onClick={() => void savePolicy(p)}>
                                      <Icon name={saving === p.severity ? 'refresh' : 'check'} size={11} /> {saving === p.severity ? '…' : 'salvar'}
                                    </button>
                                    <button className="btn btn-xs" onClick={() => cancelEdit(p.severity)}><Icon name="x" size={11} /></button>
                                  </span>
                                ) : (
                                  <button className="btn btn-ghost btn-xs" onClick={() => startEdit(p)}><Icon name="edit" size={12} /> editar</button>
                                ))}
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                    <div className="border-t border-line px-5 py-3 font-mono text-[10px] text-faint">
                      valores em minutos · aplicados a novos incidentes e ao recálculo de conformidade do tenant
                    </div>
                  </div>
                )}
              </Panel>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
