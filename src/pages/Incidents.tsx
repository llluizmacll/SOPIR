import { useEffect, useMemo, useState } from 'react';
import type { Incident, Severity } from '../data/mock';
import { INC_FLOW, INC_STATUS_META, PRIORITY_META, SEV_META, SLA_HOURS, SLA_POLICY_DEMO, sevToPriority } from '../data/mock';
import { can, slaInfo, timeAgo, useNow, useStore } from '../lib/store';
import { Avatar, ConfirmDialog, EmptyState, Field, Icon, Modal, Pill, SevBadge } from '../components/ui';
import type { ConfirmState } from '../components/ui';
import { SLABar } from '../components/charts';

const KIND_ICON: Record<string, string> = { system: 'cpu', user: 'user', action: 'zap' };

export default function Incidents() {
  const { s, scope, nav, patchIncident, deleteIncident, toggleTask, addIncident, openCaseFromIncident } = useStore();
  const now = useNow(15000);
  const [statusFilter, setStatusFilter] = useState('all');
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [showNew, setShowNew] = useState(false);
  const [note, setNote] = useState('');
  const [bulk, setBulk] = useState<Set<string>>(new Set());
  const [confirm, setConfirm] = useState<ConfirmState | null>(null);
  const toggleBulk = (id: string) => setBulk(p => { const n = new Set(p); if (n.has(id)) n.delete(id); else n.add(id); return n; });

  // novo incidente (formulário)
  const [nTitle, setNTitle] = useState('');
  const [nSev, setNSev] = useState<Severity>('high');
  const [nDesc, setNDesc] = useState('');
  const [nAsset, setNAsset] = useState('');

  useEffect(() => {
    if (s.focus?.type === 'incident') { setSelectedId(s.focus.id); nav('incidents', null); }
    if (s.focus?.type === 'new') { setShowNew(true); nav('incidents', null); }
  }, [s.focus, nav]);

  const incidents = useMemo(() => scope(s.incidents), [s.incidents, s.tenant]); // eslint-disable-line react-hooks/exhaustive-deps
  const filtered = incidents.filter(i => statusFilter === 'all' || i.status === statusFilter);
  const sel: Incident | null = filtered.find(i => i.id === selectedId) ?? incidents.find(i => i.id === selectedId) ?? filtered[0] ?? null;

  const canUpdate = can(s.role, 'incidents.update');
  const assets = scope(s.assets);

  const submitNew = () => {
    if (!nTitle.trim()) return;
    addIncident({ title: nTitle.trim(), severity: nSev, desc: nDesc.trim(), asset: nAsset || undefined });
    setShowNew(false); setNTitle(''); setNDesc(''); setNAsset('');
  };

  return (
    <div className="flex h-full">
      {/* lista */}
      <div className="a-up flex w-[350px] shrink-0 flex-col border-r border-line bg-panel/30">
        <div className="flex items-center gap-2 border-b border-line px-4 py-3">
          {bulk.size === 0 ? (
            <>
              <select className="select flex-1 py-1.5! text-[11.5px]" value={statusFilter} onChange={e => setStatusFilter(e.target.value)}>
                <option value="all">Todos os status</option>
                {INC_FLOW.map(st => <option key={st} value={st}>{INC_STATUS_META[st].label}</option>)}
              </select>
              <button className="btn btn-primary btn-xs" onClick={() => setShowNew(true)} disabled={!canUpdate}>
                <Icon name="plus" size={12} /> Novo
              </button>
            </>
          ) : (
            <>
              <label className="flex items-center gap-1.5 text-[11px] text-sub">
                <input type="checkbox" className="accent-[#2fd6a5]" checked={filtered.every(i => bulk.has(i.id))}
                  onChange={() => setBulk(p => filtered.every(i => p.has(i.id)) ? new Set() : new Set(filtered.map(i => i.id)))} />
                {bulk.size} selecionado(s)
              </label>
              <button className="btn btn-xs btn-danger ml-auto" disabled={!canUpdate}
                onClick={() => setConfirm({
                  title: 'Excluir incidentes selecionados',
                  msg: `Excluir ${bulk.size} incidente(s) permanentemente? Essa ação não pode ser desfeita.`,
                  danger: true,
                  action: () => { bulk.forEach(id => deleteIncident(id)); setBulk(new Set()); },
                })}>
                <Icon name="trash" size={12} /> Excluir {bulk.size}
              </button>
            </>
          )}
        </div>
        <div className="min-h-0 flex-1 overflow-y-auto p-2">
          {filtered.length === 0 && <EmptyState icon="flame" title="Nenhum incidente" sub="Nada por aqui com esse filtro." />}
          {filtered.map(i => {
            const sla = slaInfo(i, now);
            const active = sel?.id === i.id;
            return (
              <div key={i.id} className="mb-1.5 flex items-start gap-1.5">
                <input type="checkbox" className="mt-3 shrink-0 accent-[#2fd6a5]" checked={bulk.has(i.id)} onChange={() => toggleBulk(i.id)} />
                <button onClick={() => setSelectedId(i.id)}
                  className={`w-full min-w-0 rounded-lg border px-3 py-2.5 text-left transition-all ${active ? 'border-teal/50 bg-teal/[.07]' : 'border-line bg-panel hover:border-line2'}`}>
                  <div className="flex items-center gap-2">
                    <span className="h-2 w-2 shrink-0 rounded-sm" style={{ background: SEV_META[i.severity].color, boxShadow: `0 0 6px ${SEV_META[i.severity].color}66` }} />
                    <span className="font-mono text-[11px] text-teal">{i.id}</span>
                    {i.priority && <span className="rounded px-1 py-px font-mono text-[9px] font-bold" style={{ color: PRIORITY_META[i.priority].color, background: PRIORITY_META[i.priority].color + '1a', border: `1px solid ${PRIORITY_META[i.priority].color}40` }}>{i.priority}</span>}
                    <span className="ml-auto"><Pill label={INC_STATUS_META[i.status].label} color={INC_STATUS_META[i.status].color} sm /></span>
                  </div>
                  <div className="mt-1.5 truncate text-[12.5px] font-medium text-ink/90">{i.title}</div>
                  <div className="mt-2 flex items-center gap-2">
                    <div className="flex-1"><SLABar pct={sla.pct} breached={sla.breached && !['resolvido', 'fechado'].includes(i.status)} /></div>
                    <span className={`font-mono text-[9.5px] ${sla.breached && !['resolvido', 'fechado'].includes(i.status) ? 'text-crit' : 'text-faint'}`}>
                      {['resolvido', 'fechado'].includes(i.status) ? 'encerrado' : sla.breached ? 'SLA estourado' : `${Math.round(sla.pct * 100)}%`}
                    </span>
                  </div>
                </button>
              </div>
            );
          })}
        </div>
      </div>

      {/* detalhe */}
      <div className="min-w-0 flex-1 overflow-y-auto">
        {!sel ? (
          <EmptyState icon="flame" title="Selecione um incidente" sub="Escolha um incidente na lista para ver timeline, tarefas, IOCs e SLA." />
        ) : (() => {
          const sla = slaInfo(sel, now);
          const idx = INC_FLOW.indexOf(sel.status);
          const next = INC_FLOW[Math.min(idx + 1, INC_FLOW.length - 1)];
          const linkedAlerts = s.alerts.filter(a => sel.alertIds.includes(a.id));
          const doneTasks = sel.tasks.filter(t => t.done).length;
          return (
            <div className="mx-auto flex max-w-[980px] flex-col gap-4 p-5">
              {/* header */}
              <div className="panel a-up p-5">
                <div className="flex flex-wrap items-start gap-3">
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2.5 flex-wrap">
                      <span className="font-mono text-[13px] text-teal">{sel.id}</span>
                      <SevBadge sev={sel.severity} />
                      {sel.priority && <Pill label={`${sel.priority} · ${PRIORITY_META[sel.priority].desc.split('—')[1]?.trim() ?? ''}`} color={PRIORITY_META[sel.priority].color} />}
                      <Pill label={INC_STATUS_META[sel.status].label} color={INC_STATUS_META[sel.status].color} />
                      {sel.caseId && (
                        <button className="font-mono text-[11px] text-cyan hover:underline" onClick={() => nav('cases', { type: 'case', id: sel.caseId! })}>
                          {sel.caseId} ↗
                        </button>
                      )}
                    </div>
                    <h2 className="mt-2 font-display text-[19px] font-bold leading-tight text-ink">{sel.title}</h2>
                    <div className="mt-2 flex items-center gap-3 text-[11.5px] text-faint flex-wrap">
                      <span className="flex items-center gap-1.5"><Avatar name={sel.assignee} size={20} /> {sel.assignee}</span>
                      <span>aberto {timeAgo(sel.ts)}</span>
                      {sel.asset && <span className="font-mono">ativo: {sel.asset}</span>}
                    </div>
                  </div>

                  {/* SLA duplo: resposta + resolução */}
                  <div className="flex w-full max-w-[300px] flex-col gap-2.5 sm:w-[300px]">
                    <div>
                      <div className="mb-1 flex items-center justify-between font-mono text-[9.5px] uppercase tracking-wide">
                        <span className="text-faint">SLA resposta · alvo {sla.resp.targetMin}min</span>
                        {sla.resp.done
                          ? <span className="text-teal">✓ {sla.resp.actualMin}min</span>
                          : <span className={sla.resp.breached ? 'text-crit' : 'text-cyan'}>{sla.resp.breached ? 'estourado' : `${Math.round(sla.resp.left / 60_000)}min`}</span>}
                      </div>
                      <SLABar pct={sla.resp.pct} breached={sla.resp.breached && !sla.resp.done} />
                    </div>
                    <div>
                      <div className="mb-1 flex items-center justify-between font-mono text-[9.5px] uppercase tracking-wide">
                        <span className="text-faint">SLA resolução · alvo {Math.round(sla.targetMin / 60)}h</span>
                        {sla.at
                          ? <span className="text-teal">✓ {sla.actualMin != null ? Math.round(sla.actualMin / 60) + 'h' : ''}</span>
                          : <span className={sla.breached ? 'text-crit' : 'text-high'}>{sla.breached ? 'estourado' : `${Math.round(sla.left / 3_600_000)}h`}</span>}
                      </div>
                      <SLABar pct={sla.pct} breached={sla.breached && !['resolvido', 'fechado'].includes(sel.status)} />
                    </div>
                  </div>
                </div>

                {/* ações */}
                <div className="mt-4 flex flex-wrap items-center gap-2 border-t border-line pt-4">
                  {idx < INC_FLOW.length - 1 && (
                    <button className="btn btn-primary btn-xs" disabled={!canUpdate}
                      onClick={() => patchIncident(sel.id, { status: next }, `avançou status para ${INC_STATUS_META[next].label}`)}>
                      <Icon name="chevronRight" size={12} /> Avançar: {INC_STATUS_META[next].label}
                    </button>
                  )}
                  <select className="select py-1! text-[11px]" value={sel.severity} disabled={!canUpdate}
                    onChange={e => {
                      const sv = e.target.value as Severity;
                      patchIncident(sel.id, { severity: sv, slaH: SLA_HOURS[sv] }, `alterou severidade para ${SEV_META[sv].label} (SLA ${SLA_HOURS[sv]}h)`);
                    }}>
                    {(Object.keys(SEV_META) as Severity[]).map(sv => <option key={sv} value={sv}>{SEV_META[sv].label} · SLA {SLA_HOURS[sv]}h</option>)}
                  </select>
                  <select className="select py-1! text-[11px]" value={sel.assignee} disabled={!canUpdate}
                    onChange={e => patchIncident(sel.id, { assignee: e.target.value }, `reatribuiu para ${e.target.value}`)}>
                    {(sel.assignee && !s.analysts.includes(sel.assignee) ? [sel.assignee, ...s.analysts] : s.analysts)
                      .map(a => <option key={a} value={a}>{a}{a === sel.assignee && !s.analysts.includes(a) ? ' (inativo)' : ''}</option>)}
                  </select>
                  {!sel.caseId && (
                    <button className="btn btn-xs" disabled={!can(s.role, 'cases.update')} onClick={() => openCaseFromIncident(sel.id)}>
                      <Icon name="folder" size={12} /> Abrir case
                    </button>
                  )}
                  <button className="btn btn-xs ml-auto" onClick={() => nav('playbooks')}>
                    <Icon name="zap" size={12} /> Executar playbook
                  </button>
                  <button className="btn btn-xs btn-danger" disabled={!canUpdate}
                    title="Excluir incidente permanentemente"
                    onClick={() => setConfirm({
                      title: 'Excluir incidente',
                      msg: `Excluir o incidente "${sel.title}" (${sel.id}) permanentemente? Essa ação não pode ser desfeita.`,
                      danger: true,
                      action: () => { deleteIncident(sel.id); setSelectedId(null); },
                    })}>
                    <Icon name="trash" size={12} />
                  </button>
                </div>
              </div>

              <div className="grid grid-cols-1 gap-4 lg:grid-cols-5">
                {/* timeline */}
                <div className="panel a-up lg:col-span-3" style={{ animationDelay: '80ms' }}>
                  <div className="panel-hd"><Icon name="history" size={14} className="text-teal" />
                    <h3 className="font-display text-[11.5px] font-semibold uppercase tracking-[0.14em]">Timeline</h3>
                    <span className="ml-auto font-mono text-[10px] text-faint">{sel.timeline.length} entradas</span>
                  </div>
                  <div className="p-4">
                    <div className="relative ml-2 flex flex-col gap-3.5 border-l border-line2 pl-5">
                      {[...sel.timeline].reverse().map((t, i) => (
                        <div key={i} className="relative">
                          <span className="absolute -left-[27px] top-0.5 flex h-4 w-4 items-center justify-center rounded-full border border-line2 bg-panel2 text-sub">
                            <Icon name={KIND_ICON[t.kind] ?? 'activity'} size={9} />
                          </span>
                          <div className="text-[12.5px] leading-snug text-ink/90">{t.text}</div>
                          <div className="mt-0.5 font-mono text-[10px] text-faint">
                            {t.author ? `${t.author} · ` : ''}{timeAgo(t.ts)}
                          </div>
                        </div>
                      ))}
                    </div>
                    <div className="mt-4 flex gap-2 border-t border-line pt-3.5">
                      <input className="input flex-1" placeholder="Registrar entrada na timeline…" value={note}
                        onChange={e => setNote(e.target.value)}
                        onKeyDown={e => { if (e.key === 'Enter' && note.trim()) { patchIncident(sel.id, {}, note.trim()); setNote(''); } }} />
                      <button className="btn btn-xs" disabled={!note.trim() || !canUpdate}
                        onClick={() => { patchIncident(sel.id, {}, note.trim()); setNote(''); }}>
                        <Icon name="send" size={12} /> Registrar
                      </button>
                    </div>
                  </div>
                </div>

                <div className="flex flex-col gap-4 lg:col-span-2">
                  {/* tarefas */}
                  <div className="panel a-up" style={{ animationDelay: '140ms' }}>
                    <div className="panel-hd"><Icon name="check" size={14} className="text-teal" />
                      <h3 className="font-display text-[11.5px] font-semibold uppercase tracking-[0.14em]">Tarefas</h3>
                      <span className="ml-auto font-mono text-[10px] text-faint">{doneTasks}/{sel.tasks.length}</span>
                    </div>
                    <div className="p-3.5">
                      {sel.tasks.map(t => (
                        <button key={t.id} className="flex w-full items-center gap-2.5 rounded-md px-2 py-[7px] text-left hover:bg-raise transition-colors"
                          onClick={() => canUpdate && toggleTask(sel.id, t.id)}>
                          <span className={`flex h-4 w-4 shrink-0 items-center justify-center rounded border transition-colors ${t.done ? 'border-teal bg-teal text-[#04160f]' : 'border-line2'}`}>
                            {t.done && <Icon name="check" size={10} strokeWidth={3} />}
                          </span>
                          <span className={`text-[12px] ${t.done ? 'text-faint line-through' : 'text-ink/90'}`}>{t.text}</span>
                        </button>
                      ))}
                    </div>
                  </div>

                  {/* IOCs */}
                  <div className="panel a-up" style={{ animationDelay: '200ms' }}>
                    <div className="panel-hd"><Icon name="target" size={14} className="text-high" />
                      <h3 className="font-display text-[11.5px] font-semibold uppercase tracking-[0.14em]">IOCs</h3>
                    </div>
                    <div className="flex flex-col gap-1.5 p-3.5">
                      {sel.iocs.length === 0 && <span className="text-[11.5px] text-faint">Nenhum IOC vinculado.</span>}
                      {sel.iocs.map(ioc => (
                        <div key={ioc} className="flex items-center gap-2 rounded-md border border-line/70 bg-panel px-2.5 py-1.5">
                          <span className="h-1.5 w-1.5 rounded-full bg-high" />
                          <span className="truncate font-mono text-[10.5px] text-ink/80" title={ioc}>{ioc}</span>
                          <button className="ml-auto shrink-0 text-faint hover:text-high transition-colors" title="Bloquear via playbook"
                            onClick={() => nav('playbooks', { type: 'pb', id: 'PB-IOC' })}>
                            <Icon name="zap" size={12} />
                          </button>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>

                {/* alertas vinculados */}
                <div className="panel a-up lg:col-span-5" style={{ animationDelay: '240ms' }}>
                  <div className="panel-hd"><Icon name="bell" size={14} className="text-med" />
                    <h3 className="font-display text-[11.5px] font-semibold uppercase tracking-[0.14em]">Alertas vinculados</h3>
                    <span className="ml-auto font-mono text-[10px] text-faint">{linkedAlerts.length}</span>
                  </div>
                  {linkedAlerts.length === 0 ? (
                    <div className="px-4 py-4 text-[12px] text-faint">Nenhum alerta vinculado — incidentes manuais podem receber alertas pela correlação.</div>
                  ) : linkedAlerts.map(a => (
                    <button key={a.id} className="flex w-full items-center gap-3 border-t border-line/60 px-4 py-2.5 text-left first:border-t-0 hover:bg-raise transition-colors"
                      onClick={() => nav('alerts', { type: 'alert', id: a.id })}>
                      <SevBadge sev={a.severity} sm />
                      <span className="font-mono text-[11px] text-teal">{a.id}</span>
                      <span className="min-w-0 flex-1 truncate text-[12.5px] text-ink/90">{a.title}</span>
                      <span className="hidden md:block font-mono text-[10.5px] text-faint">{a.host} · {timeAgo(a.ts)}</span>
                      <Icon name="arrowUpRight" size={12} className="text-faint" />
                    </button>
                  ))}
                </div>
              </div>
            </div>
          );
        })()}
      </div>

      {/* modal novo incidente */}
      <Modal open={showNew} onClose={() => setShowNew(false)} title="Novo incidente"
        footer={<>
          <button className="btn btn-xs" onClick={() => setShowNew(false)}>Cancelar</button>
          <button className="btn btn-primary btn-xs" onClick={submitNew} disabled={!nTitle.trim()}>
            <Icon name="flame" size={12} /> Abrir incidente
          </button>
        </>}>
        <div className="flex flex-col gap-3.5">
          <Field label="Título">
            <input className="input w-full" placeholder="Ex.: Atividade suspeita no servidor de pagamentos" value={nTitle} onChange={e => setNTitle(e.target.value)} autoFocus />
          </Field>
          <div className="grid grid-cols-2 gap-3">
            <Field label="Severidade (define SLA + prioridade)">
              <select className="select w-full" value={nSev} onChange={e => setNSev(e.target.value as Severity)}>
                {(Object.keys(SLA_HOURS) as Severity[]).filter(sv => sv !== 'info').map(sv => (
                  <option key={sv} value={sv}>{SEV_META[sv].label} — resp {SLA_POLICY_DEMO[sv].responseMin}min · resol {SLA_HOURS[sv]}h</option>
                ))}
              </select>
            </Field>
            <Field label="Ativo afetado (opcional)">
              <select className="select w-full" value={nAsset} onChange={e => setNAsset(e.target.value)}>
                <option value="">— sem ativo —</option>
                {assets.map(a => <option key={a.id} value={a.name}>{a.name}</option>)}
              </select>
            </Field>
          </div>
          <div className="flex items-center gap-2.5">
            <span className="rounded px-2 py-1 font-mono text-[11px] font-bold"
              style={{ color: PRIORITY_META[sevToPriority(nSev)].color, background: PRIORITY_META[sevToPriority(nSev)].color + '1a', border: `1px solid ${PRIORITY_META[sevToPriority(nSev)].color}40` }}>
              {sevToPriority(nSev)}
            </span>
            <span className="text-[12px] text-sub">{PRIORITY_META[sevToPriority(nSev)].desc}</span>
          </div>
          <Field label="Descrição inicial">
            <textarea className="input w-full min-h-[84px] resize-none" placeholder="Contexto, impacto observado, primeiros indícios…" value={nDesc} onChange={e => setNDesc(e.target.value)} />
          </Field>
          <div className="rounded-md border border-line bg-panel px-3 py-2 font-mono text-[10.5px] text-faint">
            {sevToPriority(nSev)} · SLA resposta: {SLA_POLICY_DEMO[nSev].responseMin}min · SLA resolução: {SLA_HOURS[nSev]}h · responsável: você · trilha de auditoria ativada
          </div>
        </div>
      </Modal>
      <ConfirmDialog state={confirm} onClose={() => setConfirm(null)} />
    </div>
  );
}
