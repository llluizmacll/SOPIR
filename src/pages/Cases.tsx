import { useEffect, useMemo, useState } from 'react';
import type { Case, CaseStage, Priority, Severity } from '../data/mock';
import {
  ANALYSTS, CASE_SLA_MIN_DEMO, CASE_STATUS_META, CASE_STAGES, CASE_TEMPLATES_DEMO,
  PRIORITY_META, PRIORITY_ORDER, SEV_META, SEV_ORDER, sevToPriority,
} from '../data/mock';
import { can, timeAgo, useNow, useStore } from '../lib/store';
import { Avatar, Drawer, EmptyState, Field, Icon, Modal, Pill, SevBadge } from '../components/ui';
import type { IconName } from '../components/icons';

const STAGE_COLOR: Record<string, string> = {
  Triagem: '#56c4ff', 'Investigação': '#ffc53d', 'Contenção': '#ff9142', 'Recuperação': '#5aa2ff', Encerrado: '#2fd6a5',
};
const STAGE_ICON: Record<string, IconName> = {
  Triagem: 'filter', 'Investigação': 'search', 'Contenção': 'shield', 'Recuperação': 'refresh', Encerrado: 'check',
};
const REL_META: { kind: 'alert' | 'incident' | 'asset' | 'ioc' | 'evidence'; label: string; icon: IconName; color: string }[] = [
  { kind: 'alert', label: 'Alertas', icon: 'bell', color: '#ffc53d' },
  { kind: 'incident', label: 'Incidentes', icon: 'flame', color: '#ff9142' },
  { kind: 'asset', label: 'Ativos', icon: 'server', color: '#56c4ff' },
  { kind: 'ioc', label: 'IOCs', icon: 'target', color: '#ff4d5e' },
  { kind: 'evidence', label: 'Evidências', icon: 'file', color: '#8fa3c8' },
];

const fmtDur = (min: number) => {
  if (min < 60) return `${min}min`;
  const h = Math.floor(min / 60);
  const m = min % 60;
  if (h < 24) return `${h}h${m ? ' ' + m + 'm' : ''}`;
  const d = Math.floor(h / 24);
  return `${d}d ${h % 24}h`;
};

const lastStageTs = (c: Case) =>
  [...(c.timeline ?? [])].reverse().find(t => t.kind === 'stage')?.ts ?? c.openedAt ?? c.ts;

type Tab = 'overview' | 'relations' | 'tasks' | 'timeline' | 'comments';

export default function Cases() {
  const {
    s, scope, nav, refresh,
    advanceCase, setCaseStage, addComment, addCase,
    patchCaseMeta, closeCase, reopenCase,
    addCaseTask, toggleCaseTask, removeCaseTask,
    addCaseRelation, removeCaseRelation,
  } = useStore();
  const now = useNow(15000);

  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [tab, setTab] = useState<Tab>('overview');
  const [q, setQ] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [showNew, setShowNew] = useState(false);

  useEffect(() => {
    if (s.focus?.type === 'case') { setSelectedId(s.focus.id); setTab('overview'); nav('cases', null); }
  }, [s.focus, nav]);

  const all = useMemo(() => scope(s.cases), [s.cases, s.tenant]); // eslint-disable-line react-hooks/exhaustive-deps
  const cases = all.filter(c => {
    if (statusFilter !== 'all' && (c.status ?? 'active') !== statusFilter) return false;
    const query = q.trim().toLowerCase();
    if (query && ![c.id, c.title, c.assignee].some(f => f.toLowerCase().includes(query))) return false;
    return true;
  });
  const sel: Case | null = all.find(c => c.id === selectedId) ?? null;
  const canUpdate = can(s.role, 'cases.update');

  // métricas do ciclo operacional (derivadas do escopo atual)
  const metrics = useMemo(() => {
    const active = all.filter(c => (c.status ?? 'active') === 'active');
    const onHold = all.filter(c => c.status === 'on_hold');
    const closed = all.filter(c => c.status === 'closed');
    const weekAgo = now - 7 * 86_400_000;
    const closedWeek = closed.filter(c => (c.closedAt ?? 0) > weekAgo).length;
    const cycles = closed.map(c => ((c.closedAt ?? c.ts) - (c.openedAt ?? c.ts)) / 60_000);
    const avgCycleMin = cycles.length ? Math.round(cycles.reduce((a, b) => a + b, 0) / cycles.length) : null;
    const within = all.filter(c => {
      const end = c.status === 'closed' ? (c.closedAt ?? c.ts) : now;
      return end - (c.openedAt ?? c.ts) <= (c.slaMin ?? 4320) * 60_000;
    }).length;
    const slaCompliance = all.length ? Math.round((within / all.length) * 100) : 100;
    const overdue = active.filter(c => now - (c.openedAt ?? c.ts) > (c.slaMin ?? 4320) * 60_000).length;
    return { total: all.length, active: active.length, onHold: onHold.length, closedWeek, avgCycleMin, slaCompliance, overdue };
  }, [all, now]);

  return (
    <div className="flex h-full flex-col">
      {/* ── métricas do ciclo ── */}
      <div className="grid shrink-0 grid-cols-2 gap-3 border-b border-line bg-panel/30 px-5 py-3.5 md:grid-cols-3 xl:grid-cols-6">
        {[
          { label: 'Cases ativos', value: String(metrics.active), sub: `${metrics.onHold} em espera`, color: '#2fd6a5', icon: 'folder' as IconName },
          { label: 'Encerrados (7d)', value: String(metrics.closedWeek), sub: `${metrics.total} no total`, color: '#8fa3c8', icon: 'check' as IconName },
          { label: 'Ciclo médio', value: metrics.avgCycleMin != null ? fmtDur(metrics.avgCycleMin) : '—', sub: 'abertura → encerramento', color: '#56c4ff', icon: 'clock' as IconName },
          { label: 'Conformidade SLA', value: `${metrics.slaCompliance}%`, sub: 'dentro do alvo', color: metrics.slaCompliance >= 90 ? '#2fd6a5' : '#ffc53d', icon: 'shieldCheck' as IconName },
          { label: 'Vencidos', value: String(metrics.overdue), sub: 'ativos acima do alvo', color: metrics.overdue ? '#ff4d5e' : '#8fa3c8', icon: 'alertTriangle' as IconName },
          { label: 'Etapas', value: '5', sub: 'triagem → encerramento', color: '#ffc53d', icon: 'layers' as IconName },
        ].map((m, i) => (
          <div key={m.label} className="panel a-up px-3.5 py-2.5" style={{ animationDelay: `${i * 50}ms` }}>
            <div className="flex items-center justify-between">
              <span className="lbl !text-[9px]">{m.label}</span>
              <span style={{ color: m.color + '99' }}><Icon name={m.icon} size={13} /></span>
            </div>
            <div className="mt-1 font-mono text-[19px] font-bold leading-none tabular-nums" style={{ color: m.color }}>{m.value}</div>
            <div className="mt-1 text-[9.5px] text-faint">{m.sub}</div>
          </div>
        ))}
      </div>

      {/* ── toolbar ── */}
      <div className="a-up flex shrink-0 flex-wrap items-center gap-2.5 border-b border-line bg-panel/40 px-5 py-3">
        <div className="relative min-w-[180px]">
          <span className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-faint"><Icon name="search" size={13} /></span>
          <input className="input w-[220px] pl-8" placeholder="Buscar case…" value={q} onChange={e => setQ(e.target.value)} />
        </div>
        <select className="select" value={statusFilter} onChange={e => setStatusFilter(e.target.value)}>
          <option value="all">Todos os status</option>
          <option value="active">Ativos</option>
          <option value="on_hold">Em espera</option>
          <option value="closed">Encerrados</option>
        </select>
        <span className="ml-auto hidden font-mono text-[10.5px] text-faint md:inline">
          ciclo operacional: triagem → investigação → contenção → recuperação → encerramento
        </span>
        <button className="btn btn-primary btn-xs" onClick={() => setShowNew(true)} disabled={!canUpdate}>
          <Icon name="plus" size={12} /> Novo case
        </button>
      </div>

      {/* ── board ── */}
      <div className="min-h-0 flex-1 overflow-x-auto overflow-y-hidden">
        <div className="flex h-full min-w-max gap-3.5 p-4">
          {CASE_STAGES.map(stage => {
            const items = cases.filter(c => c.stage === stage);
            const sevCount = (sv: Severity) => items.filter(c => c.severity === sv).length;
            return (
              <div key={stage} className="flex h-full w-[272px] shrink-0 flex-col rounded-xl border border-line bg-panel/40">
                <div className="border-b border-line px-3.5 py-3">
                  <div className="flex items-center gap-2">
                    <span className="flex h-5 w-5 items-center justify-center rounded-md" style={{ background: STAGE_COLOR[stage] + '1f', color: STAGE_COLOR[stage] }}>
                      <Icon name={STAGE_ICON[stage]} size={11} />
                    </span>
                    <span className="font-display text-[11px] font-semibold uppercase tracking-[0.13em] text-ink/90">{stage}</span>
                    <span className="ml-auto rounded bg-raise px-1.5 py-0.5 font-mono text-[10px] text-sub">{items.length}</span>
                  </div>
                  <div className="mt-2 flex h-[4px] w-full overflow-hidden rounded-sm bg-[#0a1322]">
                    {SEV_ORDER.filter(sv => sv !== 'info').map(sv => sevCount(sv) > 0 && (
                      <div key={sv} style={{ width: `${(sevCount(sv) / Math.max(1, items.length)) * 100}%`, background: SEV_META[sv].color }} />
                    ))}
                  </div>
                </div>
                <div className="min-h-0 flex-1 overflow-y-auto p-2.5">
                  {items.length === 0 && (
                    <div className="rounded-lg border border-dashed border-line px-3 py-5 text-center text-[11px] text-faint">vazio</div>
                  )}
                  {items.map((c, idx) => {
                    const inStageMin = Math.max(1, Math.round((now - lastStageTs(c)) / 60_000));
                    const slaLeft = (c.slaMin ?? 4320) * 60_000 - (now - (c.openedAt ?? c.ts));
                    const overdue = (c.status ?? 'active') !== 'closed' && slaLeft < 0;
                    const doneTasks = (c.tasks ?? []).filter(t => t.done).length;
                    return (
                      <button key={c.id} onClick={() => { setSelectedId(c.id); setTab('overview'); }}
                        className="a-up group mb-2 w-full rounded-lg border border-line bg-panel p-3 text-left transition-all hover:-translate-y-[2px] hover:border-line2"
                        style={{ animationDelay: `${idx * 40}ms` }}>
                        <div className="flex items-center gap-1.5">
                          <span className="font-mono text-[10.5px] text-teal">{c.id}</span>
                          {c.priority && (
                            <span className="rounded px-1 py-px font-mono text-[8.5px] font-bold"
                              style={{ color: PRIORITY_META[c.priority].color, background: PRIORITY_META[c.priority].color + '1a', border: `1px solid ${PRIORITY_META[c.priority].color}40` }}>
                              {c.priority}
                            </span>
                          )}
                          {c.status === 'on_hold' && <Pill label="pausado" color="#ffc53d" sm />}
                          <span className={`ml-auto flex items-center gap-1 font-mono text-[9px] ${overdue ? 'text-crit' : 'text-faint'}`}>
                            <span className={`h-1.5 w-1.5 rounded-full ${overdue ? 'bg-crit dot-crit' : 'bg-faint/50'}`} />
                            {overdue ? `+${fmtDur(Math.round(-slaLeft / 60_000))}` : fmtDur(Math.round(slaLeft / 60_000))}
                          </span>
                        </div>
                        <div className="mt-1.5 line-clamp-2 text-[12.5px] font-medium leading-snug text-ink/90">{c.title}</div>
                        <div className="mt-2 flex items-center gap-2 text-[9.5px] text-faint">
                          <span className="flex items-center gap-1">
                            <span className="h-1.5 w-1.5 rounded-full" style={{ background: SEV_META[c.severity].color }} />
                            {SEV_META[c.severity].label}
                          </span>
                          <span>· {fmtDur(inStageMin)} na etapa</span>
                          {(c.tasks ?? []).length > 0 && <span>· {doneTasks}/{c.tasks!.length} tarefas</span>}
                        </div>
                        <div className="mt-2.5 flex items-center gap-2.5 border-t border-line/60 pt-2 font-mono text-[9.5px] text-faint">
                          <span className="flex items-center gap-1"><Icon name="bell" size={10} /> {c.alertIds.length}</span>
                          <span className="flex items-center gap-1"><Icon name="flame" size={10} /> {c.incidentIds.length}</span>
                          <span className="flex items-center gap-1"><Icon name="server" size={10} /> {c.assetNames.length}</span>
                          <span className="flex items-center gap-1"><Icon name="target" size={10} /> {c.iocs.length}</span>
                          <span className="ml-auto"><Avatar name={c.assignee} size={18} /></span>
                        </div>
                        {stage !== 'Encerrado' && (c.status ?? 'active') !== 'closed' && (
                          <span className="mt-2 flex items-center gap-1 text-[10.5px] font-medium text-teal opacity-0 transition-opacity group-hover:opacity-100"
                            onClick={e => { e.stopPropagation(); if (canUpdate) advanceCase(c.id); }}>
                            avançar etapa <Icon name="chevronRight" size={11} />
                          </span>
                        )}
                      </button>
                    );
                  })}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      <CaseDrawer
        sel={sel} tab={tab} setTab={setTab} onClose={() => setSelectedId(null)}
        canUpdate={canUpdate} now={now}
        onAdvance={advanceCase} onStage={setCaseStage} onMeta={patchCaseMeta}
        onCloseCase={closeCase} onReopen={reopenCase}
        onTaskAdd={addCaseTask} onTaskToggle={toggleCaseTask} onTaskRemove={removeCaseTask}
        onRelAdd={addCaseRelation} onRelRemove={removeCaseRelation}
        onComment={addComment} nav={nav}
      />

      <NewCaseModal open={showNew} onClose={() => setShowNew(false)} onCreate={addCase} />
      {/* mantém refresh acessível para sincronização pós-mutação quando online */}
      <span className="hidden">{typeof refresh}</span>
    </div>
  );
}

// ════════════════════════════════════════════════════════════
// Drawer do case — ciclo operacional completo
// ════════════════════════════════════════════════════════════
function CaseDrawer(props: {
  sel: Case | null; tab: Tab; setTab: (t: Tab) => void; onClose: () => void;
  canUpdate: boolean; now: number;
  onAdvance: (id: string) => void; onStage: (id: string, st: CaseStage) => void;
  onMeta: (id: string, patch: Partial<Pick<Case, 'priority' | 'status' | 'assignee'>>, log?: string) => void;
  onCloseCase: (id: string, summary?: string) => void; onReopen: (id: string) => void;
  onTaskAdd: (id: string, text: string) => void; onTaskToggle: (id: string, taskId: string) => void; onTaskRemove: (id: string, taskId: string) => void;
  onRelAdd: (id: string, kind: 'alert' | 'incident' | 'asset' | 'ioc' | 'evidence', value: string) => void;
  onRelRemove: (id: string, kind: 'alert' | 'incident' | 'asset' | 'ioc' | 'evidence', value: string) => void;
  onComment: (id: string, text: string) => void;
  nav: (r: 'alerts' | 'incidents' | 'assets', focus?: { type: string; id: string } | null) => void;
}) {
  const { sel, tab, setTab, onClose, canUpdate, now } = props;
  const [comment, setComment] = useState('');
  const [newTask, setNewTask] = useState('');
  const [closing, setClosing] = useState(false);
  const [summary, setSummary] = useState('');
  const [relInput, setRelInput] = useState<Record<string, string>>({});
  const { s } = useStore();

  useEffect(() => { setClosing(false); setSummary(''); setNewTask(''); setComment(''); }, [sel?.id]);

  if (!sel) return null;

  const stageIdx = CASE_STAGES.indexOf(sel.stage);
  const slaTotal = (sel.slaMin ?? 4320) * 60_000;
  const elapsed = (sel.status === 'closed' ? (sel.closedAt ?? now) : now) - (sel.openedAt ?? sel.ts);
  const slaLeft = slaTotal - elapsed;
  const overdue = sel.status !== 'closed' && slaLeft < 0;
  const doneTasks = (sel.tasks ?? []).filter(t => t.done).length;
  const relCount = sel.alertIds.length + sel.incidentIds.length + sel.assetNames.length + sel.iocs.length + sel.evidence.length;
  const timeline = [...(sel.timeline ?? [])].reverse();

  const tabs: { id: Tab; label: string; icon: IconName; badge?: string }[] = [
    { id: 'overview', label: 'Visão geral', icon: 'folder' },
    { id: 'relations', label: 'Relações', icon: 'network', badge: String(relCount) },
    { id: 'tasks', label: 'Tarefas', icon: 'check', badge: `${doneTasks}/${(sel.tasks ?? []).length}` },
    { id: 'timeline', label: 'Timeline', icon: 'history', badge: String(timeline.length) },
    { id: 'comments', label: 'Comentários', icon: 'user', badge: String(sel.comments.length) },
  ];

  return (
    <Drawer open onClose={onClose} width={680}
      title={
        <span className="flex items-center gap-2.5">
          <span className="font-mono text-teal">{sel.id}</span>
          {sel.priority && <Pill label={sel.priority} color={PRIORITY_META[sel.priority].color} sm />}
          <Pill label={CASE_STATUS_META[sel.status ?? 'active'].label} color={CASE_STATUS_META[sel.status ?? 'active'].color} sm />
        </span>
      }
      sub={
        <>
          <span className="font-display text-[13px] font-semibold text-ink">{sel.title}</span>
        </>
      }
      footer={
        sel.status !== 'closed' ? (
          <div className="flex items-center gap-2">
            <select className="select py-1.5! text-[11.5px]" value={sel.stage} disabled={!canUpdate}
              onChange={e => props.onStage(sel.id, e.target.value as CaseStage)}>
              {CASE_STAGES.map(st => <option key={st} value={st}>{st}</option>)}
            </select>
            {sel.stage !== 'Encerrado' && (
              <button className="btn btn-primary btn-xs" disabled={!canUpdate} onClick={() => props.onAdvance(sel.id)}>
                Avançar <Icon name="chevronRight" size={12} />
              </button>
            )}
            <button className="btn btn-xs ml-auto" disabled={!canUpdate} onClick={() => setClosing(v => !v)}>
              <Icon name="check" size={12} /> Encerrar case
            </button>
          </div>
        ) : (
          <div className="flex items-center gap-2">
            <span className="text-[11.5px] text-faint">
              Ciclo encerrado {sel.closedAt ? timeAgo(sel.closedAt) : ''} · duração {fmtDur(Math.round(elapsed / 60_000))}
            </span>
            <button className="btn btn-xs ml-auto" disabled={!canUpdate} onClick={() => props.onReopen(sel.id)}>
              <Icon name="refresh" size={12} /> Reabrir case
            </button>
          </div>
        )
      }>
      <div className="flex flex-col gap-4">
        {/* stepper de etapas + SLA */}
        <div className="rounded-lg border border-line bg-panel p-4">
          <div className="flex items-center">
            {CASE_STAGES.map((st, i) => {
              const done = i < stageIdx || sel.status === 'closed';
              const current = i === stageIdx && sel.status !== 'closed';
              const dur = sel.stageDurations?.[st];
              return (
                <div key={st} className={`flex items-center ${i < CASE_STAGES.length - 1 ? 'flex-1' : ''}`}>
                  <div className="flex flex-col items-center">
                    <span className={`flex h-7 w-7 items-center justify-center rounded-full border-2 transition-colors ${
                      done ? 'border-teal bg-teal text-[#04160f]'
                        : current ? 'border-cyan bg-cyan/15 text-cyan'
                        : 'border-line2 bg-panel2 text-faint'}`}>
                      {done ? <Icon name="check" size={12} strokeWidth={2.6} />
                        : current ? <span className="h-2 w-2 animate-pulse rounded-full bg-cyan" />
                        : <Icon name={STAGE_ICON[st]} size={11} />}
                    </span>
                    <span className={`mt-1 whitespace-nowrap text-[8.5px] font-mono ${current ? 'text-cyan' : done ? 'text-teal' : 'text-faint'}`}>
                      {dur != null ? fmtDur(dur) : st.slice(0, 5)}
                    </span>
                  </div>
                  {i < CASE_STAGES.length - 1 && (
                    <div className={`mx-1 mb-4 h-px flex-1 ${i < stageIdx || sel.status === 'closed' ? 'bg-teal/60' : 'bg-line2'}`} />
                  )}
                </div>
              );
            })}
          </div>
          <div className="mt-3 border-t border-line/60 pt-3">
            <div className="flex items-center justify-between font-mono text-[9.5px] uppercase tracking-wide">
              <span className="text-faint">SLA do case · alvo {fmtDur(Math.round(slaTotal / 60_000))}</span>
              {sel.status === 'closed'
                ? <span className={elapsed <= slaTotal ? 'text-teal' : 'text-crit'}>encerrado em {fmtDur(Math.round(elapsed / 60_000))}</span>
                : <span className={overdue ? 'text-crit' : 'text-cyan'}>{overdue ? `vencido há ${fmtDur(Math.round(-slaLeft / 60_000))}` : `${fmtDur(Math.round(slaLeft / 60_000))} restantes`}</span>}
            </div>
            <div className="mt-1.5 h-[6px] w-full overflow-hidden rounded-sm bg-[#0a1322]">
              <div className="h-full rounded-sm transition-all duration-700"
                style={{ width: `${Math.min(100, (elapsed / slaTotal) * 100)}%`, background: overdue ? '#ff4d5e' : elapsed <= slaTotal * 0.7 ? '#2fd6a5' : '#ffc53d' }} />
            </div>
          </div>
        </div>

        {/* encerramento com resumo */}
        {closing && sel.status !== 'closed' && (
          <div className="a-pop rounded-lg border border-teal/40 bg-teal/[.06] p-3.5">
            <div className="lbl mb-2">Resumo do encerramento</div>
            <textarea className="input w-full min-h-[64px] resize-none" placeholder="Causa raiz, ações tomadas, lições aprendidas…"
              value={summary} onChange={e => setSummary(e.target.value)} autoFocus />
            <div className="mt-2 flex justify-end gap-2">
              <button className="btn btn-xs" onClick={() => setClosing(false)}>Cancelar</button>
              <button className="btn btn-primary btn-xs" onClick={() => { props.onCloseCase(sel.id, summary.trim() || undefined); setClosing(false); }}>
                <Icon name="check" size={12} /> Confirmar encerramento
              </button>
            </div>
          </div>
        )}

        {/* tabs */}
        <div className="flex gap-1 border-b border-line">
          {tabs.map(t => (
            <button key={t.id} onClick={() => setTab(t.id)}
              className={`flex items-center gap-1.5 border-b-2 px-3 py-2 text-[12px] font-medium transition-colors ${
                tab === t.id ? 'border-teal text-ink' : 'border-transparent text-faint hover:text-sub'}`}>
              <Icon name={t.icon} size={13} />
              {t.label}
              {t.badge && <span className="rounded bg-raise px-1.5 py-px font-mono text-[9px] text-sub">{t.badge}</span>}
            </button>
          ))}
        </div>

        {tab === 'overview' && (
          <div className="a-up flex flex-col gap-4">
            <div className="grid grid-cols-2 gap-x-4 gap-y-3.5 rounded-lg border border-line bg-panel p-4">
              <Field label="Responsável">
                <select className="select w-full" value={sel.assignee} disabled={!canUpdate}
                  onChange={e => props.onMeta(sel.id, { assignee: e.target.value }, `reatribuiu case para ${e.target.value}`)}>
                  {ANALYSTS.map(a => <option key={a} value={a}>{a}</option>)}
                </select>
              </Field>
              <Field label="Prioridade">
                <select className="select w-full" value={sel.priority ?? 'P3'} disabled={!canUpdate}
                  onChange={e => props.onMeta(sel.id, { priority: e.target.value as Priority }, `alterou prioridade para ${e.target.value}`)}>
                  {PRIORITY_ORDER.map(p => <option key={p} value={p}>{p} — {PRIORITY_META[p].desc}</option>)}
                </select>
              </Field>
              <Field label="Severidade"><SevBadge sev={sel.severity} /></Field>
              <Field label="Status">
                <select className="select w-full" value={sel.status ?? 'active'} disabled={!canUpdate}
                  onChange={e => props.onMeta(sel.id, { status: e.target.value as Case['status'] }, `alterou status para ${e.target.value}`)}>
                  <option value="active">Ativo</option>
                  <option value="on_hold">Em espera</option>
                </select>
              </Field>
              <Field label="Aberto em" mono>{new Date(sel.openedAt ?? sel.ts).toLocaleString('pt-BR')}</Field>
              <Field label="Encerrado em" mono>{sel.closedAt ? new Date(sel.closedAt).toLocaleString('pt-BR') : '—'}</Field>
            </div>
            <div className="rounded-lg border border-line bg-panel p-4">
              <div className="lbl mb-2">Metadados do ciclo</div>
              <div className="grid grid-cols-3 gap-3 text-center">
                <div>
                  <div className="font-mono text-[17px] font-bold text-cyan">{fmtDur(Math.round((now - lastStageTs(sel)) / 60_000))}</div>
                  <div className="text-[9.5px] text-faint">tempo na etapa atual</div>
                </div>
                <div>
                  <div className="font-mono text-[17px] font-bold text-high">{fmtDur(Math.round(elapsed / 60_000))}</div>
                  <div className="text-[9.5px] text-faint">tempo total de ciclo</div>
                </div>
                <div>
                  <div className="font-mono text-[17px] font-bold text-teal">{doneTasks}/{(sel.tasks ?? []).length}</div>
                  <div className="text-[9.5px] text-faint">tarefas concluídas</div>
                </div>
              </div>
            </div>
          </div>
        )}

        {tab === 'relations' && (
          <div className="a-up flex flex-col gap-3">
            {REL_META.map(rm => {
              const field = { alert: sel.alertIds, incident: sel.incidentIds, asset: sel.assetNames, ioc: sel.iocs, evidence: sel.evidence }[rm.kind];
              const candidates =
                rm.kind === 'alert' ? s.alerts.filter(a => a.tenant === sel.tenant && !field.includes(a.id)).map(a => ({ v: a.id, l: `${a.id} · ${a.title}` }))
                : rm.kind === 'incident' ? s.incidents.filter(i => i.tenant === sel.tenant && !field.includes(i.id)).map(i => ({ v: i.id, l: `${i.id} · ${i.title}` }))
                : rm.kind === 'asset' ? s.assets.filter(a => a.tenant === sel.tenant && !field.includes(a.name)).map(a => ({ v: a.name, l: `${a.name} · ${a.ip}` }))
                : [];
              return (
                <div key={rm.kind} className="rounded-lg border border-line bg-panel p-3.5">
                  <div className="lbl mb-2 flex items-center gap-1.5" style={{ color: rm.color }}>
                    <Icon name={rm.icon} size={12} /> {rm.label} · {field.length}
                  </div>
                  <div className="flex flex-wrap gap-1.5">
                    {field.length === 0 && <span className="text-[11px] text-faint">nenhum vínculo</span>}
                    {field.map(v => (
                      <span key={v} className="group flex items-center gap-1.5 rounded-md border border-line/70 bg-[#0a1322] px-2 py-1 font-mono text-[10.5px] text-ink/85">
                        <button className="hover:text-teal hover:underline"
                          onClick={() => rm.kind === 'alert' ? props.nav('alerts', { type: 'alert', id: v })
                            : rm.kind === 'incident' ? props.nav('incidents', { type: 'incident', id: v })
                            : rm.kind === 'asset' ? props.nav('assets', { type: 'assetname', id: v }) : undefined}>
                          {v}
                        </button>
                        {canUpdate && (
                          <button className="text-faint hover:text-crit" onClick={() => props.onRelRemove(sel.id, rm.kind, v)} title="Remover vínculo">
                            <Icon name="x" size={11} />
                          </button>
                        )}
                      </span>
                    ))}
                  </div>
                  {canUpdate && (
                    <div className="mt-2.5 flex gap-2">
                      {candidates.length > 0 ? (
                        <>
                          <select className="select flex-1 py-1! text-[11px]" value={relInput[rm.kind] ?? ''}
                            onChange={e => setRelInput(p => ({ ...p, [rm.kind]: e.target.value }))}>
                            <option value="">vincular existente…</option>
                            {candidates.map(c => <option key={c.v} value={c.v}>{c.l}</option>)}
                          </select>
                          <button className="btn btn-xs" disabled={!relInput[rm.kind]}
                            onClick={() => { props.onRelAdd(sel.id, rm.kind, relInput[rm.kind]); setRelInput(p => ({ ...p, [rm.kind]: '' })); }}>
                            <Icon name="plus" size={12} />
                          </button>
                        </>
                      ) : (
                        <input className="input flex-1 py-1! text-[11px]" placeholder={`adicionar ${rm.label.toLowerCase()}…`}
                          value={relInput[rm.kind] ?? ''} onChange={e => setRelInput(p => ({ ...p, [rm.kind]: e.target.value }))}
                          onKeyDown={e => { if (e.key === 'Enter' && relInput[rm.kind]?.trim()) { props.onRelAdd(sel.id, rm.kind, relInput[rm.kind].trim()); setRelInput(p => ({ ...p, [rm.kind]: '' })); } }} />
                      )}
                      {candidates.length === 0 && (
                        <button className="btn btn-xs" disabled={!relInput[rm.kind]?.trim()}
                          onClick={() => { props.onRelAdd(sel.id, rm.kind, relInput[rm.kind].trim()); setRelInput(p => ({ ...p, [rm.kind]: '' })); }}>
                          <Icon name="plus" size={12} />
                        </button>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}

        {tab === 'tasks' && (
          <div className="a-up">
            <div className="mb-3 flex items-center gap-3">
              <div className="h-[6px] flex-1 overflow-hidden rounded-sm bg-[#0a1322]">
                <div className="h-full bg-teal transition-all duration-500" style={{ width: `${(sel.tasks ?? []).length ? (doneTasks / sel.tasks!.length) * 100 : 0}%` }} />
              </div>
              <span className="font-mono text-[11px] text-sub">{doneTasks}/{(sel.tasks ?? []).length}</span>
            </div>
            <div className="flex flex-col gap-1">
              {(sel.tasks ?? []).length === 0 && <EmptyState icon="check" title="Nenhuma tarefa" sub="Adicione tarefas para acompanhar o ciclo." />}
              {(sel.tasks ?? []).map(t => (
                <div key={t.id} className="group flex items-center gap-2.5 rounded-md px-2 py-[7px] hover:bg-raise">
                  <button className={`flex h-4 w-4 shrink-0 items-center justify-center rounded border transition-colors ${t.done ? 'border-teal bg-teal text-[#04160f]' : 'border-line2'}`}
                    disabled={!canUpdate} onClick={() => props.onTaskToggle(sel.id, t.id)}>
                    {t.done && <Icon name="check" size={10} strokeWidth={3} />}
                  </button>
                  <span className={`flex-1 text-[12.5px] ${t.done ? 'text-faint line-through' : 'text-ink/90'}`}>{t.text}</span>
                  {canUpdate && (
                    <button className="text-faint opacity-0 transition-opacity hover:text-crit group-hover:opacity-100" onClick={() => props.onTaskRemove(sel.id, t.id)}>
                      <Icon name="trash" size={12} />
                    </button>
                  )}
                </div>
              ))}
            </div>
            {canUpdate && (
              <div className="mt-3 flex gap-2 border-t border-line pt-3">
                <input className="input flex-1" placeholder="Nova tarefa…" value={newTask}
                  onChange={e => setNewTask(e.target.value)}
                  onKeyDown={e => { if (e.key === 'Enter' && newTask.trim()) { props.onTaskAdd(sel.id, newTask.trim()); setNewTask(''); } }} />
                <button className="btn btn-xs" disabled={!newTask.trim()}
                  onClick={() => { props.onTaskAdd(sel.id, newTask.trim()); setNewTask(''); }}>
                  <Icon name="plus" size={12} /> Adicionar
                </button>
              </div>
            )}
          </div>
        )}

        {tab === 'timeline' && (
          <div className="a-up relative ml-2 flex flex-col gap-3.5 border-l border-line2 pl-5">
            {timeline.length === 0 && <span className="text-[11.5px] text-faint">Sem eventos registrados.</span>}
            {timeline.map((t, i) => (
              <div key={i} className="relative">
                <span className={`absolute -left-[27px] top-0.5 flex h-4 w-4 items-center justify-center rounded-full border ${
                  t.kind === 'stage' ? 'border-cyan/60 bg-cyan/15 text-cyan'
                    : t.kind === 'relation' ? 'border-high/60 bg-high/15 text-high'
                    : t.kind === 'system' ? 'border-line2 bg-panel2 text-faint'
                    : 'border-teal/60 bg-teal/15 text-teal'}`}>
                  <Icon name={t.kind === 'stage' ? 'chevronRight' : t.kind === 'relation' ? 'target' : t.kind === 'system' ? 'cpu' : 'user'} size={9} />
                </span>
                <div className="text-[12.5px] leading-snug text-ink/90">{t.text}</div>
                <div className="mt-0.5 font-mono text-[10px] text-faint">{t.author ? `${t.author} · ` : ''}{timeAgo(t.ts)}</div>
              </div>
            ))}
          </div>
        )}

        {tab === 'comments' && (
          <div className="a-up flex flex-col gap-2.5">
            {sel.comments.length === 0 && <EmptyState icon="user" title="Nenhum comentário" sub="Registre o contexto da investigação." />}
            {sel.comments.map((c, i) => (
              <div key={i} className="rounded-lg border border-line bg-panel p-3">
                <div className="flex items-center gap-2">
                  <Avatar name={c.author} size={20} />
                  <span className="text-[11.5px] font-medium text-ink/90">{c.author}</span>
                  <span className="ml-auto font-mono text-[10px] text-faint">{timeAgo(c.ts)}</span>
                </div>
                <p className="mt-1.5 text-[12px] leading-relaxed text-sub">{c.text}</p>
              </div>
            ))}
            <div className="mt-1 flex gap-2">
              <input className="input flex-1" placeholder="Adicionar comentário…" value={comment}
                onChange={e => setComment(e.target.value)}
                onKeyDown={e => { if (e.key === 'Enter' && comment.trim()) { props.onComment(sel.id, comment.trim()); setComment(''); } }} />
              <button className="btn btn-xs" disabled={!comment.trim()}
                onClick={() => { props.onComment(sel.id, comment.trim()); setComment(''); }}>
                <Icon name="send" size={12} /> Enviar
              </button>
            </div>
          </div>
        )}
      </div>
    </Drawer>
  );
}

// ════════════════════════════════════════════════════════════
// Modal de novo case (com templates)
// ════════════════════════════════════════════════════════════
function NewCaseModal({ open, onClose, onCreate }: {
  open: boolean; onClose: () => void;
  onCreate: (d: { title: string; severity: Severity; priority?: Priority; templateId?: string }) => void;
}) {
  const [title, setTitle] = useState('');
  const [sev, setSev] = useState<Severity>('medium');
  const [prio, setPrio] = useState<Priority>('P3');
  const [tpl, setTpl] = useState<string | null>(null);

  useEffect(() => {
    if (open) { setTitle(''); setSev('medium'); setPrio('P3'); setTpl(null); }
  }, [open]);

  useEffect(() => { setPrio(sevToPriority(sev)); }, [sev]);

  const template = CASE_TEMPLATES_DEMO.find(t => t.id === tpl) ?? null;

  return (
    <Modal open={open} onClose={onClose} title="Novo case" width={560}
      footer={<>
        <button className="btn btn-xs" onClick={onClose}>Cancelar</button>
        <button className="btn btn-primary btn-xs" disabled={!title.trim()}
          onClick={() => { onCreate({ title: title.trim(), severity: sev, priority: prio, templateId: tpl ?? undefined }); onClose(); }}>
          <Icon name="folder" size={12} /> Criar case
        </button>
      </>}>
      <div className="flex flex-col gap-3.5">
        <Field label="Título do case">
          <input className="input w-full" placeholder="Ex.: Campanha de phishing — contenção e erradicação" value={title} onChange={e => setTitle(e.target.value)} autoFocus />
        </Field>
        <div className="grid grid-cols-2 gap-3">
          <Field label="Severidade">
            <select className="select w-full" value={sev} onChange={e => setSev(e.target.value as Severity)}>
              {SEV_ORDER.filter(sv => sv !== 'info').map(sv => (
                <option key={sv} value={sv}>{SEV_META[sv].label} · SLA {fmtDur(CASE_SLA_MIN_DEMO[sv])}</option>
              ))}
            </select>
          </Field>
          <Field label="Prioridade">
            <select className="select w-full" value={prio} onChange={e => setPrio(e.target.value as Priority)}>
              {PRIORITY_ORDER.map(p => <option key={p} value={p}>{p} — {PRIORITY_META[p].desc}</option>)}
            </select>
          </Field>
        </div>
        <Field label="Template operacional (opcional)">
          <div className="flex flex-wrap gap-1.5">
            <button className={`chip ${tpl === null ? 'on' : ''}`} onClick={() => setTpl(null)}>sem template</button>
            {CASE_TEMPLATES_DEMO.map(t => (
              <button key={t.id} className={`chip ${tpl === t.id ? 'on' : ''}`} onClick={() => setTpl(t.id === tpl ? null : t.id)}>{t.name}</button>
            ))}
          </div>
        </Field>
        {template && (
          <div className="a-pop rounded-lg border border-teal/30 bg-teal/[.05] p-3">
            <div className="lbl mb-2 text-teal">Tarefas sugeridas ({template.tasks.length})</div>
            <div className="flex flex-col gap-1">
              {template.tasks.map((t, i) => (
                <div key={i} className="flex items-center gap-2 text-[11.5px] text-sub">
                  <span className="flex h-3.5 w-3.5 items-center justify-center rounded-sm border border-line2"><Icon name="check" size={8} className="text-faint" /></span>
                  {t}
                </div>
              ))}
            </div>
          </div>
        )}
        <div className="rounded-md border border-line bg-panel px-3 py-2 text-[10.5px] font-mono text-faint">
          O case nasce na etapa Triagem com SLA de {fmtDur(CASE_SLA_MIN_DEMO[sev])} · prioridade {prio} · trilha de auditoria ativada
        </div>
      </div>
    </Modal>
  );
}
