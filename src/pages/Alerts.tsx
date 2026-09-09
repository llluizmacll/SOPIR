import { useEffect, useMemo, useState } from 'react';
import type { Alert, AlertStatus, Severity } from '../data/mock';
import { ALERT_STATUS_META, ANALYSTS, SEV_META, SEV_ORDER } from '../data/mock';
import { can, timeAgo, useStore } from '../lib/store';
import { api as srv } from '../lib/api';
import type { SuppressionRule } from '../lib/api';
import { Avatar, Drawer, EmptyState, Field, Icon, Pill, SevBadge } from '../components/ui';

const OPEN: AlertStatus[] = ['novo', 'reconhecido', 'investigando', 'escalado', 'falso_positivo', 'fechado'];

export default function Alerts() {
  const { s, scope, ack, assignAlert, patchAlert, escalate, nav } = useStore();
  const [q, setQ] = useState('');
  const [sevs, setSevs] = useState<Severity[]>([]);
  const [status, setStatus] = useState('all');
  const [source, setSource] = useState('all');
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [bulk, setBulk] = useState<Set<string>>(new Set());
  const [classify, setClassify] = useState('Falso positivo');
  const [showSuppression, setShowSuppression] = useState(false);

  useEffect(() => {
    if (s.focus?.type === 'alert') { setSelectedId(s.focus.id); nav('alerts', null); }
  }, [s.focus, nav]);

  const alerts = useMemo(() => scope(s.alerts), [s.alerts, s.tenant]); // eslint-disable-line react-hooks/exhaustive-deps

  const filtered = useMemo(() => {
    const query = q.trim().toLowerCase();
    return alerts.filter(a => {
      if (sevs.length && !sevs.includes(a.severity)) return false;
      if (status !== 'all' && a.status !== status) return false;
      if (source !== 'all' && a.source !== source) return false;
      if (query && ![a.id, a.title, a.host, a.srcIp, a.user, a.rule, a.ruleId].some(f => f.toLowerCase().includes(query))) return false;
      return true;
    });
  }, [alerts, q, sevs, status, source]);

  const sel = filtered.find(a => a.id === selectedId) ?? null;
  const relatedEvents = sel ? scope(s.events).filter(e => e.host === sel.host || e.srcIp === sel.srcIp).slice(0, 6) : [];

  const toggleSev = (sv: Severity) => setSevs(p => (p.includes(sv) ? p.filter(x => x !== sv) : [...p, sv]));
  const toggleBulk = (id: string) => setBulk(p => { const n = new Set(p); if (n.has(id)) n.delete(id); else n.add(id); return n; });
  const canUpdate = can(s.role, 'alerts.update');

  return (
    <div className="flex h-full flex-col">
      {/* toolbar */}
      <div className="a-up shrink-0 border-b border-line bg-panel/40 px-5 py-3.5">
        <div className="flex flex-wrap items-center gap-2.5">
          <div className="relative min-w-[220px] flex-1 max-w-[420px]">
            <span className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-faint"><Icon name="search" size={14} /></span>
            <input className="input w-full pl-9" placeholder="Buscar por ID, título, host, IP, regra…" value={q} onChange={e => setQ(e.target.value)} />
          </div>
          {SEV_ORDER.map(sv => (
            <button key={sv} className={`chip ${sevs.includes(sv) ? 'on' : ''}`}
              style={sevs.includes(sv) ? { borderColor: SEV_META[sv].color + '66', color: SEV_META[sv].color } : undefined}
              onClick={() => toggleSev(sv)}>
              {SEV_META[sv].label}
              <span className="font-mono">{alerts.filter(a => a.severity === sv && !['fechado', 'falso_positivo'].includes(a.status)).length}</span>
            </button>
          ))}
          <select className="select" value={status} onChange={e => setStatus(e.target.value)}>
            <option value="all">Todos os status</option>
            {OPEN.map(st => <option key={st} value={st}>{ALERT_STATUS_META[st].label}</option>)}
          </select>
          <select className="select" value={source} onChange={e => setSource(e.target.value)}>
            <option value="all">Todas as origens</option>
            <option value="Wazuh">Wazuh</option>
            <option value="FortiSIEM">FortiSIEM</option>
          </select>
          {bulk.size > 0 && (
            <button className="btn btn-xs btn-primary a-pop" onClick={() => { bulk.forEach(id => ack(id)); setBulk(new Set()); }} disabled={!canUpdate}>
              <Icon name="check" size={12} /> Reconhecer {bulk.size}
            </button>
          )}
          <button className="btn btn-xs" onClick={() => setShowSuppression(true)} title="Regras de supressão de alertas">
            <Icon name="bell" size={12} /> Supressão
          </button>
          <span className="ml-auto font-mono text-[11px] text-faint">{filtered.length} de {alerts.length}</span>
        </div>
      </div>

      {/* tabela */}
      <div className="min-h-0 flex-1 overflow-auto px-5 py-4">
        {filtered.length === 0 ? (
          <EmptyState icon="bell" title="Nenhum alerta no filtro" sub="Ajuste severidade, status ou o termo de busca." />
        ) : (
          <table className="tbl">
            <thead>
              <tr>
                <th className="w-[36px]">
                  <input type="checkbox" className="accent-[#2fd6a5]"
                    checked={bulk.size > 0 && filtered.every(a => bulk.has(a.id))}
                    onChange={e => setBulk(e.target.checked ? new Set(filtered.map(a => a.id)) : new Set())} />
                </th>
                <th className="w-[88px]">ID</th>
                <th>Alerta</th>
                <th className="w-[92px]">Severidade</th>
                <th className="w-[130px]">Status</th>
                <th className="hidden md:table-cell w-[120px]">Host</th>
                <th className="hidden lg:table-cell w-[120px]">Origem</th>
                <th className="w-[130px]">Atribuído</th>
                <th className="w-[80px]">Quando</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map(a => (
                <tr key={a.id} className={`cursor-pointer ${selectedId === a.id ? 'bg-raise/60' : ''}`}
                  onClick={() => setSelectedId(a.id)}>
                  <td onClick={e => e.stopPropagation()}>
                    <input type="checkbox" className="accent-[#2fd6a5]" checked={bulk.has(a.id)} onChange={() => toggleBulk(a.id)} />
                  </td>
                  <td className="font-mono text-[11px] text-teal">{a.id}</td>
                  <td>
                    <div className="flex items-center gap-2">
                      {a.status === 'novo' && <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-crit dot-crit" />}
                      <span className="truncate text-[12.5px] text-ink/90">{a.title}</span>
                    </div>
                    <div className="mt-0.5 font-mono text-[10px] text-faint">
                      {a.source} · regra #{a.ruleId}{a.srcIp !== '—' ? ` · ${a.srcIp}` : ''}
                    </div>
                  </td>
                  <td><SevBadge sev={a.severity} sm /></td>
                  <td><Pill label={ALERT_STATUS_META[a.status].label} color={ALERT_STATUS_META[a.status].color} sm /></td>
                  <td className="hidden md:table-cell font-mono text-[11px] text-sub">{a.host}</td>
                  <td className="hidden lg:table-cell font-mono text-[11px] text-sub">{a.srcIp}</td>
                  <td>{a.assignee ? (
                    <span className="flex items-center gap-1.5"><Avatar name={a.assignee} size={20} /><span className="text-[11.5px] text-sub">{a.assignee.split(' ')[0]}</span></span>
                  ) : <span className="text-[11px] text-faint">—</span>}</td>
                  <td className="font-mono text-[10.5px] text-faint">{timeAgo(a.ts)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* drawer de triagem */}
      <Drawer open={!!sel} onClose={() => setSelectedId(null)}
        title={sel ? <span className="flex items-center gap-2.5"><span className="font-mono text-teal">{sel.id}</span>{sel.title}</span> : ''}
        sub={sel ? (<><SevBadge sev={sel.severity} sm /><Pill label={ALERT_STATUS_META[sel.status].label} color={ALERT_STATUS_META[sel.status].color} sm />
          <span className="font-mono text-faint">{timeAgo(sel.ts)}</span></>) : undefined}
        footer={sel ? (
          <div className="flex flex-wrap items-center gap-2">
            {sel.status === 'novo' && (
              <button className="btn btn-primary btn-xs" onClick={() => ack(sel.id)} disabled={!canUpdate}>
                <Icon name="check" size={12} /> Reconhecer
              </button>
            )}
            <button className="btn btn-xs btn-primary" onClick={() => { escalate(sel.id); setSelectedId(null); }}
              disabled={!can(s.role, 'incidents.update') || sel.status === 'escalado'}
              title={sel.status === 'escalado' ? 'Já escalonado' : undefined}>
              <Icon name="flame" size={12} /> Escalar para incidente
            </button>
            <div className="ml-auto flex items-center gap-2">
              <select className="select py-1! text-[11px]" value={classify} onChange={e => setClassify(e.target.value)}>
                <option>Falso positivo</option><option>Benigno</option><option>Duplicado</option>
              </select>
              <button className="btn btn-xs" disabled={!canUpdate}
                onClick={() => patchAlert(sel.id, { status: classify === 'Falso positivo' ? 'falso_positivo' : 'fechado', classification: classify }, `fechou alerta como ${classify}`)}>
                <Icon name="x" size={12} /> Fechar
              </button>
            </div>
          </div>
        ) : undefined}>
        {sel && (
          <div className="flex flex-col gap-5">
            <div className="grid grid-cols-2 gap-x-4 gap-y-3.5 rounded-lg border border-line bg-panel p-4">
              <Field label="Origem (SIEM)">{sel.source}</Field>
              <Field label="Regra" mono>{sel.rule} · #{sel.ruleId}</Field>
              <Field label="IP de origem" mono>{sel.srcIp}</Field>
              <Field label="IP de destino" mono>{sel.dstIp}</Field>
              <Field label="Usuário" mono>{sel.user}</Field>
              <Field label="Host / Agente" mono>{sel.host}</Field>
              <Field label="Detecção" mono>{new Date(sel.ts).toLocaleString('pt-BR')}</Field>
              <Field label="Atribuído a">
                <select className="select w-full py-1! text-[11.5px]" value={sel.assignee ?? ''} disabled={!canUpdate}
                  onChange={e => e.target.value && assignAlert(sel.id, e.target.value)}>
                  <option value="" disabled>Atribuir analista…</option>
                  {ANALYSTS.map(a => <option key={a} value={a}>{a}</option>)}
                </select>
              </Field>
            </div>

            <div>
              <div className="lbl mb-1.5">Descrição</div>
              <p className="text-[12.5px] leading-relaxed text-sub">{sel.desc}</p>
            </div>

            {sel.incidentId && (
              <button className="flex items-center gap-2.5 rounded-lg border border-high/40 bg-high/10 px-3.5 py-2.5 text-left hover:bg-high/15 transition-colors"
                onClick={() => nav('incidents', { type: 'incident', id: sel.incidentId! })}>
                <Icon name="flame" size={14} className="text-high" />
                <span className="text-[12px] text-ink/90">Vinculado ao incidente <span className="font-mono text-high">{sel.incidentId}</span> — abrir</span>
                <Icon name="arrowUpRight" size={12} className="ml-auto text-high" />
              </button>
            )}

            <div>
              <div className="lbl mb-2">Eventos relacionados ({relatedEvents.length})</div>
              {relatedEvents.length === 0 && <span className="text-[11.5px] text-faint">Sem eventos correlacionados no buffer.</span>}
              <div className="flex flex-col gap-1.5">
                {relatedEvents.map(ev => (
                  <button key={ev.id} className="flex items-center gap-2.5 rounded-md border border-line/70 bg-panel px-3 py-2 text-left hover:border-line2 transition-colors"
                    onClick={() => nav('explorer', { type: 'event', id: ev.ruleId })}>
                    <span className="h-1.5 w-1.5 shrink-0 rounded-full" style={{ background: SEV_META[ev.severity].color }} />
                    <span className="truncate text-[11.5px] text-ink/80">{ev.rule}</span>
                    <span className="ml-auto shrink-0 font-mono text-[10px] text-faint">{ev.host} · {timeAgo(ev.ts)}</span>
                  </button>
                ))}
              </div>
            </div>

            <div>
              <div className="lbl mb-2">Fluxo de triagem</div>
              <div className="flex items-center gap-1.5 font-mono text-[10.5px] text-faint flex-wrap">
                {['Alert', 'Analista', 'Triagem', 'Incidente?', 'Case'].map((st, i) => (
                  <span key={st} className="flex items-center gap-1.5">
                    <span className={`rounded border px-2 py-1 ${i === 0 ? 'border-teal/50 text-teal' : i === 1 || i === 2 ? 'border-cyan/40 text-cyan' : 'border-line text-faint'}`}>{st}</span>
                    {i < 4 && <Icon name="chevronRight" size={11} />}
                  </span>
                ))}
              </div>
            </div>
          </div>
        )}
      </Drawer>

      <SuppressionDrawer open={showSuppression} onClose={() => setShowSuppression(false)} />
    </div>
  );
}

// ── Supressão de alertas ─────────────────────────────────────
function SuppressionDrawer({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { backend } = useStore();
  const online = backend === 'online';
  const [rules, setRules] = useState<SuppressionRule[]>([]);
  const [ruleId, setRuleId] = useState('');
  const [host, setHost] = useState('');
  const [srcIp, setSrcIp] = useState('');
  const [reason, setReason] = useState('');
  const [duration, setDuration] = useState(60);
  const [err, setErr] = useState('');

  const load = async () => {
    if (!online) return;
    const res = await srv.suppressionRules();
    if (res) setRules(res);
  };
  useEffect(() => { if (open) void load(); }, [open]); // eslint-disable-line react-hooks/exhaustive-deps

  const create = async () => {
    setErr('');
    if (!ruleId.trim() && !host.trim() && !srcIp.trim()) { setErr('Informe ao menos um critério.'); return; }
    if (!online) { setErr('Requer a sopir-api conectada.'); return; }
    const res = await srv.createSuppression({ ruleId: ruleId.trim() || undefined, host: host.trim() || undefined, srcIp: srcIp.trim() || undefined, reason: reason.trim(), durationMin: duration });
    if (res?.error) { setErr(res.error); return; }
    setRuleId(''); setHost(''); setSrcIp(''); setReason('');
    void load();
  };
  const remove = async (id: number) => { await srv.deleteSuppression(id); void load(); };
  const toggle = async (id: number, enabled: boolean) => { await srv.toggleSuppression(id, enabled); void load(); };

  return (
    <Drawer open={open} onClose={onClose} width={520} title="Supressão de alertas"
      sub={<span className="text-faint">Eventos que casarem com uma regra ativa não geram alerta automático.</span>}>
      <div className="flex flex-col gap-5">
        <div>
          <div className="lbl mb-2">Nova regra</div>
          <div className="grid grid-cols-2 gap-2.5">
            <Field label="Regra (id ou nome)"><input className="input w-full" placeholder="5551" value={ruleId} onChange={e => setRuleId(e.target.value)} /></Field>
            <Field label="Host"><input className="input w-full" placeholder="WS-FIN-014" value={host} onChange={e => setHost(e.target.value)} /></Field>
            <Field label="IP de origem"><input className="input w-full" placeholder="185.220.101.34" value={srcIp} onChange={e => setSrcIp(e.target.value)} /></Field>
            <Field label="Duração (min)"><input type="number" className="input w-full" value={duration} min={5} onChange={e => setDuration(Number(e.target.value) || 60)} /></Field>
          </div>
          <Field label="Motivo (opcional)"><input className="input w-full mt-2.5" placeholder="ex.: manutenção programada" value={reason} onChange={e => setReason(e.target.value)} /></Field>
          {err && <div className="mt-2 text-[11px] text-crit">{err}</div>}
          <button className="btn btn-primary btn-xs mt-3" onClick={create}>
            <Icon name="plus" size={12} /> Criar regra
          </button>
          {!online && <div className="mt-2 text-[10.5px] text-faint">Conecte a sopir-api para gerenciar supressão.</div>}
        </div>

        <div>
          <div className="lbl mb-2">Regras ativas ({rules.length})</div>
          {rules.length === 0 && <div className="text-[11.5px] text-faint">Nenhuma regra de supressão.</div>}
          <div className="flex flex-col gap-2">
            {rules.map(r => {
              const active = r.enabled && r.expiresAt > Date.now();
              return (
                <div key={r.id} className={`rounded-lg border px-3.5 py-2.5 transition-colors ${active ? 'border-med/40 bg-med/[.05]' : 'border-line bg-panel opacity-60'}`}>
                  <div className="flex items-center gap-2 flex-wrap">
                    {r.ruleId && <Pill label={`regra ${r.ruleId}`} color="#56c4ff" sm />}
                    {r.host && <Pill label={r.host} color="#2fd6a5" sm />}
                    {r.srcIp && <Pill label={r.srcIp} color="#ff9142" sm />}
                    <span className="ml-auto font-mono text-[9.5px] text-faint">expira {timeAgo(r.expiresAt).replace('há', 'em')}</span>
                  </div>
                  {r.reason && <div className="mt-1 text-[11px] text-sub">{r.reason}</div>}
                  <div className="mt-2 flex items-center gap-2">
                    <button className="btn btn-ghost btn-xs" onClick={() => toggle(r.id, !r.enabled)}>
                      <Icon name={r.enabled ? 'pause' : 'play'} size={11} /> {r.enabled ? 'pausar' : 'ativar'}
                    </button>
                    <button className="btn btn-ghost btn-xs hover:text-crit" onClick={() => remove(r.id)}>
                      <Icon name="trash" size={11} /> remover
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </Drawer>
  );
}
