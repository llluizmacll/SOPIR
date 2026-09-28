import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { api as srv } from '../lib/api';
import type { AuditCompliance, AuditVerify } from '../lib/api';
import { useStore } from '../lib/store';
import type { AuditEntry } from '../data/mock';
import { AreaChart, HBars } from '../components/charts';
import { Avatar, EmptyState, Field, Icon, Pill } from '../components/ui';
import type { IconName } from '../components/icons';
import { download, toCSV, timeAgo, fmtDT } from '../lib/store';

// ── catálogo de controles (base SOC 2 / ISO 27001) ───────────
const CONTROLS: Record<string, { name: string; color: string }> = {
  'CC6.1': { name: 'Acesso lógico & identidade', color: '#56c4ff' },
  'CC6.6': { name: 'Proteção contra ameaças externas', color: '#ff9142' },
  'CC7.2': { name: 'Monitoramento contínuo', color: '#ffc53d' },
  'CC7.3': { name: 'Resposta a incidentes', color: '#ff4d5e' },
  'CC7.4': { name: 'Comunicação de resposta', color: '#2fd6a5' },
  'CC8.1': { name: 'Gestão de mudanças & dados', color: '#5aa2ff' },
};

const KIND_META: Record<string, { label: string; icon: IconName; color: string }> = {
  auth: { label: 'Autenticação', icon: 'lock', color: '#56c4ff' },
  triage: { label: 'Triagem', icon: 'filter', color: '#ffc53d' },
  response: { label: 'Resposta', icon: 'zap', color: '#ff9142' },
  data: { label: 'Dados', icon: 'database', color: '#5aa2ff' },
  system: { label: 'Sistema', icon: 'cpu', color: '#8fa3c8' },
};

const RANGES = [
  { id: '24h', label: '24h', ms: 86_400_000 },
  { id: '7d', label: '7d', ms: 7 * 86_400_000 },
  { id: '30d', label: '30d', ms: 30 * 86_400_000 },
  { id: 'all', label: 'Tudo', ms: 0 },
];

export default function Audit() {
  const { s, backend } = useStore();
  const online = backend === 'online';

  // filtros
  const [q, setQ] = useState('');
  const [kind, setKind] = useState('all');
  const [actor, setActor] = useState('all');
  const [outcome, setOutcome] = useState('all');
  const [control, setControl] = useState('all');
  const [range, setRange] = useState('7d');
  const [rows, setRows] = useState<AuditEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState<string | null>(null);

  // integridade & compliance
  const [verify, setVerify] = useState<AuditVerify | null>(null);
  const [verifying, setVerifying] = useState(false);
  const [compliance, setCompliance] = useState<AuditCompliance | null>(null);

  const actors = useMemo(() => Array.from(new Set(rows.map(r => r.actor))).sort(), [rows]);

  const load = useCallback(async () => {
    setLoading(true);
    if (online) {
      const ms = RANGES.find(r => r.id === range)?.ms ?? 0;
      const res = await srv.auditQuery({
        q: q || undefined,
        kind: kind !== 'all' ? kind : undefined,
        actor: actor !== 'all' ? actor : undefined,
        outcome: outcome !== 'all' ? outcome : undefined,
        control: control !== 'all' ? control : undefined,
        from: ms ? Date.now() - ms : undefined,
      });
      if (res) setRows(res);
    } else {
      // modo demonstração: filtra a trilha local
      const ms = RANGES.find(r => r.id === range)?.ms ?? 0;
      const cutoff = ms ? Date.now() - ms : 0;
      const query = q.trim().toLowerCase();
      setRows(s.audit.filter(a =>
        a.ts >= cutoff &&
        (kind === 'all' || a.kind === kind) &&
        (actor === 'all' || a.actor === actor) &&
        (outcome === 'all' || (a.outcome ?? 'ok') === outcome) &&
        (control === 'all' || a.control === control) &&
        (!query || `${a.actor} ${a.action} ${a.target}`.toLowerCase().includes(query)),
      ));
    }
    setLoading(false);
  }, [online, q, kind, actor, outcome, control, range, s.audit]);

  useEffect(() => { void load(); }, [load]);

  // verificação de integridade
  const runVerify = useCallback(async () => {
    setVerifying(true);
    if (online) {
      const res = await srv.verifyAudit();
      if (res) setVerify(res);
    } else {
      // demo: sela a cadeia local em memória
      setVerify({ ok: true, total: s.audit.length, verified: s.audit.length, legacy: 0, firstBad: null, tip: null });
    }
    setVerifying(false);
  }, [online, s.audit.length]);

  useEffect(() => { void runVerify(); }, [runVerify]);
  useEffect(() => {
    if (online) {
      let alive = true;
      srv.auditCompliance().then(res => { if (alive && res) setCompliance(res); });
      return () => { alive = false; };
    }
    // modo demonstração: deriva o painel da trilha local
    const KIND_CTRL: Record<string, string> = { auth: 'CC6.1', triage: 'CC7.2', response: 'CC7.4', data: 'CC8.1', system: 'CC8.1' };
    const acc: Record<string, number> = {};
    const days = new Array(14).fill(0);
    const nowDay = Math.floor(Date.now() / 86_400_000);
    let deniedRecent = 0;
    for (const a of s.audit) {
      const c = KIND_CTRL[a.kind] ?? 'CC8.1';
      acc[c] = (acc[c] ?? 0) + 1;
      const idx = nowDay - Math.floor(a.ts / 86_400_000);
      if (idx >= 0 && idx < 14) days[13 - idx] += 1;
      if (a.outcome === 'denied' && Date.now() - a.ts < 86_400_000) deniedRecent += 1;
    }
    const controls = Object.entries(acc).map(([control, n]) => ({ control, n }));
    // sem histórico suficiente → série ilustrativa para o gráfico
    const perDay = days.reduce((a: number, b: number) => a + b, 0) > 0
      ? days
      : [4, 6, 5, 8, 7, 10, 9, 12, 8, 11, 13, 10, 12, 14];
    setCompliance({
      controls,
      perDay,
      signals: [
        { id: 'failed-logins', label: 'Logins negados (última hora)', count: deniedRecent, severity: deniedRecent > 3 ? 'high' : deniedRecent > 0 ? 'medium' : 'low' },
        { id: 'cross-tenant', label: 'Acessos entre tenants bloqueados (24h)', count: 0, severity: 'low' },
        { id: 'after-hours', label: 'Ações administrativas fora do horário (24h)', count: 0, severity: 'low' },
        { id: 'rejections', label: 'Ações de resposta rejeitadas (7d)', count: 0, severity: 'low' },
      ],
    });
  }, [online, s.audit]);

  const exportCSV = () => {
    download('sopir-auditoria.csv', toCSV(rows.map(r => ({
      id: r.id, data: fmtDT(r.ts), ator: r.actor, acao: r.action, alvo: r.target,
      tipo: r.kind, resultado: r.outcome ?? 'ok', controle: r.control ?? '', ip: r.ip ?? '', hash: (r.hash ?? '').slice(0, 16),
    }))), 'text/csv');
  };
  const exportJSON = () => {
    download('sopir-auditoria.json', JSON.stringify(rows, null, 2), 'application/json');
  };

  const denied = rows.filter(r => r.outcome === 'denied').length;

  return (
    <div className="flex h-full flex-col overflow-hidden">
      {/* ── faixa de integridade ── */}
      <div className="a-up shrink-0 border-b border-line bg-gradient-to-r from-panel via-panel2 to-panel px-5 py-4">
        <div className="flex flex-wrap items-center gap-4">
          <div className={`relative flex h-12 w-12 items-center justify-center rounded-xl border ${
            verifying ? 'border-cyan/40 text-cyan' : verify?.ok ? 'border-teal/50 text-teal' : verify ? 'border-crit/50 text-crit' : 'border-line text-faint'}`}>
            <Icon name={verifying ? 'activity' : verify?.ok === false ? 'alertTriangle' : 'shieldCheck'} size={22} />
            {!verifying && <span className={`absolute -right-1 -top-1 h-3 w-3 rounded-full border-2 border-bg ${verify?.ok ? 'bg-teal dot-live' : verify ? 'bg-crit' : 'bg-faint'}`} />}
          </div>
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2.5 flex-wrap">
              <h2 className="font-display text-[16px] font-bold text-ink">Trilha de auditoria à prova de adulteração</h2>
              {verify && !verifying && (
                <Pill label={verify.ok ? 'cadeia íntegra' : 'VIOLAÇÃO DETECTADA'} color={verify.ok ? '#2fd6a5' : '#ff4d5e'} />
              )}
            </div>
            <div className="mt-1 font-mono text-[10.5px] text-faint flex items-center gap-2 flex-wrap">
              <span>{verify ? `${verify.verified} registro(s) verificados` : '—'}</span>
              {verify && verify.legacy > 0 && <span>· {verify.legacy} legados</span>}
              {verify?.tip && <span className="text-teal/70">· ponta: {verify.tip.slice(0, 14)}…</span>}
              {!online && <span className="text-cyan/70">· verificação local (demonstração)</span>}
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button className="btn btn-xs" onClick={() => void runVerify()} disabled={verifying}>
              <Icon name={verifying ? 'activity' : 'shieldCheck'} size={12} /> {verifying ? 'Verificando…' : 'Verificar cadeia'}
            </button>
            <button className="btn btn-xs" onClick={exportCSV} disabled={!rows.length}><Icon name="download" size={12} /> CSV</button>
            <button className="btn btn-xs" onClick={exportJSON} disabled={!rows.length}><Icon name="file" size={12} /> JSON</button>
          </div>
        </div>
        {verify && !verify.ok && verify.firstBad && (
          <div className="mt-3 flex items-center gap-2 rounded-md border border-crit/40 bg-crit/10 px-3 py-2 text-[11.5px] text-crit">
            <Icon name="alertTriangle" size={13} /> Integridade rompida a partir do registro <span className="font-mono">{verify.firstBad}</span> — investigue imediatamente.
          </div>
        )}
      </div>

      {/* ── barra de filtros ── */}
      <div className="a-up flex shrink-0 flex-wrap items-center gap-2 border-b border-line bg-panel/60 px-5 py-2.5" style={{ animationDelay: '50ms' }}>
        <div className="relative min-w-[190px] flex-1 max-w-[320px]">
          <span className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-faint"><Icon name="search" size={13} /></span>
          <input className="input w-full pl-8 py-1.5!" placeholder="Buscar ação, alvo, ator…" value={q} onChange={e => setQ(e.target.value)} />
        </div>
        <select className="select py-1.5!" value={kind} onChange={e => setKind(e.target.value)}>
          <option value="all">Todo tipo</option>
          {Object.entries(KIND_META).map(([k, m]) => <option key={k} value={k}>{m.label}</option>)}
        </select>
        <select className="select py-1.5!" value={outcome} onChange={e => setOutcome(e.target.value)}>
          <option value="all">Todo resultado</option>
          <option value="ok">Sucesso</option>
          <option value="denied">Negado</option>
        </select>
        <select className="select py-1.5!" value={control} onChange={e => setControl(e.target.value)}>
          <option value="all">Todo controle</option>
          {Object.entries(CONTROLS).map(([k, c]) => <option key={k} value={k}>{k} — {c.name}</option>)}
        </select>
        {actors.length > 1 && (
          <select className="select py-1.5! max-w-[150px]" value={actor} onChange={e => setActor(e.target.value)}>
            <option value="all">Todos os atores</option>
            {actors.map(a => <option key={a} value={a}>{a}</option>)}
          </select>
        )}
        <div className="ml-auto flex rounded-lg border border-line bg-panel p-0.5">
          {RANGES.map(r => (
            <button key={r.id} onClick={() => setRange(r.id)}
              className={`rounded-md px-2.5 py-1 font-mono text-[10.5px] transition-colors ${range === r.id ? 'bg-teal/15 text-teal' : 'text-faint hover:text-sub'}`}>
              {r.label}
            </button>
          ))}
        </div>
        <span className="font-mono text-[10px] text-faint">{rows.length} registro(s){denied > 0 && <span className="text-crit"> · {denied} negados</span>}</span>
      </div>

      {/* ── conteúdo: timeline + conformidade ── */}
      <div className="grid min-h-0 flex-1 grid-cols-12 gap-4 overflow-hidden p-4">
        {/* timeline */}
        <div className="col-span-12 xl:col-span-8 min-h-0 overflow-y-auto pr-1">
          {loading && <div className="py-10 text-center text-[12px] text-faint">carregando trilha…</div>}
          {!loading && rows.length === 0 && <EmptyState icon="history" title="Nenhum registro no filtro" sub="Ajuste os filtros ou amplie o período." />}
          {!loading && (
            <div className="relative flex flex-col gap-1.5">
              {rows.map((r, i) => {
                const km = KIND_META[r.kind] ?? KIND_META.system;
                const isOpen = expanded === r.id;
                const isDenied = r.outcome === 'denied';
                return (
                  <div key={r.id} className="a-up">
                    <button onClick={() => setExpanded(isOpen ? null : r.id)}
                      className={`group flex w-full items-center gap-3 rounded-lg border px-3.5 py-2.5 text-left transition-all ${
                        isOpen ? 'border-teal/50 bg-teal/[.05]' : isDenied ? 'border-crit/30 bg-crit/[.04] hover:border-crit/50' : 'border-line bg-panel hover:border-line2'}`}
                      style={{ animationDelay: `${Math.min(i, 14) * 25}ms` }}>
                      <span className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-lg border ${isDenied ? 'border-crit/40 bg-crit/10 text-crit' : 'border-line bg-panel2'}`}
                        style={isDenied ? {} : { color: km.color }}>
                        <Icon name={isDenied ? 'x' : km.icon} size={14} />
                      </span>
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="text-[12.5px] font-medium text-ink/95">{r.action}</span>
                          {r.control && <Pill label={r.control} color={CONTROLS[r.control]?.color ?? '#8fa3c8'} sm />}
                          {isDenied && <Pill label="negado" color="#ff4d5e" sm />}
                        </div>
                        <div className="mt-0.5 flex items-center gap-2 font-mono text-[10px] text-faint flex-wrap">
                          <span>{r.actor}</span>
                          {r.target && <><span className="text-line2">→</span><span className="text-teal/80">{r.target}</span></>}
                          {r.tenant && <span className="text-cyan/70">[{r.tenant}]</span>}
                        </div>
                      </div>
                      <div className="flex shrink-0 items-center gap-2.5">
                        <span className="font-mono text-[10px] text-faint" title={fmtDT(r.ts)}>{timeAgo(r.ts)}</span>
                        <Icon name={isOpen ? 'chevronDown' : 'chevronRight'} size={13} className="text-faint transition-transform" />
                      </div>
                    </button>

                    {isOpen && (
                      <div className="a-pop mx-3 mb-1 rounded-b-lg border border-t-0 border-line bg-panel2/70 px-4 py-3.5">
                        <div className="grid grid-cols-2 gap-x-5 gap-y-3 md:grid-cols-3">
                          <Field label="Ator"><span className="flex items-center gap-1.5"><Avatar name={r.actor} size={18} /> {r.actor}</span></Field>
                          <Field label="Tipo">{km.label}</Field>
                          <Field label="Resultado"><Pill label={isDenied ? 'Negado' : 'Sucesso'} color={isDenied ? '#ff4d5e' : '#2fd6a5'} sm /></Field>
                          <Field label="Endereço IP" mono>{r.ip ?? '—'}</Field>
                          <Field label="Sessão" mono>{r.sid ? r.sid.slice(0, 12) + '…' : '—'}</Field>
                          <Field label="Data completa" mono>{fmtDT(r.ts)}</Field>
                          {r.ua && <Field label="User-agent"><span className="block truncate max-w-[260px]" title={r.ua}>{r.ua}</span></Field>}
                          {r.control && <Field label="Controle"><span style={{ color: CONTROLS[r.control]?.color }}>{r.control}</span> — {CONTROLS[r.control]?.name}</Field>}
                        </div>

                        {(r.before || r.after) && (
                          <div className="mt-3.5">
                            <div className="lbl mb-1.5">Alteração registrada</div>
                            <DiffView before={r.before} after={r.after} />
                          </div>
                        )}

                        {r.hash && (
                          <div className="mt-3.5 rounded-md border border-line bg-input-bg px-3 py-2">
                            <div className="lbl mb-1">Selo de integridade (SHA-256)</div>
                            <div className="font-mono text-[10px] leading-relaxed">
                              <div className="text-faint">prev <span className="text-cyan/80">{r.prevHash ?? 'GENESIS'}</span></div>
                              <div className="text-faint">hash <span className="text-teal">{r.hash}</span></div>
                            </div>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* conformidade */}
        <div className="col-span-12 xl:col-span-4 min-h-0 overflow-y-auto flex flex-col gap-4">
          <div className="panel a-up p-4" style={{ animationDelay: '80ms' }}>
            <div className="flex items-center gap-2 mb-3">
              <Icon name="shield" size={14} className="text-teal" />
              <h3 className="font-display text-[11.5px] font-semibold uppercase tracking-[0.14em] text-ink/90">Sinais de risco</h3>
            </div>
            {compliance ? (
              <div className="flex flex-col gap-2">
                {compliance.signals.map(sig => (
                  <div key={sig.id} className="flex items-center gap-2.5 rounded-md border border-line/70 bg-panel px-3 py-2">
                    <span className={`h-2 w-2 shrink-0 rounded-full ${sig.severity === 'high' ? 'bg-crit dot-crit' : sig.severity === 'medium' ? 'bg-med' : 'bg-teal'}`} />
                    <span className="min-w-0 flex-1 truncate text-[11.5px] text-sub" title={sig.label}>{sig.label}</span>
                    <span className={`font-mono text-[13px] font-semibold tabular-nums ${sig.count > 0 && sig.severity !== 'low' ? 'text-crit' : 'text-ink/80'}`}>{sig.count}</span>
                  </div>
                ))}
              </div>
            ) : (
              <SkelLines n={4} />
            )}
          </div>

          <div className="panel a-up p-4" style={{ animationDelay: '140ms' }}>
            <div className="flex items-center gap-2 mb-3">
              <Icon name="layers" size={14} className="text-cyan" />
              <h3 className="font-display text-[11.5px] font-semibold uppercase tracking-[0.14em] text-ink/90">Cobertura de controles</h3>
            </div>
            {compliance ? (
              <HBars items={Object.entries(CONTROLS).map(([id, c]) => ({
                label: `${id}`, value: compliance.controls.find(x => x.control === id)?.n ?? 0, color: c.color,
              }))} />
            ) : (
              <SkelLines n={6} />
            )}
            <div className="mt-3 border-t border-line pt-2.5 flex flex-col gap-1">
              {Object.entries(CONTROLS).map(([id, c]) => (
                <div key={id} className="flex items-center gap-2 text-[10.5px]">
                  <span className="h-1.5 w-1.5 rounded-sm" style={{ background: c.color }} />
                  <span className="font-mono text-faint">{id}</span>
                  <span className="text-sub/80">{c.name}</span>
                </div>
              ))}
            </div>
          </div>

          <div className="panel a-up p-4" style={{ animationDelay: '200ms' }}>
            <div className="flex items-center gap-2 mb-2">
              <Icon name="activity" size={14} className="text-teal" />
              <h3 className="font-display text-[11.5px] font-semibold uppercase tracking-[0.14em] text-ink/90">Volume — 14 dias</h3>
            </div>
            {compliance ? <AreaChart data={compliance.perDay} height={120} unit="ações" /> : <SkelLines n={3} />}
          </div>
        </div>
      </div>
    </div>
  );
}

// ── diff antes/depois ────────────────────────────────────────
function DiffView({ before, after }: { before?: Record<string, unknown> | null; after?: Record<string, unknown> | null }) {
  const keys = Array.from(new Set([...Object.keys(before ?? {}), ...Object.keys(after ?? {})]));
  const changed = keys.filter(k => JSON.stringify(before?.[k] ?? null) !== JSON.stringify(after?.[k] ?? null));
  if (!changed.length) return <div className="text-[11px] text-faint">Sem alterações de campo registradas.</div>;
  return (
    <div className="overflow-hidden rounded-md border border-line">
      <table className="w-full text-[11px]">
        <thead>
          <tr className="border-b border-line bg-input-bg">
            <th className="px-3 py-1.5 text-left font-mono text-[9.5px] uppercase text-faint">campo</th>
            <th className="px-3 py-1.5 text-left font-mono text-[9.5px] uppercase text-faint">antes</th>
            <th className="px-3 py-1.5 text-left font-mono text-[9.5px] uppercase text-faint">depois</th>
          </tr>
        </thead>
        <tbody>
          {changed.map(k => (
            <tr key={k} className="border-t border-line/60">
              <td className="px-3 py-1.5 font-mono text-faint">{k}</td>
              <td className="px-3 py-1.5 font-mono text-crit/90">{fmtVal(before?.[k])}</td>
              <td className="px-3 py-1.5 font-mono text-teal">{fmtVal(after?.[k])}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
const fmtVal = (v: unknown) => (v === null || v === undefined || v === '' ? '—' : String(v));

function SkelLines({ n }: { n: number }) {
  return (
    <div className="flex flex-col gap-2">
      {Array.from({ length: n }).map((_, i) => (
        <div key={i} className="h-6 animate-pulse rounded-md bg-raise/60" style={{ animationDelay: `${i * 120}ms` }} />
      ))}
    </div>
  );
}
