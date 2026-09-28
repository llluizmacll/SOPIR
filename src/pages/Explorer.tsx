import { useEffect, useMemo, useRef, useState } from 'react';
import type { Ev, Severity } from '../data/mock';
import { SEV_META, SEV_ORDER } from '../data/mock';
import { can, download, toCSV, useNow, useStore } from '../lib/store';
import { api as srv } from '../lib/api';
import { EmptyState, Field, Icon, SevBadge } from '../components/ui';

const PERIODS = [
  { id: '1h', label: '1h', ms: 3_600_000 },
  { id: '24h', label: '24h', ms: 24 * 3_600_000 },
  { id: '48h', label: '48h', ms: 48 * 3_600_000 },
  { id: 'all', label: 'tudo', ms: Infinity },
] as const;

// fontes conhecidas de fábrica — sempre oferecidas mesmo sem eventos ainda
// no buffer local; qualquer outra fonte observada nos dados é somada a esta lista
const KNOWN_SOURCES = ['Wazuh', 'FortiSIEM', 'Splunk', 'QRadar', 'Microsoft Defender'];

const PAGE_SIZE = 150;

// campos suportados na sintaxe campo:valor (aplicados client-side sobre a página carregada)
const FIELD_GETTERS: Record<string, (e: Ev) => string> = {
  'rule.id': e => e.ruleId, ruleid: e => e.ruleId,
  rule: e => e.rule,
  host: e => e.host,
  srcip: e => e.srcIp, src: e => e.srcIp,
  dstip: e => e.dstIp, dst: e => e.dstIp,
  user: e => e.user,
  severity: e => e.severity, sev: e => e.severity,
  source: e => e.source,
  id: e => e.id,
};

// separa tokens "campo:valor" do texto livre
function parseQuery(raw: string) {
  const fields: { field: string; value: string }[] = [];
  const free: string[] = [];
  for (const token of raw.trim().split(/\s+/).filter(Boolean)) {
    const m = token.match(/^([\w.]+):(.+)$/);
    if (m && FIELD_GETTERS[m[1].toLowerCase()]) fields.push({ field: m[1].toLowerCase(), value: m[2] });
    else free.push(token);
  }
  return { fields, freeText: free.join(' ').toLowerCase() };
}

export default function Explorer() {
  const { s, scope, nav, togglePause, reportEvent } = useStore();
  const now = useNow(15000);
  const [q, setQ] = useState('');
  const [period, setPeriod] = useState<string>('24h');
  const [sevs, setSevs] = useState<Severity[]>([]);
  const [source, setSource] = useState('all');
  const [expanded, setExpanded] = useState<string | null>(null);
  const [saved, setSaved] = useState<string[]>(() => {
    try { return JSON.parse(localStorage.getItem('sopir.savedSearches') ?? '[]'); } catch { return []; }
  });

  // ── busca real no backend (histórico completo, não só o buffer local) ──
  const [results, setResults] = useState<Ev[]>([]);
  const [loading, setLoading] = useState(false);
  const [hasMore, setHasMore] = useState(false);
  const online = s.backend === 'online';
  const reqSeq = useRef(0);

  useEffect(() => {
    if (s.focus?.type === 'event') { setQ(s.focus.id); nav('explorer', null); }
  }, [s.focus, nav]);

  const base = useMemo(() => scope(s.events), [s.events, s.tenant]); // eslint-disable-line react-hooks/exhaustive-deps

  const runSearch = async (offset: number, append: boolean) => {
    const mySeq = ++reqSeq.current;
    if (!online) return; // sem API não há o que buscar além do buffer local (fallback abaixo)
    setLoading(true);
    const p = PERIODS.find(x => x.id === period) ?? PERIODS[1];
    const { fields, freeText } = parseQuery(q);
    const fieldQ = fields.find(f => f.field !== 'severity' && f.field !== 'sev' && f.field !== 'source')?.value;
    const r = await srv.searchEvents({
      tenant: s.tenant, q: fieldQ || freeText || undefined,
      severity: sevs.length === 1 ? sevs[0] : undefined,
      source: source !== 'all' ? source : undefined,
      from: Number.isFinite(p.ms) ? now - p.ms : undefined,
      limit: PAGE_SIZE, offset,
    });
    if (mySeq !== reqSeq.current) return; // resposta obsoleta (filtro mudou no meio do caminho)
    setLoading(false);
    if (!r) return;
    setResults(prev => (append ? [...prev, ...r] : r));
    setHasMore(r.length === PAGE_SIZE);
  };

  // dispara nova busca (debounced pro texto) sempre que filtro ou tenant mudam
  useEffect(() => {
    const t = setTimeout(() => runSearch(0, false), q ? 320 : 0);
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [q, period, source, sevs.join(','), s.tenant, online]);

  // mantém a primeira página "viva": reaproveita o ciclo de refresh global do
  // app — mas pausa enquanto um evento estiver aberto, pra ele não sair
  // reordenando/descendo na tela embaixo do usuário. Volta a atualizar
  // normalmente assim que a linha é fechada.
  useEffect(() => {
    if (online && !expanded) runSearch(0, false);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [now]);

  // fallback: sem API (modo demo/offline), filtra o buffer local como antes
  // congela a base usada no filtro local enquanto um evento estiver aberto —
  // mesmo motivo do freio no runSearch acima: não deixar a lista reordenar
  // embaixo do usuário no modo offline/demo (sem isso, cada refresh do buffer
  // global de 8s recomputava tudo e o item aberto "descia" na tela)
  const frozenBase = useRef(base);
  if (!expanded) frozenBase.current = base;

  const localFiltered = useMemo(() => {
    if (online) return null;
    const effectiveBase = expanded ? frozenBase.current : base;
    const p = PERIODS.find(x => x.id === period) ?? PERIODS[1];
    const { fields, freeText } = parseQuery(q);
    return effectiveBase.filter(ev => {
      if (now - ev.ts > p.ms) return false;
      if (sevs.length && !sevs.includes(ev.severity)) return false;
      if (source !== 'all' && ev.source !== source) return false;
      for (const f of fields) {
        const val = (FIELD_GETTERS[f.field]?.(ev) ?? '').toLowerCase();
        if (!val.includes(f.value.toLowerCase())) return false;
      }
      if (freeText && ![ev.rule, ev.ruleId, ev.host, ev.srcIp, ev.dstIp, ev.user, ev.id, ev.desc]
        .some(x => x.toLowerCase().includes(freeText))) return false;
      return true;
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [online, base, period, sevs, source, q, now, expanded]);

  // multi-severidade: o backend só filtra por UMA severidade, então quando
  // várias estão marcadas refinamos a página recebida aqui do lado do cliente
  const events = useMemo(() => {
    const list = localFiltered ?? results;
    if (sevs.length > 1) return list.filter(e => sevs.includes(e.severity));
    return list;
  }, [localFiltered, results, sevs]);

  // fontes conhecidas + qualquer outra observada nos dados carregados (cobre
  // qualquer conector CEF genérico, cujo nome de fonte é o próprio fabricante)
  const sourceOptions = useMemo(() => {
    const seen = new Set([...KNOWN_SOURCES, ...base.map(e => e.source), ...results.map(e => e.source)]);
    return [...seen].sort();
  }, [base, results]);

  // facetas calculadas sobre a página atual de resultados
  const facets = useMemo(() => {
    const count = (get: (e: Ev) => string) => {
      const m = new Map<string, number>();
      for (const e of events) { const k = get(e); if (k && k !== '—') m.set(k, (m.get(k) ?? 0) + 1); }
      return [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, 6);
    };
    return { hosts: count(e => e.host), rules: count(e => e.rule), users: count(e => e.user) };
  }, [events]);

  // garante que o evento aberto não desapareça da lista quando a página
  // recarrega e ele sai da janela atual
  const visible = useMemo(() => {
    if (expanded && !events.some(e => e.id === expanded)) {
      const stuck = [...base, ...results].find(e => e.id === expanded);
      if (stuck) return [...events, stuck];
    }
    return events;
  }, [events, expanded, base, results]);

  const saveSearch = () => {
    const term = q.trim();
    if (!term || saved.includes(term)) return;
    const next = [term, ...saved].slice(0, 8);
    setSaved(next);
    try { localStorage.setItem('sopir.savedSearches', JSON.stringify(next)); } catch { /* noop */ }
  };
  const applyField = (field: string, value: string) =>
    setQ(prev => {
      const { fields, freeText } = parseQuery(prev);
      const rest = fields.filter(f => f.field !== field).map(f => `${f.field}:${f.value}`);
      return [...rest, freeText, `${field}:${value}`].filter(Boolean).join(' ');
    });

  const evPerMin = useMemo(
    () => (base.filter(e => now - e.ts < 600_000).length / 10).toFixed(1),
    [base, now],
  );

  const toggleSev = (sv: Severity) =>
    setSevs(prev => (prev.includes(sv) ? prev.filter(x => x !== sv) : [...prev, sv]));

  // eventos relacionados de verdade (histórico completo via API, não só o
  // buffer local) — buscado sob demanda quando a linha é aberta, com cache
  const [relatedCache, setRelatedCache] = useState<Record<string, Ev[] | 'loading'>>({});
  const loadRelated = async (ev: Ev) => {
    if (relatedCache[ev.id]) return;
    if (!online) {
      const local = base.filter(e => e.id !== ev.id
        && ((ev.host !== '—' && e.host === ev.host) || (ev.srcIp !== '—' && e.srcIp === ev.srcIp) || (ev.ruleId && e.ruleId === ev.ruleId)))
        .slice(0, 6);
      setRelatedCache(p => ({ ...p, [ev.id]: local }));
      return;
    }
    setRelatedCache(p => ({ ...p, [ev.id]: 'loading' }));
    const r = await srv.eventRelated(ev.id);
    setRelatedCache(p => ({ ...p, [ev.id]: r ?? [] }));
  };

  const exportCsv = () => {
    if (events.length > 500) {
      // eslint-disable-next-line no-alert
      if (!window.confirm(`O filtro atual tem ${events.length.toLocaleString('pt-BR')} eventos carregados — só os primeiros 500 vão pro CSV. Exportar mesmo assim?`)) return;
    }
    download('sopir-eventos.csv', toCSV(events.slice(0, 500).map(e => ({
      id: e.id, timestamp: new Date(e.ts).toISOString(), severidade: e.severity, regra: e.rule,
      regra_id: e.ruleId, origem: e.source, src_ip: e.srcIp, dst_ip: e.dstIp, usuario: e.user, host: e.host,
    }))), 'text/csv');
  };

  let raw: unknown = null;
  let rawError = false;
  if (expanded) {
    const ev = visible.find(e => e.id === expanded);
    if (ev) {
      try { raw = JSON.parse(ev.raw); } catch { rawError = true; raw = ev.raw; }
    }
  }

  return (
    <div className="flex h-full flex-col">
      {/* toolbar */}
      <div className="a-up shrink-0 border-b border-line bg-panel/40 px-5 py-3.5">
        <div className="flex flex-wrap items-center gap-2.5">
          <div className="relative min-w-[260px] flex-1 max-w-[520px]">
            <span className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-faint"><Icon name="terminal" size={14} /></span>
            <input className="input w-full pl-9 font-mono text-[12px]"
              placeholder='rule.id:5551 · host:WS-FIN · 45.155.205.86…'
              value={q} onChange={e => setQ(e.target.value)} />
            {q && (
              <button className="absolute right-2.5 top-1/2 -translate-y-1/2 text-faint hover:text-ink" onClick={() => setQ('')}>
                <Icon name="x" size={13} />
              </button>
            )}
          </div>

          <div className="flex items-center gap-1 rounded-lg border border-line bg-panel p-0.5">
            {PERIODS.map(p => (
              <button key={p.id} className={`rounded-md px-2.5 py-1 font-mono text-[11px] transition-colors ${period === p.id ? 'bg-teal/15 text-teal' : 'text-faint hover:text-ink'}`}
                onClick={() => setPeriod(p.id)}>
                {p.label}
              </button>
            ))}
          </div>

          <select className="select" value={source} onChange={e => setSource(e.target.value)}>
            <option value="all">Todas as fontes</option>
            {sourceOptions.map(src => <option key={src} value={src}>{src}</option>)}
          </select>

          {SEV_ORDER.map(sv => (
            <button key={sv} className={`chip ${sevs.includes(sv) ? 'on' : ''}`}
              style={sevs.includes(sv) ? { borderColor: SEV_META[sv].color + '66', color: SEV_META[sv].color } : undefined}
              onClick={() => toggleSev(sv)}>
              <span className="h-1.5 w-1.5 rounded-full" style={{ background: SEV_META[sv].color }} />
              {SEV_META[sv].label}
            </button>
          ))}

          <div className="ml-auto flex items-center gap-2">
            {loading && <Icon name="refresh" size={13} className="text-faint animate-spin" />}
            <button className="btn btn-xs" onClick={saveSearch} disabled={!q.trim()} title="Salvar busca atual">
              <Icon name="bookmark" size={12} /> salvar
            </button>
            <button className={`btn btn-xs ${s.paused ? 'btn-primary' : ''}`} onClick={togglePause}>
              <Icon name={s.paused ? 'play' : 'pause'} size={12} /> {s.paused ? 'retomar' : 'pausar'}
            </button>
            <button className="btn btn-xs" onClick={exportCsv} disabled={!can(s.role, 'reports.export')}>
              <Icon name="download" size={12} /> CSV
            </button>
          </div>
        </div>

        {/* buscas salvas + dicas de sintaxe */}
        {(saved.length > 0 || q.trim()) && (
          <div className="mt-2 flex flex-wrap items-center gap-1.5">
            {saved.map(t => (
              <button key={t} onClick={() => setQ(t)}
                className={`chip ${q === t ? 'on' : ''} font-mono text-[10.5px]!`} title="Aplicar busca salva">
                <Icon name="bookmark" size={10} /> {t}
              </button>
            ))}
            <span className="ml-auto hidden lg:inline font-mono text-[9.5px] text-faint">
              sintaxe: host:WS-FIN · rule.id:5551 · srcip:45.155 · severity:critical · texto livre
            </span>
          </div>
        )}

        {/* facetas */}
        {events.length > 0 && (
          <div className="mt-2.5 flex flex-wrap items-center gap-x-5 gap-y-1.5 border-t border-line/60 pt-2.5">
            {([['host', facets.hosts], ['rule', facets.rules], ['user', facets.users]] as const).map(([field, items]) => (
              <div key={field} className="flex items-center gap-1.5">
                <span className="lbl">{field}</span>
                {items.slice(0, 3).map(([val, n]) => (
                  <button key={val} onClick={() => applyField(field, val)}
                    className="rounded border border-line bg-panel px-1.5 py-0.5 font-mono text-[10px] text-sub transition-colors hover:border-teal/50 hover:text-teal">
                    {val} <span className="text-faint">{n}</span>
                  </button>
                ))}
              </div>
            ))}
          </div>
        )}

        <div className="mt-2.5 flex items-center gap-4 font-mono text-[10.5px] text-faint">
          <span><span className="text-teal">{events.length.toLocaleString('pt-BR')}</span> eventos carregados{hasMore && sevs.length <= 1 ? '+' : ''}</span>
          {online
            ? <span>busca no histórico completo</span>
            : <span>{base.length.toLocaleString('pt-BR')} no buffer local (sem conexão com a API)</span>}
          <span>{evPerMin} ev/min agora</span>
          <span className="ml-auto hidden md:inline">modelo normalizado SOPIR · origem → destino → usuário → host → regra</span>
        </div>
      </div>

      {/* tabela */}
      <div className="min-h-0 flex-1 overflow-auto px-5 py-4">
        {events.length === 0 ? (
          <EmptyState icon="radar" title={loading ? 'Buscando…' : 'Nenhum evento encontrado'}
            sub={loading ? 'Consultando o histórico completo.' : 'Ajuste o período, as severidades ou o termo de busca.'} />
        ) : (
          <>
          <table className="tbl">
            <thead>
              <tr>
                <th className="w-[86px]">Hora</th>
                <th className="w-[86px]">Sev</th>
                <th>Regra</th>
                <th className="w-[90px]">Fonte</th>
                <th className="hidden lg:table-cell">Origem → Destino</th>
                <th className="hidden md:table-cell w-[110px]">Usuário</th>
                <th className="w-[120px]">Host</th>
                <th className="w-[36px]" />
              </tr>
            </thead>
            <tbody>
              {visible.map(ev => {
                const isOpen = expanded === ev.id;
                const isNew = now - ev.ts < 30_000;
                return (
                  <FragmentRow key={ev.id}>
                    <tr className={`cursor-pointer ${isNew ? 'flash-new' : ''}`}
                      onClick={() => { const next = isOpen ? null : ev.id; setExpanded(next); if (next) void loadRelated(ev); }}>
                      <td className="font-mono text-[11px] text-faint tabular-nums">{new Date(ev.ts).toTimeString().slice(0, 8)}</td>
                      <td><SevBadge sev={ev.severity} sm /></td>
                      <td>
                        <div className="flex items-center gap-2">
                          <span className="text-[12.5px] text-ink/90">{ev.rule}</span>
                          <span className="font-mono text-[10px] text-faint">#{ev.ruleId}</span>
                        </div>
                      </td>
                      <td><span className="font-mono text-[11px] text-cyan/80">{ev.source}</span></td>
                      <td className="hidden lg:table-cell font-mono text-[11px] text-sub">{ev.srcIp} → {ev.dstIp}</td>
                      <td className="hidden md:table-cell font-mono text-[11px] text-sub">{ev.user}</td>
                      <td className="font-mono text-[11px] text-ink/80">{ev.host}</td>
                      <td className="text-faint"><Icon name={isOpen ? 'chevronDown' : 'chevronRight'} size={13} /></td>
                    </tr>
                    {isOpen && (
                      <tr>
                        <td colSpan={8} className="p-0!">
                          <div className="a-up grid grid-cols-1 gap-4 bg-input-bg/70 px-5 py-4 lg:grid-cols-3">
                            <div className="grid grid-cols-2 gap-x-4 gap-y-3">
                              <Field label="Origem" mono>{ev.srcIp}</Field>
                              <Field label="Destino" mono>{ev.dstIp}</Field>
                              <Field label="Usuário" mono>{ev.user}</Field>
                              <Field label="Host / IP" mono>{ev.host}{ev.hostIp ? ` · ${ev.hostIp}` : ''}</Field>
                              <Field label="Regra" mono>{ev.rule} (#{ev.ruleId})</Field>
                              <Field label="Severidade"><SevBadge sev={ev.severity} sm /></Field>
                              <Field label="Timestamp" mono>{new Date(ev.ts).toLocaleString('pt-BR')}</Field>
                              <Field label="Tenant">{ev.tenant}</Field>
                            </div>
                            <div>
                              <div className="lbl mb-2">Descrição</div>
                              <p className="text-[12.5px] leading-relaxed text-sub">{ev.desc}</p>
                              {ev.message && ev.message !== ev.desc && (
                                <>
                                  <div className="lbl mb-2 mt-3">Mensagem original</div>
                                  <p className="rounded-md border border-line bg-input-bg p-2.5 font-mono text-[11px] leading-relaxed text-sub break-words">{ev.message}</p>
                                </>
                              )}
                              <div className="mt-3 flex flex-wrap gap-2">
                                <button className="btn btn-xs btn-primary" onClick={() => reportEvent(ev.id)}
                                  disabled={!can(s.role, 'alerts.update')}>
                                  <Icon name="bell" size={12} /> Gerar alerta
                                </button>
                                <button className="btn btn-xs" onClick={() => setQ(ev.srcIp)}>
                                  <Icon name="crosshair" size={12} /> Investigar origem
                                </button>
                                <button className="btn btn-xs" onClick={() => setQ(ev.host)}>
                                  <Icon name="server" size={12} /> Eventos do host
                                </button>
                              </div>
                            </div>
                            <div>
                              <div className="lbl mb-2">Evento original (raw)</div>
                              <pre className="max-h-[150px] overflow-auto rounded-md border border-line bg-input-bg p-3 font-mono text-[10.5px] leading-relaxed text-sub">
                                {expanded === ev.id ? (rawError ? String(raw) : JSON.stringify(raw, null, 2)) : ''}
                              </pre>
                            </div>
                            <div className="lg:col-span-3">
                              <div className="lbl mb-2">Eventos relacionados — mesmo host, origem ou usuário (histórico completo)</div>
                              <div className="grid grid-cols-1 gap-1.5 md:grid-cols-2 xl:grid-cols-3">
                                {relatedCache[ev.id] === 'loading' && <span className="text-[11.5px] text-faint">Buscando…</span>}
                                {Array.isArray(relatedCache[ev.id]) && (relatedCache[ev.id] as Ev[]).length === 0 && (
                                  <span className="text-[11.5px] text-faint">Nenhum evento relacionado encontrado.</span>
                                )}
                                {Array.isArray(relatedCache[ev.id]) && (relatedCache[ev.id] as Ev[]).map(r => (
                                  <button key={r.id} className="flex items-center gap-2 rounded-md border border-line/70 bg-panel px-2.5 py-1.5 text-left hover:border-line2 transition-colors"
                                    onClick={() => { setExpanded(r.id); void loadRelated(r); }}>
                                    <span className="h-1.5 w-1.5 shrink-0 rounded-full" style={{ background: SEV_META[r.severity].color }} />
                                    <span className="truncate text-[11px] text-ink/80">{r.rule}</span>
                                    <span className="ml-auto shrink-0 font-mono text-[10px] text-faint">{r.host}</span>
                                  </button>
                                ))}
                              </div>
                            </div>
                          </div>
                        </td>
                      </tr>
                    )}
                  </FragmentRow>
                );
              })}
            </tbody>
          </table>
          {online && hasMore && sevs.length <= 1 && (
            <div className="flex justify-center py-4">
              <button className="btn btn-xs" disabled={loading} onClick={() => runSearch(results.length, true)}>
                <Icon name="chevronDown" size={12} /> Carregar mais {PAGE_SIZE}
              </button>
            </div>
          )}
          </>
        )}
      </div>
    </div>
  );
}

function FragmentRow({ children }: { children: React.ReactNode }) {
  return <>{children}</>;
}
