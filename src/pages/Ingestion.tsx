import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { api as srv } from '../lib/api';
import type { IngestStats, IngestTestResult } from '../lib/api';
import { SEV_META, type Ev, type Severity } from '../data/mock';
import { timeAgo, useNow, useStore } from '../lib/store';
import { Icon, Pill, SevBadge } from '../components/ui';
import { Spark } from '../components/charts';
import type { IconName } from '../components/icons';

// estágios do pipeline de ingestão
const STAGES: { id: string; label: string; icon: IconName; color: string; desc: string }[] = [
  { id: 'collect', label: 'Coleta', icon: 'radar', color: '#56c4ff', desc: 'Connectors puxam eventos das fontes (poll/webhook)' },
  { id: 'normalize', label: 'Normalização', icon: 'layers', color: '#2fd6a5', desc: 'Qualquer fonte vira o modelo comum do SOPIR' },
  { id: 'dedup', label: 'Deduplicação', icon: 'copy', color: '#ffc53d', desc: 'O mesmo evento coletado duas vezes não duplica' },
  { id: 'correlate', label: 'Correlação', icon: 'crosshair', color: '#ff9142', desc: 'Padrões em janela disparam alertas por política' },
  { id: 'alert', label: 'Alertas', icon: 'bell', color: '#ff4d5e', desc: 'Eventos críticos/alto geram alertas para triagem' },
];

// modelo de evento de teste (editável)
const SAMPLE_EVENT = {
  source: 'Wazuh',
  rule: 'Modificação em massa de arquivos',
  ruleId: '5551',
  level: 14,
  severity: 'critical',
  srcIp: '10.0.4.18',
  dstIp: '10.0.1.20',
  user: 'j.pereira',
  host: 'WS-FIN-014',
  tenant: 'vetra',
};

export default function Ingestion() {
  const { s, scope, backend } = useStore();
  const online = backend === 'online';
  const now = useNow(2000);

  const [stats, setStats] = useState<IngestStats | null>(null);
  const [epsHistory, setEpsHistory] = useState<Record<string, number[]>>({});
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<IngestTestResult | null>(null);
  const [testErr, setTestErr] = useState('');
  const [evJson, setEvJson] = useState(JSON.stringify(SAMPLE_EVENT, null, 2));

  // buffer local (modo demonstração)
  const localEvents = useMemo(() => scope(s.events), [s.events, s.tenant]); // eslint-disable-line react-hooks/exhaustive-deps

  const load = useCallback(async () => {
    if (online) {
      const res = await srv.ingestStats();
      if (res) {
        setStats(res);
        setEpsHistory(prev => {
          const next: Record<string, number[]> = { ...prev };
          for (const [src, n] of Object.entries(res.epsBySource)) {
            next[src] = [...(prev[src] ?? []).slice(-23), n];
          }
          return next;
        });
      }
    }
  }, [online]);

  useEffect(() => { void load(); }, [load]);
  useEffect(() => {
    if (!online) return;
    const t = setInterval(() => void load(), 2500);
    return () => clearInterval(t);
  }, [online, load]);

  // dados exibidos: online → stats da API · demo → derivados do buffer local
  const recent: Ev[] = stats?.recent ?? localEvents.slice(0, 20);
  const epsBySource = useMemo(() => {
    if (stats) return stats.epsBySource;
    const acc: Record<string, number> = {};
    for (const e of localEvents) if (now - e.ts < 60_000) acc[e.source] = (acc[e.source] ?? 0) + 1;
    return acc;
  }, [stats, localEvents, now]);
  const totalEps = Object.values(epsBySource).reduce((a, b) => a + b, 0);

  const pipeline = stats?.pipeline ?? null;

  const runTest = async () => {
    setTestErr(''); setTestResult(null);
    let event: Record<string, unknown>;
    try { event = JSON.parse(evJson); } catch { setTestErr('JSON inválido.'); return; }
    if (!online) { setTestErr('O teste de ingestão requer a sopir-api conectada (modo online).'); return; }
    setTesting(true);
    const res = await srv.ingestTest(event);
    setTesting(false);
    if (res) setTestResult(res); else setTestErr('Falha ao enviar o evento de teste.');
  };

  const sevDist = useMemo(() => {
    const acc: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const e of recent) acc[e.severity] += 1;
    return acc;
  }, [recent]);

  return (
    <div className="h-full overflow-y-auto">
      <div className="mx-auto flex max-w-[1400px] flex-col gap-4 p-5">

        {/* cabeçalho + métricas principais */}
        <div className="a-up flex flex-wrap items-end justify-between gap-3">
          <div>
            <div className="lbl mb-1 flex items-center gap-2">
              <span className="inline-block h-1.5 w-1.5 rounded-full bg-teal dot-live" />
              pipeline em tempo real · {online ? 'sopir-api' : 'demonstração'}
            </div>
            <h2 className="font-display text-[22px] font-bold tracking-tight text-ink">Centro de Ingestão</h2>
          </div>
          <div className="flex items-center gap-3">
            <div className="panel flex items-center gap-3 px-4 py-2.5">
              <Icon name="activity" size={18} className="text-teal" />
              <div>
                <div className="font-mono text-[20px] font-bold leading-none tabular-nums text-ink">{totalEps}</div>
                <div className="lbl">eventos / min</div>
              </div>
            </div>
            <div className="panel hidden sm:flex items-center gap-3 px-4 py-2.5">
              <Icon name="database" size={18} className="text-cyan" />
              <div>
                <div className="font-mono text-[20px] font-bold leading-none tabular-nums text-ink">
                  {pipeline ? pipeline.normalized.toLocaleString('pt-BR') : localEvents.length.toLocaleString('pt-BR')}
                </div>
                <div className="lbl">normalizados</div>
              </div>
            </div>
          </div>
        </div>

        {/* pipeline de normalização */}
        <div className="panel a-up p-5" style={{ animationDelay: '60ms' }}>
          <div className="flex items-center gap-2 mb-4">
            <Icon name="layers" size={15} className="text-teal" />
            <h3 className="font-display text-[12px] font-semibold uppercase tracking-[0.14em] text-ink/90">Pipeline de normalização</h3>
            <span className="ml-auto font-mono text-[10px] text-faint">coleta → modelo comum → dedup → correlação → alerta</span>
          </div>
          <div className="flex flex-col lg:flex-row items-stretch gap-2">
            {STAGES.map((st, i) => {
              const count =
                st.id === 'collect' ? (pipeline ? pipeline.normalized + pipeline.deduped : localEvents.length)
                : st.id === 'normalize' ? (pipeline?.normalized ?? localEvents.length)
                : st.id === 'dedup' ? (pipeline?.deduped ?? 0)
                : st.id === 'correlate' ? (pipeline?.correlations ?? 0)
                : (pipeline?.autoAlerts ?? 0);
              return (
                <div key={st.id} className="flex items-center flex-1 min-w-0">
                  <div className="group relative flex-1 rounded-lg border border-line bg-panel2/70 p-3.5 transition-all hover:border-line2">
                    <div className="flex items-center gap-2.5">
                      <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg" style={{ background: st.color + '1a', color: st.color, border: `1px solid ${st.color}40` }}>
                        <Icon name={st.icon} size={15} />
                      </span>
                      <div className="min-w-0">
                        <div className="text-[12.5px] font-semibold text-ink/95">{st.label}</div>
                        <div className="font-mono text-[11px] tabular-nums" style={{ color: st.color }}>{count.toLocaleString('pt-BR')}</div>
                      </div>
                    </div>
                    <div className="pointer-events-none absolute left-1/2 top-full z-20 mt-1 w-56 -translate-x-1/2 rounded-md border border-line bg-[#0a1322] px-3 py-2 text-[10.5px] text-sub opacity-0 shadow-lg transition-opacity group-hover:opacity-100">
                      {st.desc}
                    </div>
                  </div>
                  {i < STAGES.length - 1 && (
                    <svg className="mx-0.5 hidden lg:block h-5 w-6 shrink-0" viewBox="0 0 24 20">
                      <path d="M0 10 H16 M11 4 L18 10 L11 16" fill="none" stroke="#2fd6a5" strokeWidth="1.6" className="dashline" opacity="0.7" />
                    </svg>
                  )}
                </div>
              );
            })}
          </div>
          {pipeline && pipeline.suppressed > 0 && (
            <div className="mt-3 flex items-center gap-2 rounded-md border border-med/30 bg-med/[.06] px-3 py-2 text-[11px] text-med">
              <Icon name="bell" size={12} /> {pipeline.suppressed} alerta(s) suprimido(s) por regras ativas
            </div>
          )}
        </div>

        <div className="grid grid-cols-12 gap-4">
          {/* EPS por fonte */}
          <div className="panel a-up col-span-12 md:col-span-5 p-4" style={{ animationDelay: '100ms' }}>
            <div className="flex items-center gap-2 mb-3">
              <Icon name="radar" size={14} className="text-cyan" />
              <h3 className="font-display text-[11.5px] font-semibold uppercase tracking-[0.14em] text-ink/90">Vazão por fonte</h3>
              <span className="ml-auto font-mono text-[10px] text-faint">eventos / min · 60s</span>
            </div>
            <div className="flex flex-col gap-3">
              {Object.entries(epsBySource).map(([src, n]) => (
                <div key={src} className="flex items-center gap-3">
                  <span className="w-[86px] shrink-0 font-mono text-[11.5px] text-sub">{src}</span>
                  <div className="flex-1"><Spark data={epsHistory[src] ?? [n]} color={src === 'Wazuh' ? '#2fd6a5' : '#56c4ff'} w={130} h={26} /></div>
                  <span className="w-[42px] text-right font-mono text-[14px] font-bold tabular-nums text-ink">{n}</span>
                </div>
              ))}
              {Object.keys(epsBySource).length === 0 && <div className="py-3 text-center text-[11.5px] text-faint">Sem eventos na última janela.</div>}
            </div>
            <div className="mt-4 border-t border-line pt-3">
              <div className="lbl mb-2">Severidade (eventos recentes)</div>
              <div className="flex flex-wrap gap-2">
                {(Object.keys(sevDist) as Severity[]).map(sv => sevDist[sv] > 0 && (
                  <span key={sv} className="flex items-center gap-1.5 rounded-md px-2 py-1 font-mono text-[10.5px]" style={{ color: SEV_META[sv].color, background: SEV_META[sv].color + '14', border: `1px solid ${SEV_META[sv].color}38` }}>
                    <span className="h-1.5 w-1.5 rounded-full" style={{ background: SEV_META[sv].color }} />{SEV_META[sv].label} {sevDist[sv]}
                  </span>
                ))}
              </div>
            </div>
          </div>

          {/* tester de ingestão */}
          <div className="panel a-up col-span-12 md:col-span-7 p-4" style={{ animationDelay: '140ms' }}>
            <div className="flex items-center gap-2 mb-3">
              <Icon name="terminal" size={14} className="text-teal" />
              <h3 className="font-display text-[11.5px] font-semibold uppercase tracking-[0.14em] text-ink/90">Testar ingestão</h3>
              <span className="ml-auto font-mono text-[10px] text-faint">envie um evento pelo pipeline real</span>
            </div>
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
              <div>
                <div className="lbl mb-1.5">Evento (JSON)</div>
                <textarea className="input w-full h-[190px] resize-none font-mono text-[11px] leading-relaxed" value={evJson}
                  onChange={e => setEvJson(e.target.value)} spellCheck={false} />
                <div className="mt-2 flex items-center gap-2">
                  <button className="btn btn-primary btn-xs" onClick={runTest} disabled={testing || !online}>
                    <Icon name={testing ? 'activity' : 'send'} size={12} /> {testing ? 'Enviando…' : 'Enviar pelo pipeline'}
                  </button>
                  <button className="btn btn-ghost btn-xs" onClick={() => { setEvJson(JSON.stringify(SAMPLE_EVENT, null, 2)); setTestResult(null); setTestErr(''); }}>
                    restaurar exemplo
                  </button>
                </div>
                {testErr && <div className="mt-2 text-[11px] text-crit">{testErr}</div>}
                {!online && <div className="mt-2 text-[10.5px] text-faint">Conecte a sopir-api para executar o teste contra o pipeline real.</div>}
              </div>
              <div>
                <div className="lbl mb-1.5">Resultado</div>
                {testResult ? (
                  <div className="a-pop rounded-lg border border-line bg-panel2/70 p-3.5 h-[212px] overflow-y-auto">
                    <div className="flex items-center gap-2">
                      <span className={`flex h-7 w-7 items-center justify-center rounded-full ${testResult.accepted ? 'bg-teal/15 text-teal' : 'bg-med/15 text-med'}`}>
                        <Icon name={testResult.accepted ? 'check' : 'alertTriangle'} size={14} />
                      </span>
                      <div>
                        <div className="text-[12.5px] font-semibold text-ink">{testResult.accepted ? 'Evento aceito' : 'Evento deduplicado'}</div>
                        {testResult.code && <div className="font-mono text-[10.5px] text-teal">{testResult.code}</div>}
                      </div>
                      <SevBadge sev={testResult.severity as Severity} sm />
                    </div>
                    <div className="mt-3 flex flex-col gap-1.5 text-[11.5px]">
                      <div className="flex justify-between"><span className="text-faint">Alerta automático</span><span className="font-mono text-ink">{testResult.alertCreated ?? '—'}</span></div>
                      <div className="flex justify-between"><span className="text-faint">Correlações disparadas</span><span className="font-mono text-ink">{testResult.correlationsFired}</span></div>
                    </div>
                    <div className="mt-3 rounded-md border border-line bg-[#0a1322] px-3 py-2 text-[10.5px] text-sub">{testResult.note}</div>
                  </div>
                ) : (
                  <div className="flex h-[212px] flex-col items-center justify-center gap-2 rounded-lg border border-dashed border-line text-center">
                    <Icon name="zap" size={20} className="text-faint" />
                    <span className="max-w-[240px] text-[11px] text-faint">O resultado mostra se o evento virou alerta, disparou correlação ou foi deduplicado.</span>
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* fluxo ao vivo */}
          <div className="panel a-up col-span-12 p-0" style={{ animationDelay: '180ms' }}>
            <div className="panel-hd">
              <Icon name="activity" size={14} className="text-teal" />
              <h3 className="font-display text-[11.5px] font-semibold uppercase tracking-[0.14em] text-ink/90">Fluxo de eventos normalizados</h3>
              <span className="ml-auto flex items-center gap-1.5 font-mono text-[10px] text-teal"><span className="h-1.5 w-1.5 rounded-full bg-teal dot-live" />ao vivo</span>
            </div>
            <div className="max-h-[320px] overflow-y-auto px-2 py-2">
              {recent.length === 0 && <div className="py-8 text-center text-[12px] text-faint">Nenhum evento recente.</div>}
              {recent.map((e, i) => (
                <div key={e.id + i} className={`${i === 0 ? 'flash-new' : ''} a-row flex items-center gap-3 rounded-md px-3 py-[7px] hover:bg-raise transition-colors`} style={{ animationDelay: `${Math.min(i, 10) * 30}ms` }}>
                  <span className="w-[62px] shrink-0 font-mono text-[10px] text-faint tabular-nums">{new Date(e.ts).toTimeString().slice(0, 8)}</span>
                  <span className="h-1.5 w-1.5 shrink-0 rounded-full" style={{ background: SEV_META[e.severity].color, boxShadow: `0 0 6px ${SEV_META[e.severity].color}` }} />
                  <span className="w-[72px] shrink-0 font-mono text-[10px] text-cyan/80">{e.source}</span>
                  <span className="min-w-0 flex-1 truncate text-[11.5px] text-ink/85">{e.rule}</span>
                  <span className="hidden md:block w-[90px] shrink-0 truncate font-mono text-[10px] text-sub">{e.host}</span>
                  <span className="w-[70px] shrink-0 text-right font-mono text-[9.5px] text-faint">{timeAgo(e.ts)}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
