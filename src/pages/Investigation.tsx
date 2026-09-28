import { useMemo, useState } from 'react';
import type { GraphNodeType } from '../lib/graph';
import { NODE_META, seedSuggestions } from '../lib/graph';
import { timeAgo, useStore } from '../lib/store';
import GraphCanvas from '../components/GraphCanvas';
import { Icon, Pill } from '../components/ui';

const TYPE_OPTIONS: { value: GraphNodeType; label: string }[] = [
  { value: 'ip', label: 'IP' },
  { value: 'user', label: 'Usuário' },
  { value: 'host', label: 'Host / Endpoint' },
  { value: 'rule', label: 'Regra (ID)' },
  { value: 'ioc', label: 'IOC' },
  { value: 'incident', label: 'Incidente' },
];

export default function Investigation() {
  const {
    s, scope, nav, startInvestigation, expandNode, selectGraphNode,
    clearGraph, saveInvestigation, loadInvestigation, closeInvestigation,
  } = useStore();

  const [type, setType] = useState<GraphNodeType>('ip');
  const [value, setValue] = useState('');
  const [saving, setSaving] = useState(false);
  const [invName, setInvName] = useState('');

  const suggestions = useMemo(
    () => seedSuggestions({ events: scope(s.events), alerts: scope(s.alerts), incidents: scope(s.incidents), assets: scope(s.assets) }),
    [s.events, s.alerts, s.incidents, s.assets, s.tenant], // eslint-disable-line react-hooks/exhaustive-deps
  );

  const sel = s.graph.nodes.find(n => n.id === s.graphSel) ?? null;
  const selDegree = sel ? s.graph.edges.filter(e => e.source === sel.id || e.target === sel.id).length : 0;
  const investigations = useMemo(() => scope(s.investigations), [s.investigations, s.tenant]); // eslint-disable-line react-hooks/exhaustive-deps

  const go = () => { if (value.trim()) { startInvestigation(type, value.trim()); setValue(''); } };

  const openInModule = (t: GraphNodeType, v: string) => {
    if (t === 'host') nav('assets', { type: 'assetname', id: v });
    else if (t === 'incident') nav('incidents', { type: 'incident', id: v });
    else if (t === 'ioc' || t === 'ip' || t === 'user' || t === 'rule') { nav('explorer'); }
    else if (t === 'process') nav('explorer');
    else nav('explorer');
  };

  return (
    <div className="flex h-full">
      {/* ── painel lateral ── */}
      <aside className="a-up flex w-[300px] shrink-0 flex-col border-r border-line bg-panel/30">
        {/* busca / semente */}
        <div className="border-b border-line p-4">
          <div className="lbl mb-2 flex items-center gap-1.5"><Icon name="search" size={12} /> Ponto de partida</div>
          <div className="flex gap-2">
            <select className="select w-[104px] shrink-0 py-1.5! text-[11.5px]" value={type} onChange={e => setType(e.target.value as GraphNodeType)}>
              {TYPE_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
            </select>
            <input className="input min-w-0 flex-1 py-1.5! font-mono text-[11.5px]" placeholder={type === 'ip' ? '45.155.205.86' : type === 'incident' ? 'INC-2041' : 'valor…'}
              value={value} onChange={e => setValue(e.target.value)} onKeyDown={e => e.key === 'Enter' && go()} />
          </div>
          <button className="btn btn-primary mt-2.5 w-full" onClick={go} disabled={!value.trim()}>
            <Icon name="network" size={14} /> Iniciar investigação
          </button>

          {suggestions.length > 0 && (
            <div className="mt-3">
              <div className="lbl mb-1.5">Sugestões do ambiente</div>
              <div className="flex flex-wrap gap-1.5">
                {suggestions.map(sg => (
                  <button key={sg.type + sg.value} className="chip px-2! py-1! font-mono text-[10px]!"
                    onClick={() => { setType(sg.type); startInvestigation(sg.type, sg.value); }}>
                    <span className="h-1.5 w-1.5 rounded-full" style={{ background: NODE_META[sg.type].color }} />
                    {sg.value.length > 16 ? sg.value.slice(0, 15) + '…' : sg.value}
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* nó selecionado */}
        {sel && (
          <div className="border-b border-line p-4">
            <div className="lbl mb-2 flex items-center gap-1.5"><Icon name="target" size={12} /> Entidade selecionada</div>
            <div className="rounded-lg border border-line bg-panel p-3">
              <div className="flex items-center gap-2">
                <span className="h-2.5 w-2.5 shrink-0 rounded-full" style={{ background: NODE_META[sel.type].color, boxShadow: `0 0 8px ${NODE_META[sel.type].color}66` }} />
                <span className="truncate font-mono text-[12px] font-semibold text-ink" title={sel.value}>{sel.value}</span>
              </div>
              <div className="mt-1.5 flex items-center gap-2">
                <Pill label={NODE_META[sel.type].label} color={NODE_META[sel.type].color} sm />
                <span className="font-mono text-[10px] text-faint">{selDegree} conexões</span>
                {s.graphRoot && `${s.graphRoot.type}:${s.graphRoot.value}` === sel.id && <Pill label="raiz" color="#2fd6a5" sm />}
              </div>
              {sel.sub && <div className="mt-1.5 text-[10.5px] text-faint">{sel.sub}</div>}
              <div className="mt-2.5 flex flex-col gap-1.5">
                <button className="btn btn-xs justify-start" onClick={() => expandNode(sel.id)}>
                  <Icon name="chevronRight" size={12} /> Expandir conexões
                </button>
                <button className="btn btn-xs justify-start" onClick={() => openInModule(sel.type, sel.value)}>
                  <Icon name="external" size={12} /> Abrir no módulo
                </button>
              </div>
            </div>
            <div className="mt-2 text-[10px] leading-relaxed text-faint">
              Dica: clique num nó para selecionar, <span className="text-sub">duplo clique</span> para expandir, arraste para reposicionar.
            </div>
          </div>
        )}

        {/* investigações salvas */}
        <div className="min-h-0 flex-1 overflow-y-auto p-4">
          <div className="lbl mb-2 flex items-center gap-1.5"><Icon name="folder" size={12} /> Investigações salvas · {investigations.length}</div>
          {investigations.length === 0 && (
            <div className="rounded-lg border border-dashed border-line px-3 py-4 text-center text-[11px] text-faint">
              Nenhuma investigação salva ainda. Construa o grafo e clique em “Salvar”.
            </div>
          )}
          {investigations.map(inv => (
            <div key={inv.id} className="group mb-2 rounded-lg border border-line bg-panel p-3 transition-colors hover:border-line2">
              <button className="block w-full text-left" onClick={() => loadInvestigation(inv)}>
                <div className="flex items-center gap-2">
                  <span className="font-mono text-[10.5px] text-teal">{inv.id}</span>
                  <span className={`ml-auto rounded px-1.5 py-0.5 text-[8.5px] font-semibold uppercase tracking-wider ${inv.status === 'aberta' ? 'bg-med/15 text-med' : 'bg-teal/15 text-teal'}`}>{inv.status}</span>
                </div>
                <div className="mt-1 truncate text-[12px] font-medium text-ink/90">{inv.name}</div>
                <div className="mt-0.5 font-mono text-[9.5px] text-faint">
                  {inv.graph.nodes.length} nós · {inv.graph.edges.length} arestas · {timeAgo(inv.ts)}
                </div>
              </button>
              <button className="mt-1.5 hidden items-center gap-1 text-[10px] text-faint transition-colors hover:text-crit group-hover:flex"
                onClick={() => closeInvestigation(inv.id)}>
                <Icon name="x" size={10} /> encerrar investigação
              </button>
            </div>
          ))}
        </div>
      </aside>

      {/* ── canvas ── */}
      <div className="relative min-w-0 flex-1 p-4">
        {/* barra superior */}
        <div className="a-up mb-3 flex flex-wrap items-center gap-3">
          <div>
            <div className="lbl">grafo em construção</div>
            <div className="font-display text-[15px] font-semibold text-ink">
              {s.graphRoot ? <>Investigando <span className="font-mono text-teal">{s.graphRoot.value}</span></> : 'Nenhuma investigação ativa'}
            </div>
          </div>
          <div className="ml-auto flex items-center gap-2">
            <span className="rounded-lg border border-line bg-panel px-3 py-1.5 font-mono text-[11px] text-sub">
              {s.graph.nodes.length} nós · {s.graph.edges.length} arestas
            </span>
            {saving ? (
              <div className="flex items-center gap-1.5">
                <input autoFocus className="input w-[180px] py-1.5! text-[11.5px]" placeholder="Nome da investigação…"
                  value={invName} onChange={e => setInvName(e.target.value)}
                  onKeyDown={e => { if (e.key === 'Enter' && invName.trim()) { saveInvestigation(invName.trim()); setInvName(''); setSaving(false); } if (e.key === 'Escape') setSaving(false); }} />
                <button className="btn btn-primary btn-xs" disabled={!invName.trim()}
                  onClick={() => { saveInvestigation(invName.trim()); setInvName(''); setSaving(false); }}>
                  <Icon name="check" size={12} />
                </button>
              </div>
            ) : (
              <>
                <button className="btn btn-xs" onClick={() => setSaving(true)} disabled={!s.graph.nodes.length}>
                  <Icon name="folder" size={12} /> Salvar
                </button>
                <button className="btn btn-xs" onClick={clearGraph} disabled={!s.graph.nodes.length}>
                  <Icon name="x" size={12} /> Limpar
                </button>
              </>
            )}
          </div>
        </div>

        <div className="h-[calc(100%-64px)]">
          <GraphCanvas
            nodes={s.graph.nodes}
            edges={s.graph.edges}
            selected={s.graphSel}
            onSelect={selectGraphNode}
            onExpand={expandNode}
          />
        </div>
      </div>
    </div>
  );
}
