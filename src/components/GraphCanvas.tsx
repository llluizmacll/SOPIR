import { useEffect, useRef, useState } from 'react';
import type { GEdge, GNode, GraphNodeType } from '../lib/graph';
import { NODE_META } from '../lib/graph';
import { Icon } from './icons';

interface SimNode extends GNode { }

interface Props {
  nodes: GNode[];
  edges: GEdge[];
  selected: string | null;
  onSelect: (id: string | null) => void;
  onExpand: (id: string) => void;
}

const clamp = (v: number, a: number, b: number) => Math.max(a, Math.min(b, v));
const truncate = (s: string, n = 16) => (s.length > n ? s.slice(0, n - 1) + '…' : s);

export default function GraphCanvas({ nodes, edges, selected, onSelect, onExpand }: Props) {
  const svgRef = useRef<SVGSVGElement>(null);
  const simRef = useRef<Map<string, SimNode>>(new Map());
  const alphaRef = useRef(0);
  const rafRef = useRef(0);
  const dragRef = useRef<{ id: string | null; panning: boolean; sx: number; sy: number; ox: number; oy: number; moved: number }>({
    id: null, panning: false, sx: 0, sy: 0, ox: 0, oy: 0, moved: 0,
  });
  const [view, setView] = useState({ x: 0, y: 0, k: 1 });
  const [, setTick] = useState(0);
  const viewRef = useRef(view);
  viewRef.current = view;

  const size = { w: 1200, h: 800 };
  const center = { x: size.w / 2, y: size.h / 2 };

  // sincroniza nós da simulação com as props (preserva posições existentes)
  useEffect(() => {
    const sim = simRef.current;
    const ids = new Set(nodes.map(n => n.id));
    for (const id of [...sim.keys()]) if (!ids.has(id)) sim.delete(id);
    for (const n of nodes) {
      if (!sim.has(n.id)) {
        // novo nó: nasce perto de um vizinho já posicionado, ou no centro com jitter
        const neighbor = edges.find(e => e.source === n.id || e.target === n.id);
        const nbrId = neighbor ? (neighbor.source === n.id ? neighbor.target : neighbor.source) : null;
        const nbr = nbrId ? sim.get(nbrId) : undefined;
        const ang = Math.random() * Math.PI * 2;
        const rad = 90 + Math.random() * 60;
        sim.set(n.id, {
          ...n,
          x: nbr ? nbr.x + Math.cos(ang) * rad : center.x + (Math.random() - 0.5) * 200,
          y: nbr ? nbr.y + Math.sin(ang) * rad : center.y + (Math.random() - 0.5) * 200,
          vx: 0, vy: 0, fx: null, fy: null,
        });
      } else {
        const existing = sim.get(n.id)!;
        existing.type = n.type; existing.value = n.value; existing.sub = n.sub;
      }
    }
    alphaRef.current = 1; // reaquece
    start();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [nodes, edges]);

  const start = () => {
    if (rafRef.current) return;
    const loop = () => {
      step();
      setTick(t => t + 1);
      if (alphaRef.current > 0.004 || dragRef.current.id) {
        rafRef.current = requestAnimationFrame(loop);
      } else {
        rafRef.current = 0;
      }
    };
    rafRef.current = requestAnimationFrame(loop);
  };

  const step = () => {
    const sim = simRef.current;
    const arr = [...sim.values()];
    const alpha = alphaRef.current;
    const REP = 3200, SPRING = 0.02, L = 120, GRAV = 0.015, DAMP = 0.82;

    for (const a of arr) { a.vx = a.vx || 0; a.vy = a.vy || 0; }
    // repulsão
    for (let i = 0; i < arr.length; i++) {
      for (let j = i + 1; j < arr.length; j++) {
        const a = arr[i], b = arr[j];
        let dx = b.x - a.x, dy = b.y - a.y;
        let d2 = dx * dx + dy * dy;
        if (d2 < 0.01) { dx = Math.random() - 0.5; dy = Math.random() - 0.5; d2 = 0.5; }
        const d = Math.sqrt(d2);
        const f = (REP / d2) * alpha;
        const fx = (dx / d) * f, fy = (dy / d) * f;
        a.vx -= fx; a.vy -= fy; b.vx += fx; b.vy += fy;
      }
    }
    // molas
    for (const e of edges) {
      const a = sim.get(e.source), b = sim.get(e.target);
      if (!a || !b) continue;
      const dx = b.x - a.x, dy = b.y - a.y;
      const d = Math.max(1, Math.sqrt(dx * dx + dy * dy));
      const f = (d - L) * SPRING * alpha;
      const fx = (dx / d) * f, fy = (dy / d) * f;
      a.vx += fx; a.vy += fy; b.vx -= fx; b.vy -= fy;
    }
    // gravidade + integração
    for (const a of arr) {
      a.vx += (center.x - a.x) * GRAV * alpha;
      a.vy += (center.y - a.y) * GRAV * alpha;
      if (a.fx != null) { a.x = a.fx; a.vx = 0; } else { a.vx *= DAMP; a.x += a.vx; }
      if (a.fy != null) { a.y = a.fy; a.vy = 0; } else { a.vy *= DAMP; a.y += a.vy; }
    }
    alphaRef.current *= 0.985;
  };

  useEffect(() => () => { if (rafRef.current) cancelAnimationFrame(rafRef.current); }, []);

  const toGraph = (clientX: number, clientY: number) => {
    const rect = svgRef.current!.getBoundingClientRect();
    const px = ((clientX - rect.left) / rect.width) * size.w;
    const py = ((clientY - rect.top) / rect.height) * size.h;
    return { x: (px - viewRef.current.x) / viewRef.current.k, y: (py - viewRef.current.y) / viewRef.current.k };
  };

  const onNodeDown = (e: React.MouseEvent, id: string) => {
    e.stopPropagation();
    const n = simRef.current.get(id);
    if (!n) return;
    dragRef.current = { id, panning: false, sx: e.clientX, sy: e.clientY, ox: n.x, oy: n.y, moved: 0 };
    alphaRef.current = Math.max(alphaRef.current, 0.25);
    start();
  };

  const onBgDown = (e: React.MouseEvent) => {
    dragRef.current = { id: null, panning: true, sx: e.clientX, sy: e.clientY, ox: viewRef.current.x, oy: viewRef.current.y, moved: 0 };
  };

  const onMove = (e: React.MouseEvent) => {
    const d = dragRef.current;
    if (d.id) {
      const g = toGraph(e.clientX, e.clientY);
      const n = simRef.current.get(d.id);
      if (n) {
        n.fx = g.x; n.fy = g.y;
        d.moved += Math.abs(e.clientX - d.sx) + Math.abs(e.clientY - d.sy);
        d.sx = e.clientX; d.sy = e.clientY;
        alphaRef.current = Math.max(alphaRef.current, 0.2);
      }
    } else if (d.panning) {
      const rect = svgRef.current!.getBoundingClientRect();
      const scale = size.w / rect.width;
      const nx = d.ox + (e.clientX - d.sx) * scale;
      const ny = d.oy + (e.clientY - d.sy) * scale;
      d.moved += Math.abs(e.clientX - d.sx) + Math.abs(e.clientY - d.sy);
      setView(v => ({ ...v, x: nx, y: ny }));
    }
  };

  const onUp = () => {
    const d = dragRef.current;
    if (d.id) {
      const n = simRef.current.get(d.id);
      if (n) { n.fx = null; n.fy = null; }
      if (d.moved < 6) onSelect(d.id);
    } else if (d.panning && d.moved < 6) {
      onSelect(null);
    }
    dragRef.current = { ...d, id: null, panning: false };
  };

  const onWheel = (e: React.WheelEvent) => {
    const rect = svgRef.current!.getBoundingClientRect();
    const px = ((e.clientX - rect.left) / rect.width) * size.w;
    const py = ((e.clientY - rect.top) / rect.height) * size.h;
    setView(v => {
      const k2 = clamp(v.k * (e.deltaY < 0 ? 1.12 : 0.89), 0.3, 3);
      return { k: k2, x: px - (px - v.x) * (k2 / v.k), y: py - (py - v.y) * (k2 / v.k) };
    });
  };

  const fit = () => {
    const arr = [...simRef.current.values()];
    if (!arr.length) { setView({ x: 0, y: 0, k: 1 }); return; }
    const xs = arr.map(n => n.x), ys = arr.map(n => n.y);
    const minX = Math.min(...xs) - 80, maxX = Math.max(...xs) + 80;
    const minY = Math.min(...ys) - 80, maxY = Math.max(...ys) + 80;
    const k = clamp(Math.min(size.w / (maxX - minX), size.h / (maxY - minY)), 0.3, 1.6);
    setView({ k, x: (size.w - (minX + maxX) * k) / 2, y: (size.h - (minY + maxY) * k) / 2 });
  };

  const relayout = () => {
    for (const n of simRef.current.values()) {
      n.x = center.x + (Math.random() - 0.5) * 300;
      n.y = center.y + (Math.random() - 0.5) * 300;
      n.vx = 0; n.vy = 0; n.fx = null; n.fy = null;
    }
    alphaRef.current = 1; start();
  };

  const sim = simRef.current;
  // calculado a cada frame (as posições mudam durante a simulação)
  const edgeList = edges.map(e => ({
    e, a: sim.get(e.source), b: sim.get(e.target),
  })).filter(x => x.a && x.b);

  return (
    <div className="relative h-full w-full overflow-hidden rounded-xl border border-line bg-input-bg">
      {/* grade de fundo */}
      <div className="pointer-events-none absolute inset-0" style={{
        backgroundImage: 'radial-gradient(rgba(86,150,255,0.08) 1px, transparent 1px)',
        backgroundSize: '26px 26px',
      }} />
      <svg
        ref={svgRef}
        className="h-full w-full cursor-grab active:cursor-grabbing"
        viewBox={`0 0 ${size.w} ${size.h}`}
        preserveAspectRatio="xMidYMid meet"
        onMouseDown={onBgDown} onMouseMove={onMove} onMouseUp={onUp} onMouseLeave={onUp}
        onWheel={onWheel}
      >
        <g transform={`translate(${view.x} ${view.y}) scale(${view.k})`}>
          {/* arestas */}
          {edgeList.map(({ e, a, b }) => {
            const mx = (a!.x + b!.x) / 2, my = (a!.y + b!.y) / 2;
            const active = selected && (e.source === selected || e.target === selected);
            return (
              <g key={e.id} style={{ animation: 'kf-fade .5s both' }}>
                <line x1={a!.x} y1={a!.y} x2={b!.x} y2={b!.y}
                  stroke={active ? '#2fd6a5' : 'var(--color-line2)'} strokeWidth={active ? 1.8 : 1.1}
                  strokeOpacity={active ? 0.9 : 0.55} />
                <text x={mx} y={my - 4} textAnchor="middle" fontSize="9.5"
                  fill={active ? 'var(--color-teal2)' : 'var(--color-faint)'} fontFamily="JetBrains Mono, monospace"
                  style={{ paintOrder: 'stroke', stroke: 'var(--color-input-bg)', strokeWidth: 3 }}>
                  {e.label}
                </text>
              </g>
            );
          })}
          {/* nós */}
          {[...sim.values()].map(n => {
            const meta = NODE_META[n.type];
            const isSel = selected === n.id;
            return (
              <g key={n.id} transform={`translate(${n.x} ${n.y})`}
                className="cursor-pointer" onMouseDown={(e) => onNodeDown(e, n.id)}
                onDoubleClick={(e) => { e.stopPropagation(); onExpand(n.id); }}>
                <g style={{ animation: 'kf-pop .3s both' }}>
                  {isSel && <circle r={meta.r + 7} fill="none" stroke={meta.color} strokeOpacity="0.5" strokeWidth="1.5" className="dot-live" style={{ animation: 'kf-ping 1.6s ease-out infinite' }} />}
                  <circle r={meta.r} fill={meta.color + '22'} stroke={meta.color} strokeWidth={isSel ? 2.2 : 1.4}
                    style={{ filter: isSel ? `drop-shadow(0 0 8px ${meta.color})` : undefined, transition: 'stroke-width .15s' }} />
                  <circle r={3.2} fill={meta.color} />
                  <text y={meta.r + 15} textAnchor="middle" fontSize="11" fontWeight={isSel ? 700 : 500}
                    fill={isSel ? 'var(--color-ink)' : 'var(--color-sub)'} fontFamily="IBM Plex Sans, sans-serif"
                    style={{ paintOrder: 'stroke', stroke: 'var(--color-input-bg)', strokeWidth: 3.5 }}>
                    {truncate(n.value, 18)}
                  </text>
                  <text y={meta.r + 28} textAnchor="middle" fontSize="8.5" fill="var(--color-faint)"
                    fontFamily="JetBrains Mono, monospace" style={{ paintOrder: 'stroke', stroke: 'var(--color-input-bg)', strokeWidth: 3 }}>
                    {meta.label.toUpperCase()}
                  </text>
                </g>
              </g>
            );
          })}
        </g>
      </svg>

      {/* controles flutuantes */}
      <div className="absolute right-3 top-3 flex flex-col gap-1.5">
        <button className="btn btn-xs px-2.5!" onClick={() => setView(v => ({ ...v, k: clamp(v.k * 1.25, 0.3, 3) }))} title="Aproximar"><Icon name="plus" size={13} /></button>
        <button className="btn btn-xs px-2.5!" onClick={() => setView(v => ({ ...v, k: clamp(v.k * 0.8, 0.3, 3) }))} title="Afastar"><Icon name="chevronDown" size={13} /></button>
        <button className="btn btn-xs" onClick={fit} title="Enquadrar"><Icon name="crosshair" size={13} /></button>
        <button className="btn btn-xs" onClick={relayout} title="Reorganizar"><Icon name="refresh" size={13} /></button>
      </div>

      {/* legenda */}
      <div className="absolute bottom-3 left-3 flex flex-wrap items-center gap-x-3 gap-y-1 rounded-lg border border-line bg-input-bg/85 px-3 py-2">
        {(Object.keys(NODE_META) as GraphNodeType[]).map(t => (
          <span key={t} className="flex items-center gap-1.5 font-mono text-[9.5px] uppercase tracking-wide text-faint">
            <span className="h-2 w-2 rounded-full" style={{ background: NODE_META[t].color }} />
            {NODE_META[t].label}
          </span>
        ))}
      </div>

      {nodes.length === 0 && (
        <div className="absolute inset-0 flex items-center justify-center">
          <div className="text-center">
            <div className="mx-auto mb-3 flex h-12 w-12 items-center justify-center rounded-xl border border-line bg-panel text-faint"><Icon name="network" size={22} /></div>
            <div className="font-display text-[13px] font-semibold text-sub">Comece uma investigação</div>
            <div className="mt-1 text-[11.5px] text-faint">Busque um IP, usuário, host ou IOC ao lado</div>
          </div>
        </div>
      )}
    </div>
  );
}
