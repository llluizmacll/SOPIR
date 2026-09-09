import { useRef, useState } from 'react';

// ── helpers ──────────────────────────────────────────────────
function smooth(pts: [number, number][]): string {
  if (pts.length < 2) return '';
  let d = `M ${pts[0][0]},${pts[0][1]}`;
  for (let i = 0; i < pts.length - 1; i++) {
    const p0 = pts[Math.max(0, i - 1)], p1 = pts[i], p2 = pts[i + 1], p3 = pts[Math.min(pts.length - 1, i + 2)];
    const c1x = p1[0] + (p2[0] - p0[0]) / 6, c1y = p1[1] + (p2[1] - p0[1]) / 6;
    const c2x = p2[0] - (p3[0] - p1[0]) / 6, c2y = p2[1] - (p3[1] - p1[1]) / 6;
    d += ` C ${c1x.toFixed(1)},${c1y.toFixed(1)} ${c2x.toFixed(1)},${c2y.toFixed(1)} ${p2[0].toFixed(1)},${p2[1].toFixed(1)}`;
  }
  return d;
}

// ── AreaChart com hover ──────────────────────────────────────
export function AreaChart({ data, height = 170, color = '#2fd6a5', unit = 'ev' }: {
  data: number[]; height?: number; color?: string; unit?: string;
}) {
  const W = 640, H = 190, PX = 8, PT = 14, PB = 24;
  const [hover, setHover] = useState<number | null>(null);
  const ref = useRef<SVGSVGElement>(null);
  const max = Math.max(1, ...data);
  const pts: [number, number][] = data.map((v, i) => [
    PX + (i * (W - PX * 2)) / Math.max(1, data.length - 1),
    PT + (1 - v / max) * (H - PT - PB),
  ]);
  const line = smooth(pts);
  const area = `${line} L ${pts[pts.length - 1][0]},${H - PB} L ${pts[0][0]},${H - PB} Z`;
  const gid = 'ag' + color.replace('#', '');

  const onMove = (e: React.MouseEvent) => {
    const el = ref.current; if (!el) return;
    const r = el.getBoundingClientRect();
    const x = ((e.clientX - r.left) / r.width) * W;
    const idx = Math.round(((x - PX) / (W - PX * 2)) * (data.length - 1));
    setHover(Math.max(0, Math.min(data.length - 1, idx)));
  };

  return (
    <svg ref={ref} viewBox={`0 0 ${W} ${H}`} style={{ width: '100%', height }} preserveAspectRatio="none"
      onMouseMove={onMove} onMouseLeave={() => setHover(null)}>
      <defs>
        <linearGradient id={gid} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity="0.32" />
          <stop offset="100%" stopColor={color} stopOpacity="0.01" />
        </linearGradient>
      </defs>
      {[0.25, 0.5, 0.75].map(f => (
        <line key={f} x1={PX} x2={W - PX} y1={PT + f * (H - PT - PB)} y2={PT + f * (H - PT - PB)}
          stroke="#1c2b47" strokeWidth="1" strokeDasharray="3 5" />
      ))}
      <path d={area} fill={`url(#${gid})`} />
      <path d={line} fill="none" stroke={color} strokeWidth="2" vectorEffect="non-scaling-stroke" />
      {hover !== null && pts[hover] && (
        <g>
          <line x1={pts[hover][0]} x2={pts[hover][0]} y1={PT - 4} y2={H - PB} stroke="#3a5488" strokeWidth="1" vectorEffect="non-scaling-stroke" />
          <circle cx={pts[hover][0]} cy={pts[hover][1]} r="4" fill="#0d1626" stroke={color} strokeWidth="2" vectorEffect="non-scaling-stroke" />
          <g transform={`translate(${Math.min(W - 92, Math.max(4, pts[hover][0] - 44))}, ${Math.max(2, pts[hover][1] - 34)})`}>
            <rect width="88" height="24" rx="5" fill="#122036" stroke="#27395c" vectorEffect="non-scaling-stroke" />
            <text x="44" y="16" textAnchor="middle" fill="#e8eefb" fontSize="11" fontFamily="JetBrains Mono, monospace">
              {data[hover]} {unit}
            </text>
          </g>
        </g>
      )}
      {data.length === 24 && data.map((_, i) => (i % 3 === 0 ? (
        <text key={i} x={pts[i][0]} y={H - 8} textAnchor="middle" fill="#5b7099" fontSize="9.5" fontFamily="JetBrains Mono, monospace">
          -{23 - i}h
        </text>
      ) : null))}
    </svg>
  );
}

// ── Donut ────────────────────────────────────────────────────
export function Donut({ segments, size = 148, thick = 15, center, sub }: {
  segments: { value: number; color: string }[]; size?: number; thick?: number; center: string; sub: string;
}) {
  const r = (size - thick) / 2;
  const C = 2 * Math.PI * r;
  const total = Math.max(1, segments.reduce((s, x) => s + x.value, 0));
  let acc = 0;
  return (
    <div className="relative inline-block" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="#122036" strokeWidth={thick} />
        {segments.map((s, i) => {
          const frac = s.value / total;
          const dash = `${frac * C} ${C}`;
          const off = -acc * C;
          acc += frac;
          if (!s.value) return null;
          return (
            <circle key={i} cx={size / 2} cy={size / 2} r={r} fill="none" stroke={s.color}
              strokeWidth={thick} strokeDasharray={dash} strokeDashoffset={off} strokeLinecap="butt"
              style={{ transition: 'stroke-dasharray .6s cubic-bezier(.2,.7,.3,1)' }} />
          );
        })}
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="font-mono text-2xl font-bold leading-none" style={{ color: '#e8eefb' }}>{center}</span>
        <span className="lbl mt-1.5">{sub}</span>
      </div>
    </div>
  );
}

// ── Gauge (Security Score) ───────────────────────────────────
export function Gauge({ value, size = 200 }: { value: number; size?: number }) {
  const R = 80, C = 2 * Math.PI * R;
  const usable = (240 / 360) * C;
  const color = value >= 80 ? '#2fd6a5' : value >= 60 ? '#ffc53d' : '#ff4d5e';
  return (
    <div className="relative inline-block" style={{ width: size, height: size * 0.92 }}>
      <svg viewBox="0 0 200 184" style={{ width: size, height: size * 0.92 }}>
        <g transform="rotate(150 100 100)">
          <circle cx="100" cy="100" r={R} fill="none" stroke="#122036" strokeWidth="13"
            strokeDasharray={`${usable} ${C}`} strokeLinecap="round" />
          <circle cx="100" cy="100" r={R} fill="none" stroke={color} strokeWidth="13"
            strokeDasharray={`${(value / 100) * usable} ${C}`} strokeLinecap="round"
            style={{ transition: 'stroke-dasharray 1s cubic-bezier(.2,.7,.3,1)', filter: `drop-shadow(0 0 8px ${color}66)` }} />
        </g>
        {[0, 25, 50, 75, 100].map(t => {
          const ang = ((150 + (t / 100) * 240) * Math.PI) / 180;
          const x1 = 100 + 93 * Math.cos(ang), y1 = 100 + 93 * Math.sin(ang);
          const x2 = 100 + 98 * Math.cos(ang), y2 = 100 + 98 * Math.sin(ang);
          return <line key={t} x1={x1} y1={y1} x2={x2} y2={y2} stroke="#27395c" strokeWidth="2" />;
        })}
        <text x="100" y="98" textAnchor="middle" fill="#e8eefb" fontSize="46" fontWeight="700" fontFamily="JetBrains Mono, monospace">{value}</text>
        <text x="100" y="120" textAnchor="middle" fill="#5b7099" fontSize="11" letterSpacing="2" fontFamily="Chakra Petch, sans-serif">/ 100</text>
      </svg>
    </div>
  );
}

// ── Barras horizontais ───────────────────────────────────────
export function HBars({ items }: { items: { label: string; value: number; color: string }[] }) {
  const max = Math.max(1, ...items.map(i => i.value));
  return (
    <div className="flex flex-col gap-2.5">
      {items.map((it, i) => (
        <div key={it.label} className="a-up" style={{ animationDelay: `${i * 60}ms` }}>
          <div className="flex items-baseline justify-between mb-1">
            <span className="text-[12px] text-sub">{it.label}</span>
            <span className="font-mono text-[12px] font-semibold" style={{ color: it.color }}>{it.value}</span>
          </div>
          <div className="h-[7px] rounded-sm bg-[#0a1322] border border-line/60 overflow-hidden">
            <div className="h-full a-grow rounded-sm" style={{ width: `${(it.value / max) * 100}%`, background: it.color, animationDelay: `${i * 60 + 100}ms`, boxShadow: `0 0 10px ${it.color}44` }} />
          </div>
        </div>
      ))}
    </div>
  );
}

// ── Sparkline ────────────────────────────────────────────────
export function Spark({ data, color = '#56c4ff', w = 96, h = 30 }: { data: number[]; color?: string; w?: number; h?: number }) {
  const max = Math.max(1, ...data), min = Math.min(...data);
  const pts = data.map((v, i) => [
    (i * w) / (data.length - 1),
    3 + (1 - (v - min) / Math.max(1, max - min)) * (h - 6),
  ] as [number, number]);
  return (
    <svg width={w} height={h} viewBox={`0 0 ${w} ${h}`}>
      <path d={smooth(pts)} fill="none" stroke={color} strokeWidth="1.6" strokeLinecap="round" />
      <circle cx={pts[pts.length - 1][0]} cy={pts[pts.length - 1][1]} r="2.4" fill={color} />
    </svg>
  );
}

// ── Barra de SLA ─────────────────────────────────────────────
export function SLABar({ pct, breached }: { pct: number; breached: boolean }) {
  const color = breached ? '#ff4d5e' : pct < 0.25 ? '#ff9142' : pct < 0.5 ? '#ffc53d' : '#2fd6a5';
  return (
    <div className="h-[6px] rounded-sm bg-[#0a1322] border border-line/60 overflow-hidden">
      <div className="h-full rounded-sm transition-all duration-700" style={{ width: `${Math.max(2, pct * 100)}%`, background: color, boxShadow: `0 0 8px ${color}55` }} />
    </div>
  );
}
