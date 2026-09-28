import { useEffect } from 'react';
import type { CSSProperties, ReactNode } from 'react';
import type { Severity } from '../data/mock';
import { SEV_META } from '../data/mock';
import { useStore } from '../lib/store';
import type { Toast } from '../lib/store';
import { Icon } from './icons';

export { Icon };

// ── badges ───────────────────────────────────────────────────
export function SevBadge({ sev, sm = false }: { sev: Severity; sm?: boolean }) {
  const m = SEV_META[sev];
  return (
    <span className={`inline-flex items-center gap-1.5 rounded font-semibold ${sm ? 'px-1.5 py-0.5 text-[10px]' : 'px-2 py-[3px] text-[11px]'}`}
      style={{ color: m.color, background: m.color + '1c', border: `1px solid ${m.color}40` }}>
      <span className={sm ? 'hidden' : 'inline-block h-1.5 w-1.5 rounded-full'} style={{ background: m.color, boxShadow: `0 0 6px ${m.color}` }} />
      {m.label}
    </span>
  );
}

export function Pill({ label, color, sm = false }: { label: string; color: string; sm?: boolean }) {
  return (
    <span className={`inline-flex items-center gap-1.5 rounded font-medium ${sm ? 'px-1.5 py-0.5 text-[10px]' : 'px-2 py-[3px] text-[11px]'}`}
      style={{ color, background: color + '16', border: `1px solid ${color}3d` }}>
      {label}
    </span>
  );
}

// ── panel com header ─────────────────────────────────────────
export function Panel({ title, icon, right, children, className = '', delay = 0, pad = true, live = false }: {
  title: string; icon?: string; right?: ReactNode; children: ReactNode;
  className?: string; delay?: number; pad?: boolean; live?: boolean;
}) {
  return (
    <section className={`panel a-up flex flex-col min-h-0 ${className}`} style={{ animationDelay: `${delay}ms` } as CSSProperties}>
      <header className="panel-hd shrink-0">
        {icon && <span className="text-teal"><Icon name={icon} size={14} /></span>}
        <h3 className="font-display text-[11.5px] font-semibold uppercase tracking-[0.14em] text-ink/90">{title}</h3>
        {live && (
          <span className="flex items-center gap-1.5 text-[10px] font-mono text-teal">
            <span className="h-1.5 w-1.5 rounded-full bg-teal dot-live" />LIVE
          </span>
        )}
        <div className="ml-auto flex items-center gap-2">{right}</div>
      </header>
      <div className={`min-h-0 flex-1 ${pad ? 'p-4' : ''}`}>{children}</div>
    </section>
  );
}

// ── field de metadados ───────────────────────────────────────
export function Field({ label, children, mono = false }: { label: string; children: ReactNode; mono?: boolean }) {
  return (
    <div className="min-w-0">
      <div className="lbl mb-1">{label}</div>
      <div className={`text-[12.5px] text-ink/90 break-words ${mono ? 'font-mono text-[11.5px]' : ''}`}>{children}</div>
    </div>
  );
}

// ── avatar com iniciais ──────────────────────────────────────
const AV_COLORS = ['#2fd6a5', '#56c4ff', '#ffc53d', '#ff9142', '#5aa2ff', '#e879b9'];
export function Avatar({ name, size = 26 }: { name: string; size?: number }) {
  const safe = (name ?? '').trim() || '?';
  const initials = safe.split(/\s+/).map(p => p[0]).filter(Boolean).slice(0, 2).join('').toUpperCase() || '?';
  const color = AV_COLORS[((safe.charCodeAt(0) || 0) + safe.length) % AV_COLORS.length];
  return (
    <span className="inline-flex items-center justify-center rounded-full font-display font-semibold shrink-0"
      style={{ width: size, height: size, fontSize: size * 0.36, color, background: color + '1f', border: `1px solid ${color}55` }}>
      {initials}
    </span>
  );
}

// ── drawer lateral ───────────────────────────────────────────
export function Drawer({ open, onClose, title, sub, children, footer, width = 560 }: {
  open: boolean; onClose: () => void; title: ReactNode; sub?: ReactNode; children: ReactNode; footer?: ReactNode; width?: number;
}) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    if (open) window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, onClose]);
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50">
      <div className="absolute inset-0 bg-[#04070d]/72" onClick={onClose} />
      <aside className="a-drawer absolute right-0 top-0 bottom-0 flex flex-col border-l border-line2 bg-panel shadow-[-30px_0_60px_rgba(0,0,0,.25)]"
        style={{ width: `min(${width}px, 96vw)` }}>
        <header className="flex items-start gap-3 border-b border-line px-5 py-4 shrink-0">
          <div className="min-w-0 flex-1">
            <div className="font-display text-[15px] font-semibold text-ink leading-tight">{title}</div>
            {sub && <div className="mt-1 flex items-center gap-2 text-[11.5px] text-sub flex-wrap">{sub}</div>}
          </div>
          <button className="btn btn-ghost btn-xs" onClick={onClose} aria-label="Fechar"><Icon name="x" size={15} /></button>
        </header>
        <div className="flex-1 overflow-y-auto px-5 py-4">{children}</div>
        {footer && <footer className="border-t border-line px-5 py-3.5 shrink-0 bg-input-bg">{footer}</footer>}
      </aside>
    </div>
  );
}

// ── modal central ────────────────────────────────────────────
export function Modal({ open, onClose, title, children, footer, width = 480 }: {
  open: boolean; onClose: () => void; title: ReactNode; children: ReactNode; footer?: ReactNode; width?: number;
}) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    if (open) window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, onClose]);
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-[#04070d]/72" onClick={onClose} />
      <div className="a-pop relative panel shadow-[0_30px_80px_rgba(0,0,0,.55)]" style={{ width: `min(${width}px, 96vw)` }}>
        <header className="panel-hd">
          <h3 className="font-display text-[13px] font-semibold uppercase tracking-[0.12em] text-ink">{title}</h3>
          <button className="btn btn-ghost btn-xs ml-auto" onClick={onClose} aria-label="Fechar"><Icon name="x" size={15} /></button>
        </header>
        <div className="px-5 py-4">{children}</div>
        {footer && <footer className="flex justify-end gap-2 border-t border-line px-5 py-3.5">{footer}</footer>}
      </div>
    </div>
  );
}

// ── diálogo de confirmação (substitui window.confirm nativo) ─
export interface ConfirmState { title: string; msg: string; danger?: boolean; action: () => void }
export function ConfirmDialog({ state, onClose }: { state: ConfirmState | null; onClose: () => void }) {
  return (
    <Modal open={!!state} onClose={onClose} title={state?.title ?? ''} width={430}
      footer={<>
        <button className="btn btn-xs" onClick={onClose}>Cancelar</button>
        <button className={`btn btn-xs ${state?.danger ? 'btn-danger' : 'btn-primary'}`}
          onClick={() => { state?.action(); onClose(); }}>Confirmar</button>
      </>}>
      <p className="text-[12.5px] leading-relaxed text-sub">{state?.msg}</p>
    </Modal>
  );
}

// ── estado vazio ─────────────────────────────────────────────
export function EmptyState({ icon = 'search', title, sub }: { icon?: string; title: string; sub?: string }) {
  return (
    <div className="flex flex-col items-center justify-center py-12 text-center">
      <div className="mb-3 flex h-12 w-12 items-center justify-center rounded-lg border border-line bg-panel2 text-faint">
        <Icon name={icon} size={20} />
      </div>
      <div className="font-display text-[13px] font-semibold text-sub">{title}</div>
      {sub && <div className="mt-1 max-w-[280px] text-[12px] text-faint">{sub}</div>}
    </div>
  );
}

// ── toasts ───────────────────────────────────────────────────
function ToastItem({ t }: { t: Toast }) {
  const { dismiss } = useStore();
  useEffect(() => {
    const timer = setTimeout(() => dismiss(t.id), 4400);
    return () => clearTimeout(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [t.id]);
  const meta = {
    ok:   { color: '#2fd6a5', icon: 'check' },
    warn: { color: '#ffc53d', icon: 'alertTriangle' },
    err:  { color: '#ff4d5e', icon: 'x' },
    info: { color: '#56c4ff', icon: 'activity' },
  }[t.kind];
  return (
    <div className="a-toast pointer-events-auto flex items-center gap-3 rounded-lg border bg-panel/95 px-4 py-3 shadow-[0_16px_40px_rgba(0,0,0,.25)]"
      style={{ borderColor: meta.color + '55' }}>
      <span style={{ color: meta.color }}><Icon name={meta.icon} size={15} /></span>
      <span className="text-[12.5px] text-ink/95">{t.msg}</span>
      <button className="ml-2 text-faint hover:text-ink transition-colors" onClick={() => dismiss(t.id)} aria-label="Fechar aviso">
        <Icon name="x" size={13} />
      </button>
    </div>
  );
}

export function ToastHost() {
  const { s } = useStore();
  return (
    <div className="pointer-events-none fixed bottom-5 right-5 z-[70] flex flex-col gap-2">
      {s.toasts.map(t => <ToastItem key={t.id} t={t} />)}
    </div>
  );
}

// ── barra de progresso fina ──────────────────────────────────
export function Bar({ value, max = 1, color = '#2fd6a5' }: { value: number; max?: number; color?: string }) {
  return (
    <div className="h-[6px] w-full rounded-sm bg-input-bg border border-line/60 overflow-hidden">
      <div className="h-full rounded-sm transition-all duration-500" style={{ width: `${Math.min(100, (value / max) * 100)}%`, background: color }} />
    </div>
  );
}

// ── contagem regressiva de SLA ───────────────────────────────
export function SLAChip({ left, breached }: { left: number; breached: boolean }) {
  const abs = Math.abs(left);
  const hr = Math.floor(abs / 3_600_000);
  const mn = Math.floor((abs % 3_600_000) / 60_000);
  const txt = hr > 0 ? `${hr}h ${mn}min` : `${mn}min`;
  return (
    <span className={`inline-flex items-center gap-1.5 rounded px-2 py-[3px] font-mono text-[11px] font-medium ${breached ? 'dot-crit' : ''}`}
      style={breached
        ? { color: '#ff8a96', background: 'rgba(255,77,94,.12)', border: '1px solid rgba(255,77,94,.4)' }
        : left < 3_600_000
          ? { color: '#ffb37e', background: 'rgba(255,145,66,.1)', border: '1px solid rgba(255,145,66,.35)' }
          : { color: '#7ee2c0', background: 'rgba(47,214,165,.08)', border: '1px solid rgba(47,214,165,.3)' }}>
      <Icon name="clock" size={11} />
      {breached ? `estourado há ${txt}` : `${txt} restantes`}
    </span>
  );
}
