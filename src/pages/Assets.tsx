import { useEffect, useMemo, useState } from 'react';
import type { AssetType } from '../data/mock';
import { ASSET_TYPE_META } from '../data/mock';
import { can, useStore } from '../lib/store';
import { Bar, Drawer, EmptyState, Field, Icon, Modal, Pill, SevBadge } from '../components/ui';
import type { IconName } from '../components/icons';

function critColor(c: number) {
  return c >= 90 ? '#ff4d5e' : c >= 70 ? '#ff9142' : c >= 50 ? '#ffc53d' : '#5aa2ff';
}
const STATUS_META: Record<string, { label: string; color: string }> = {
  online: { label: 'Online', color: '#2fd6a5' },
  offline: { label: 'Offline', color: '#8fa3c8' },
  isolado: { label: 'ISOLADO', color: '#ff4d5e' },
};

export default function Assets() {
  const { s, scope, nav, setAssetStatus, toast } = useStore();
  const [q, setQ] = useState('');
  const [type, setType] = useState('all');
  const [critFilter, setCritFilter] = useState('all');
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [confirmIsolate, setConfirmIsolate] = useState(false);

  useEffect(() => {
    if (s.focus?.type === 'asset') { setSelectedId(s.focus.id); nav('assets', null); }
    if (s.focus?.type === 'assetname') {
      const a = s.assets.find(x => x.name === s.focus!.id);
      if (a) setSelectedId(a.id);
      nav('assets', null);
    }
  }, [s.focus, nav, s.assets]);

  const assets = useMemo(() => scope(s.assets), [s.assets, s.tenant]); // eslint-disable-line react-hooks/exhaustive-deps

  const filtered = assets.filter(a => {
    if (type !== 'all' && a.type !== type) return false;
    if (critFilter === 'crit' && a.crit < 90) return false;
    if (critFilter === 'alta' && (a.crit < 70 || a.crit >= 90)) return false;
    if (critFilter === 'media' && a.crit >= 70) return false;
    const query = q.trim().toLowerCase();
    if (query && ![a.name, a.ip, a.os, a.owner].some(f => f.toLowerCase().includes(query))) return false;
    return true;
  }).sort((a, b) => b.crit - a.crit);

  const sel = assets.find(a => a.id === selectedId) ?? null;
  const selVulns = sel ? scope(s.vulns).filter(v => v.asset === sel.name && !['resolvida', 'aceita'].includes(v.status)) : [];
  const selAlerts = sel ? scope(s.alerts).filter(a => a.host === sel.name && !['fechado', 'falso_positivo'].includes(a.status)) : [];
  const selIncs = sel ? scope(s.incidents).filter(i => i.asset === sel.name && !['resolvido', 'fechado'].includes(i.status)) : [];

  const canIsolate = can(s.role, 'assets.update') || can(s.role, 'response.execute');

  return (
    <div className="flex h-full flex-col">
      <div className="a-up shrink-0 border-b border-line bg-panel/40 px-5 py-3.5">
        <div className="flex flex-wrap items-center gap-2.5">
          <div className="relative min-w-[200px] flex-1 max-w-[380px]">
            <span className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-faint"><Icon name="search" size={14} /></span>
            <input className="input w-full pl-9" placeholder="Nome, IP, sistema, owner…" value={q} onChange={e => setQ(e.target.value)} />
          </div>
          <select className="select" value={type} onChange={e => setType(e.target.value)}>
            <option value="all">Todos os tipos</option>
            {(Object.keys(ASSET_TYPE_META) as AssetType[]).map(t => <option key={t} value={t}>{ASSET_TYPE_META[t].label}</option>)}
          </select>
          <select className="select" value={critFilter} onChange={e => setCritFilter(e.target.value)}>
            <option value="all">Toda criticidade</option>
            <option value="crit">Crítica (≥90)</option>
            <option value="alta">Alta (70–89)</option>
            <option value="media">Média (&lt;70)</option>
          </select>
          <span className="ml-auto font-mono text-[11px] text-faint">
            {assets.filter(a => a.status === 'isolado').length} isolados · {assets.filter(a => a.status === 'online').length} monitorados
          </span>
        </div>
      </div>

      <div className="min-h-0 flex-1 overflow-y-auto p-5">
        {filtered.length === 0 ? (
          <EmptyState icon="server" title="Nenhum ativo no filtro" sub="Ajuste tipo, criticidade ou busca." />
        ) : (
          <div className="grid grid-cols-1 gap-3.5 sm:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-4">
            {filtered.map((a, i) => {
              const vCount = scope(s.vulns).filter(v => v.asset === a.name && !['resolvida', 'aceita'].includes(v.status)).length;
              const aCount = scope(s.alerts).filter(x => x.host === a.name && !['fechado', 'falso_positivo'].includes(x.status)).length;
              return (
                <button key={a.id} onClick={() => setSelectedId(a.id)}
                  className={`panel a-up group p-4 text-left transition-all hover:border-line2 hover:translate-y-[-2px] ${a.status === 'isolado' ? 'border-crit/45' : ''}`}
                  style={{ animationDelay: `${Math.min(i, 10) * 45}ms` }}>
                  <div className="flex items-center gap-3">
                    <span className={`flex h-9 w-9 items-center justify-center rounded-lg border ${a.status === 'isolado' ? 'border-crit/50 bg-crit/10 text-crit' : 'border-line bg-panel2 text-cyan'}`}>
                      <Icon name={(ASSET_TYPE_META[a.type].icon as IconName) ?? 'server'} size={16} />
                    </span>
                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="truncate font-mono text-[12.5px] font-semibold text-ink">{a.name}</span>
                        {a.status === 'isolado' && <span className="dot-crit rounded-sm bg-crit/15 px-1.5 py-0.5 font-mono text-[8.5px] font-bold tracking-wider text-crit">ISOLADO</span>}
                      </div>
                      <div className="font-mono text-[10.5px] text-faint">{a.ip} · {ASSET_TYPE_META[a.type].label}</div>
                    </div>
                    <span className={`ml-auto h-2 w-2 shrink-0 rounded-full ${a.status === 'online' ? 'bg-teal dot-live' : a.status === 'isolado' ? 'bg-crit' : 'bg-faint/50'}`} />
                  </div>
                  <div className="mt-3.5 flex items-center gap-2.5">
                    <div className="flex-1"><Bar value={a.crit} max={100} color={critColor(a.crit)} /></div>
                    <span className="font-mono text-[10.5px] font-semibold" style={{ color: critColor(a.crit) }}>{a.crit}</span>
                  </div>
                  <div className="mt-3 flex items-center gap-3 font-mono text-[10px] text-faint">
                    <span className="flex items-center gap-1"><Icon name="bug" size={10} className={vCount ? 'text-crit' : ''} /> {vCount}</span>
                    <span className="flex items-center gap-1"><Icon name="bell" size={10} className={aCount ? 'text-med' : ''} /> {aCount}</span>
                    <span className="ml-auto truncate">{a.os}</span>
                  </div>
                </button>
              );
            })}
          </div>
        )}
      </div>

      {/* drawer do ativo */}
      <Drawer open={!!sel} onClose={() => setSelectedId(null)}
        title={sel ? <span className="flex items-center gap-2.5 font-mono text-cyan">{sel.name}</span> : ''}
        sub={sel ? (<><Pill label={ASSET_TYPE_META[sel.type].label} color="#56c4ff" sm />
          <Pill label={STATUS_META[sel.status].label} color={STATUS_META[sel.status].color} sm />
          <span className="font-mono text-faint">{sel.ip}</span></>) : undefined}
        footer={sel ? (
          <div className="flex items-center gap-2">
            {sel.status !== 'isolado' ? (
              <button className="btn btn-danger btn-xs" disabled={!canIsolate} onClick={() => setConfirmIsolate(true)}
                title={canIsolate ? undefined : 'requer assets.update ou response.execute'}>
                <Icon name="power" size={12} /> Isolar endpoint
              </button>
            ) : (
              <button className="btn btn-primary btn-xs" disabled={!canIsolate}
                onClick={() => { setAssetStatus(sel.name, 'online'); toast('ok', `${sel.name} liberado do isolamento`); }}>
                <Icon name="check" size={12} /> Liberar isolamento
              </button>
            )}
            {!canIsolate && <span className="flex items-center gap-1 text-[10px] text-faint"><Icon name="lock" size={10} /> requer permissão de resposta</span>}
            <button className="btn btn-xs ml-auto" onClick={() => nav('vulns')}>
              <Icon name="bug" size={12} /> Vulnerabilidades
            </button>
          </div>
        ) : undefined}>
        {sel && (
          <div className="flex flex-col gap-5">
            <div className="grid grid-cols-2 gap-x-4 gap-y-3.5 rounded-lg border border-line bg-panel p-4">
              <Field label="IP" mono>{sel.ip}</Field>
              <Field label="Sistema" mono>{sel.os}</Field>
              <Field label="Owner">{sel.owner}</Field>
              <Field label="Criticidade">
                <span className="font-mono font-bold" style={{ color: critColor(sel.crit) }}>{sel.crit}/100</span>
              </Field>
            </div>

            <div>
              <div className="lbl mb-2">Vulnerabilidades abertas · {selVulns.length}</div>
              {selVulns.length === 0 && <span className="text-[11.5px] text-faint">Nenhuma vulnerabilidade aberta.</span>}
              <div className="flex flex-col gap-1.5">
                {selVulns.map(v => (
                  <button key={v.id} className="flex items-center gap-2.5 rounded-md border border-line/70 bg-panel px-3 py-2 text-left hover:border-line2 transition-colors"
                    onClick={() => nav('vulns', { type: 'vuln', id: v.id })}>
                    <span className="font-mono text-[11px] font-medium text-cyan">{v.cve}</span>
                    <span className="truncate text-[11.5px] text-sub">{v.title}</span>
                    <span className="ml-auto font-mono text-[10.5px] text-faint">{v.cvss.toFixed(1)}</span>
                  </button>
                ))}
              </div>
            </div>

            <div>
              <div className="lbl mb-2">Alertas ativos · {selAlerts.length}</div>
              {selAlerts.length === 0 && <span className="text-[11.5px] text-faint">Sem alertas pendentes.</span>}
              <div className="flex flex-col gap-1.5">
                {selAlerts.map(a => (
                  <button key={a.id} className="flex items-center gap-2.5 rounded-md border border-line/70 bg-panel px-3 py-2 text-left hover:border-line2 transition-colors"
                    onClick={() => nav('alerts', { type: 'alert', id: a.id })}>
                    <SevBadge sev={a.severity} sm />
                    <span className="truncate text-[11.5px] text-ink/85">{a.title}</span>
                    <span className="ml-auto font-mono text-[10px] text-faint">{a.id}</span>
                  </button>
                ))}
              </div>
            </div>

            <div>
              <div className="lbl mb-2">Incidentes relacionados · {selIncs.length}</div>
              {selIncs.length === 0 && <span className="text-[11.5px] text-faint">Nenhum incidente ativo.</span>}
              <div className="flex flex-col gap-1.5">
                {selIncs.map(ic => (
                  <button key={ic.id} className="flex items-center gap-2.5 rounded-md border border-line/70 bg-panel px-3 py-2 text-left hover:border-line2 transition-colors"
                    onClick={() => nav('incidents', { type: 'incident', id: ic.id })}>
                    <SevBadge sev={ic.severity} sm />
                    <span className="truncate text-[11.5px] text-ink/85">{ic.title}</span>
                    <span className="ml-auto font-mono text-[10px] text-faint">{ic.id}</span>
                  </button>
                ))}
              </div>
            </div>
          </div>
        )}
      </Drawer>

      {/* confirmação de isolamento */}
      <Modal open={confirmIsolate} onClose={() => setConfirmIsolate(false)} title="Confirmar isolamento" width={430}
        footer={<>
          <button className="btn btn-xs" onClick={() => setConfirmIsolate(false)}>Cancelar</button>
          <button className="btn btn-danger btn-xs" onClick={() => {
            if (sel) { setAssetStatus(sel.name, 'isolado'); toast('warn', `${sel.name} isolado da rede — ação registrada em auditoria`); }
            setConfirmIsolate(false);
          }}>
            <Icon name="power" size={12} /> Isolar {sel?.name}
          </button>
        </>}>
        <p className="text-[12.5px] leading-relaxed text-sub">
          O ativo <span className="font-mono text-crit">{sel?.name}</span> será contido via EDR: tráfego de rede bloqueado
          exceto canal de gestão. A ação exige aprovação registrada e fica auditada.
        </p>
        <div className="mt-3 rounded-md border border-line bg-panel px-3 py-2 font-mono text-[10.5px] text-faint">
          solicitação → autorização → política → execução → validação → audit
        </div>
      </Modal>
    </div>
  );
}
