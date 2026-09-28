import { useEffect, useMemo, useState } from 'react';
import type { Severity, Vuln, VulnStatus } from '../data/mock';
import { SEV_META, SEV_ORDER, VULN_STATUS_META } from '../data/mock';
import { can, timeAgo, useStore } from '../lib/store';
import { Drawer, EmptyState, Field, Icon, Pill, SevBadge } from '../components/ui';

const VULN_FLOW: VulnStatus[] = ['aberta', 'confirmada', 'em_correcao', 'mitigada', 'resolvida'];

function riskScore(v: Vuln, crit: number) {
  return Math.round(v.cvss * (crit / 100) * 10) / 10;
}
function cvssColor(cvss: number) {
  return cvss >= 9 ? '#ff4d5e' : cvss >= 7 ? '#ff9142' : cvss >= 4 ? '#ffc53d' : '#5aa2ff';
}

export default function Vulnerabilities() {
  const { s, scope, setVuln, nav } = useStore();
  const [q, setQ] = useState('');
  const [sevs, setSevs] = useState<Severity[]>([]);
  const [status, setStatus] = useState('all');
  const [selectedId, setSelectedId] = useState<string | null>(null);

  useEffect(() => {
    if (s.focus?.type === 'vuln') { setSelectedId(s.focus.id); nav('vulns', null); }
  }, [s.focus, nav]);

  const vulns = useMemo(() => scope(s.vulns), [s.vulns, s.tenant]); // eslint-disable-line react-hooks/exhaustive-deps
  const assets = useMemo(() => scope(s.assets), [s.assets, s.tenant]); // eslint-disable-line react-hooks/exhaustive-deps

  const filtered = vulns.filter(v => {
    if (sevs.length && !sevs.includes(v.severity)) return false;
    if (status !== 'all' && v.status !== status) return false;
    const query = q.trim().toLowerCase();
    if (query && ![v.cve, v.title, v.asset, v.id].some(f => f.toLowerCase().includes(query))) return false;
    return true;
  }).sort((a, b) => b.cvss - a.cvss);

  const open = vulns.filter(v => !['resolvida', 'aceita'].includes(v.status));
  const sel = vulns.find(v => v.id === selectedId) ?? null;
  const selAsset = sel ? assets.find(a => a.name === sel.asset) : null;
  const canUpdate = can(s.role, 'vulns.update');
  const canAccept = s.role === 'Admin' || s.role === 'SOC Manager';

  const summary = [
    { label: 'Críticas abertas', value: open.filter(v => v.severity === 'critical').length, color: '#ff4d5e', icon: 'alertTriangle' },
    { label: 'Altas abertas', value: open.filter(v => v.severity === 'high').length, color: '#ff9142', icon: 'bug' },
    { label: 'Em correção', value: vulns.filter(v => v.status === 'em_correcao').length, color: '#ffc53d', icon: 'refresh' },
    { label: 'Resolvidas', value: vulns.filter(v => v.status === 'resolvida').length, color: '#2fd6a5', icon: 'check' },
    { label: 'Risco aceito', value: vulns.filter(v => v.status === 'aceita').length, color: '#8fa3c8', icon: 'flag' },
  ];

  return (
    <div className="flex h-full flex-col">
      {/* resumo */}
      <div className="a-up grid shrink-0 grid-cols-2 gap-3 px-5 pt-4 sm:grid-cols-5">
        {summary.map((it, i) => (
          <div key={it.label} className="panel a-up flex items-center gap-3 px-3.5 py-3" style={{ animationDelay: `${i * 50}ms` }}>
            <span style={{ color: it.color }}><Icon name={it.icon} size={16} /></span>
            <div>
              <div className="font-mono text-[19px] font-bold leading-none tabular-nums" style={{ color: it.color }}>{it.value}</div>
              <div className="lbl mt-1">{it.label}</div>
            </div>
          </div>
        ))}
      </div>

      {/* filtros */}
      <div className="shrink-0 px-5 py-3.5">
        <div className="flex flex-wrap items-center gap-2.5">
          <div className="relative min-w-[220px] flex-1 max-w-[400px]">
            <span className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-faint"><Icon name="search" size={14} /></span>
            <input className="input w-full pl-9" placeholder="CVE, título, ativo…" value={q} onChange={e => setQ(e.target.value)} />
          </div>
          {SEV_ORDER.filter(sv => sv !== 'info').map(sv => (
            <button key={sv} className={`chip ${sevs.includes(sv) ? 'on' : ''}`}
              style={sevs.includes(sv) ? { borderColor: SEV_META[sv].color + '66', color: SEV_META[sv].color } : undefined}
              onClick={() => setSevs(p => (p.includes(sv) ? p.filter(x => x !== sv) : [...p, sv]))}>
              {SEV_META[sv].label}
            </button>
          ))}
          <select className="select" value={status} onChange={e => setStatus(e.target.value)}>
            <option value="all">Todos os status</option>
            {(Object.keys(VULN_STATUS_META) as VulnStatus[]).map(st => <option key={st} value={st}>{VULN_STATUS_META[st].label}</option>)}
          </select>
          <span className="ml-auto font-mono text-[11px] text-faint">
            risco = CVSS × criticidade do ativo
          </span>
        </div>
      </div>

      {/* tabela */}
      <div className="min-h-0 flex-1 overflow-auto px-5 pb-5">
        {filtered.length === 0 ? (
          <EmptyState icon="bug" title="Nenhuma vulnerabilidade no filtro" sub="Ajuste severidade, status ou busca." />
        ) : (
          <table className="tbl">
            <thead>
              <tr>
                <th className="w-[140px]">CVE</th>
                <th>Descrição</th>
                <th className="w-[70px]">CVSS</th>
                <th className="w-[90px]">Sev</th>
                <th className="w-[150px]">Ativo</th>
                <th className="w-[120px]">Risco</th>
                <th className="w-[130px]">Status</th>
                <th className="w-[80px]">Idade</th>
                <th className="w-[110px]">Ação</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map(v => {
                const asset = assets.find(a => a.name === v.asset);
                const risk = riskScore(v, asset?.crit ?? 50);
                return (
                  <tr key={v.id} className="cursor-pointer" onClick={() => setSelectedId(v.id)}>
                    <td className="font-mono text-[11.5px] font-medium text-cyan">{v.cve}</td>
                    <td>
                      <div className="truncate text-[12.5px] text-ink/90">{v.title}</div>
                      <div className="truncate font-mono text-[10px] text-faint">{v.fix}</div>
                    </td>
                    <td>
                      <span className="inline-block rounded px-1.5 py-0.5 font-mono text-[11px] font-bold"
                        style={{ color: cvssColor(v.cvss), background: cvssColor(v.cvss) + '1a', border: `1px solid ${cvssColor(v.cvss)}44` }}>
                        {v.cvss.toFixed(1)}
                      </span>
                    </td>
                    <td><SevBadge sev={v.severity} sm /></td>
                    <td>
                      <span className="font-mono text-[11px] text-ink/80">{v.asset}</span>
                      <span className="block font-mono text-[9.5px] text-faint">criticidade {asset?.crit ?? '—'}</span>
                    </td>
                    <td>
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-[12px] font-semibold" style={{ color: cvssColor(risk) }}>{risk.toFixed(1)}</span>
                        <div className="h-[5px] w-14 overflow-hidden rounded-sm bg-input-bg">
                          <div className="h-full a-grow" style={{ width: `${(risk / 10) * 100}%`, background: cvssColor(risk) }} />
                        </div>
                      </div>
                    </td>
                    <td onClick={e => e.stopPropagation()}>
                      <select className="select py-1! text-[10.5px]" value={v.status} disabled={!canUpdate}
                        style={{ color: VULN_STATUS_META[v.status].color }}
                        onChange={e => setVuln(v.id, e.target.value as VulnStatus, `alterou status de ${v.cve} para ${VULN_STATUS_META[e.target.value as VulnStatus].label}`)}>
                        {(Object.keys(VULN_STATUS_META) as VulnStatus[]).map(st => <option key={st} value={st}>{VULN_STATUS_META[st].label}</option>)}
                      </select>
                    </td>
                    <td className="font-mono text-[10.5px] text-faint">{timeAgo(v.found)}</td>
                    <td onClick={e => e.stopPropagation()}>
                      {v.status === 'aberta' || v.status === 'confirmada' ? (
                        <button className="btn btn-xs" disabled={!canUpdate}
                          onClick={() => setVuln(v.id, 'em_correcao', `iniciou remediação de ${v.cve} em ${v.asset}`)}>
                          <Icon name="refresh" size={11} /> Corrigir
                        </button>
                      ) : v.status === 'em_correcao' ? (
                        <button className="btn btn-xs btn-primary" disabled={!canUpdate}
                          onClick={() => setVuln(v.id, 'resolvida', `validou correção de ${v.cve} — finding resolvido`)}>
                          <Icon name="check" size={11} /> Validar
                        </button>
                      ) : (
                        <Pill label={VULN_STATUS_META[v.status].label} color={VULN_STATUS_META[v.status].color} sm />
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>

      {/* drawer */}
      <Drawer open={!!sel} onClose={() => setSelectedId(null)}
        title={sel ? <span className="flex items-center gap-2.5"><span className="font-mono text-cyan">{sel.cve}</span>{sel.title}</span> : ''}
        sub={sel ? (<><SevBadge sev={sel.severity} sm /><Pill label={VULN_STATUS_META[sel.status].label} color={VULN_STATUS_META[sel.status].color} sm />
          <span className="font-mono text-[11px]" style={{ color: cvssColor(sel.cvss) }}>CVSS {sel.cvss.toFixed(1)}</span></>) : undefined}
        footer={sel ? (
          <div className="flex flex-wrap items-center gap-2">
            {VULN_FLOW.includes(sel.status) && sel.status !== 'resolvida' && (
              <button className="btn btn-primary btn-xs" disabled={!canUpdate}
                onClick={() => setVuln(sel.id, VULN_FLOW[VULN_FLOW.indexOf(sel.status) + 1] ?? 'resolvida',
                  `avançou ${sel.cve} para ${VULN_STATUS_META[VULN_FLOW[VULN_FLOW.indexOf(sel.status) + 1] ?? 'resolvida'].label}`)}>
                Avançar remediação <Icon name="chevronRight" size={12} />
              </button>
            )}
            {sel.status !== 'aceita' && sel.status !== 'resolvida' && (
              <button className="btn btn-xs" disabled={!canAccept}
                title={canAccept ? undefined : 'Somente Admin / SOC Manager'}
                onClick={() => setVuln(sel.id, 'aceita', `registrou aceite de risco para ${sel.cve} com justificativa`)}>
                <Icon name="flag" size={12} /> Aceitar risco
              </button>
            )}
            {!canAccept && sel.status !== 'aceita' && sel.status !== 'resolvida' && (
              <span className="flex items-center gap-1 text-[10px] text-faint"><Icon name="lock" size={10} /> aceite requer Admin/Manager</span>
            )}
          </div>
        ) : undefined}>
        {sel && (
          <div className="flex flex-col gap-5">
            <div className="grid grid-cols-2 gap-x-4 gap-y-3.5 rounded-lg border border-line bg-panel p-4">
              <Field label="Ativo afetado" mono>{sel.asset}</Field>
              <Field label="Criticidade do ativo">{selAsset?.crit ?? '—'} / 100</Field>
              <Field label="Risco calculado">
                <span className="font-mono text-[14px] font-bold" style={{ color: cvssColor(riskScore(sel, selAsset?.crit ?? 50)) }}>
                  {riskScore(sel, selAsset?.crit ?? 50).toFixed(1)}
                </span>
              </Field>
              <Field label="Detectada" mono>{new Date(sel.found).toLocaleString('pt-BR')}</Field>
            </div>

            <div>
              <div className="lbl mb-2">Plano de remediação</div>
              <p className="text-[12.5px] leading-relaxed text-sub">{sel.fix}</p>
            </div>

            <div>
              <div className="lbl mb-2.5">Pipeline: remediation → execution → validation</div>
              <div className="flex items-center gap-1.5 flex-wrap">
                {VULN_FLOW.map((st, i) => {
                  const cur = VULN_FLOW.indexOf(sel.status);
                  const state = sel.status === 'aceita' ? 'skip' : i < cur ? 'done' : i === cur ? 'now' : 'todo';
                  return (
                    <span key={st} className="flex items-center gap-1.5">
                      <span className={`flex items-center gap-1.5 rounded border px-2 py-1 font-mono text-[10px] ${
                        state === 'done' ? 'border-teal/50 text-teal' : state === 'now' ? 'border-med/60 text-med bg-med/10' : state === 'skip' ? 'border-line text-faint/50 line-through' : 'border-line text-faint'}`}>
                        {state === 'done' && <Icon name="check" size={9} strokeWidth={3} />}
                        {VULN_STATUS_META[st].label}
                      </span>
                      {i < VULN_FLOW.length - 1 && <Icon name="chevronRight" size={11} className="text-faint" />}
                    </span>
                  );
                })}
              </div>
            </div>

            {selAsset && (
              <button className="flex items-center gap-2.5 rounded-lg border border-line bg-panel px-3.5 py-2.5 text-left hover:border-line2 transition-colors"
                onClick={() => nav('assets', { type: 'assetname', id: sel.asset })}>
                <Icon name="server" size={14} className="text-cyan" />
                <span className="text-[12px] text-ink/90">Ver ativo <span className="font-mono text-cyan">{sel.asset}</span> — {selAsset.ip} · {selAsset.os}</span>
                <Icon name="arrowUpRight" size={12} className="ml-auto text-faint" />
              </button>
            )}
          </div>
        )}
      </Drawer>
    </div>
  );
}
