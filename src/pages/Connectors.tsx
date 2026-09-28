import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { ConnectorConfig, ConnectorState, ConnectorType } from '../lib/api';
import { api as srv } from '../lib/api';
import { hasPerm } from '../data/perms';
import { permsFor, timeAgo, useStore } from '../lib/store';
import { EmptyState, Field, Icon, Modal, Pill } from '../components/ui';
import type { IconName } from '../components/icons';

// ── metadados visuais ────────────────────────────────────────
const TYPE_META: Record<string, { label: string; icon: IconName; color: string }> = {
  wazuh_indexer: { label: 'Wazuh Indexer', icon: 'database', color: '#56c4ff' },
  wazuh_manager: { label: 'Wazuh Manager', icon: 'server', color: '#5aa2ff' },
  fortisiem: { label: 'FortiSIEM', icon: 'shield', color: '#ff9142' },
  webhook: { label: 'Webhook (push)', icon: 'zap', color: '#2fd6a5' },
  splunk: { label: 'Splunk', icon: 'search', color: '#ff9142' },
  qradar: { label: 'QRadar', icon: 'radar', color: '#5aa2ff' },
  defender: { label: 'Microsoft Defender', icon: 'shieldCheck', color: '#56c4ff' },
  cef_syslog: { label: 'CEF genérico', icon: 'send', color: '#e879b9' },
};
const STATUS_META: Record<string, { label: string; color: string }> = {
  coletando: { label: 'Coletando', color: '#2fd6a5' },
  erro: { label: 'Erro', color: '#ff4d5e' },
  inicializando: { label: 'Iniciando', color: '#8fa3c8' },
  push: { label: 'Push', color: '#56c4ff' },
};

const FALLBACK_TYPES: ConnectorType[] = [
  { id: 'wazuh_indexer', label: 'Wazuh Indexer / OpenSearch', push: false, fields: [
    { key: 'url', label: 'URL do Indexer', placeholder: 'https://wazuh-indexer:9200', type: 'text' },
    { key: 'user', label: 'Usuário', placeholder: 'admin', type: 'text' },
    { key: 'pass', label: 'Senha', placeholder: '••••', type: 'password' },
    { key: 'indexPattern', label: 'Índice de alertas', placeholder: 'wazuh-alerts-4.x-*', type: 'text' },
    { key: 'skipSSLVerify', label: 'Ignorar verificação SSL (certificado autoassinado)', placeholder: '', type: 'checkbox' },
  ]},
  { id: 'wazuh_manager', label: 'Wazuh Manager API (4.8+)', push: false, fields: [
    { key: 'url', label: 'URL da API', placeholder: 'https://wazuh-manager:55000', type: 'text' },
    { key: 'user', label: 'Usuário da API', placeholder: 'api-user', type: 'text' },
    { key: 'pass', label: 'Senha', placeholder: '••••', type: 'password' },
    { key: 'skipSSLVerify', label: 'Ignorar verificação SSL (certificado autoassinado)', placeholder: '', type: 'checkbox' },
  ]},
  { id: 'fortisiem', label: 'FortiSIEM (Phoenix REST)', push: false, fields: [
    { key: 'url', label: 'URL do Supervisor', placeholder: 'https://fortisiem:443', type: 'text' },
    { key: 'user', label: 'Usuário', placeholder: 'admin', type: 'text' },
    { key: 'pass', label: 'Senha', placeholder: '••••', type: 'password' },
    { key: 'org', label: 'Organização (opcional)', placeholder: 'super', type: 'text' },
  ]},
  { id: 'webhook', label: 'Webhook / Push (ingest)', push: true, fields: [] },
  { id: 'splunk', label: 'Splunk (REST Search API)', push: false, fields: [
    { key: 'url', label: 'URL de gerência (porta 8089)', placeholder: 'https://splunk:8089', type: 'text' },
    { key: 'user', label: 'Usuário (deixe vazio se for usar token)', placeholder: 'admin', type: 'text' },
    { key: 'pass', label: 'Senha', placeholder: '••••', type: 'password' },
    { key: 'token', label: 'Token de autenticação (alternativa a usuário/senha)', placeholder: '', type: 'password' },
    { key: 'search', label: 'Busca SPL', placeholder: 'search index=notable', type: 'text' },
    { key: 'skipSSLVerify', label: 'Ignorar verificação SSL (certificado autoassinado)', placeholder: '', type: 'checkbox' },
  ]},
  { id: 'qradar', label: 'IBM QRadar (Offenses REST API)', push: false, fields: [
    { key: 'url', label: 'URL do console', placeholder: 'https://qradar.exemplo.com', type: 'text' },
    { key: 'token', label: 'Token SEC (Authorized Service)', placeholder: '', type: 'password' },
    { key: 'skipSSLVerify', label: 'Ignorar verificação SSL (certificado autoassinado)', placeholder: '', type: 'checkbox' },
  ]},
  { id: 'defender', label: 'Microsoft Defender (Graph Security API)', push: false, fields: [
    { key: 'tenantId', label: 'Tenant ID (Azure AD)', placeholder: '00000000-0000-0000-0000-000000000000', type: 'text' },
    { key: 'clientId', label: 'Client ID (App Registration)', placeholder: '', type: 'text' },
    { key: 'pass', label: 'Client Secret', placeholder: '••••', type: 'password' },
  ]},
  { id: 'cef_syslog', label: 'CEF genérico (syslog/push) — outras ferramentas', push: true, fields: [] },
];

function useLocal<T>(initial: T) {
  const [v, setV] = useState(initial);
  useEffect(() => setV(initial), [initial]);
  return [v, setV] as const;
}

export default function Connectors() {
  const { s, backend, toast } = useStore();
  const online = backend === 'online';
  const myPerms = permsFor(s.role);
  const canRead = hasPerm(myPerms, 'connectors.read');
  const canUpdate = hasPerm(myPerms, 'connectors.update');

  const [types, setTypes] = useState<ConnectorType[]>(FALLBACK_TYPES);
  const [configs, setConfigs] = useState<ConnectorConfig[]>([]);
  const [status, setStatus] = useState<ConnectorState[]>([]);
  const [tenants, setTenants] = useState(s.tenants);
  const [loading, setLoading] = useState(true);
  const [q, setQ] = useState('');
  const [tenantFilter, setTenantFilter] = useState('all');
  const [typeFilter, setTypeFilter] = useState('all');

  const [modal, setModal] = useState<ConnectorConfig | 'new' | null>(null);
  const [testing, setTesting] = useState<{ code: string; busy: boolean } | null>(null);
  const [confirm, setConfirm] = useState<{ title: string; msg: string; action: () => void } | null>(null);
  const [copied, setCopied] = useState<string | null>(null);

  const demoSeeded = useRef(false);

  const load = useCallback(async () => {
    if (online) {
      setLoading(true);
      const [ct, cf, st, tn] = await Promise.all([
        canUpdate ? srv.connectorTypes() : Promise.resolve(null),
        canRead ? srv.connectors() : Promise.resolve(null),
        srv.connectorStatus(),
        srv.tenants(),
      ]);
      if (ct) setTypes(ct);
      if (cf) setConfigs(cf);
      if (st) setStatus(st.connectors);
      if (tn) { setTenants(tn); }
      setLoading(false);
    } else if (!demoSeeded.current) {
      setLoading(true);
      setConfigs([]);
      setStatus([]);
      setTenants(s.tenants);
      demoSeeded.current = true;
      setLoading(false);
    }
  }, [online, canRead, canUpdate, s.tenants]);

  useEffect(() => { void load(); }, [load]);

  // mantém o status ao vivo enquanto a página está aberta
  useEffect(() => {
    if (!online) return;
    const t = setInterval(async () => {
      const st = await srv.connectorStatus();
      if (st) setStatus(st.connectors);
    }, 5000);
    return () => clearInterval(t);
  }, [online]);

  const stOf = useCallback((code: string) => status.find(x => x.key === code) ?? null, [status]);

  const filtered = useMemo(() => {
    const query = q.trim().toLowerCase();
    return configs.filter(c => {
      if (tenantFilter !== 'all' && c.tenant !== tenantFilter) return false;
      if (typeFilter !== 'all' && c.type !== typeFilter) return false;
      if (query && ![c.name, c.code, c.tenantName ?? '', c.tenant].some(f => f.toLowerCase().includes(query))) return false;
      return true;
    });
  }, [configs, q, tenantFilter, typeFilter]);

  const summary = useMemo(() => {
    const active = configs.filter(c => c.enabled && (stOf(c.code)?.status === 'coletando')).length;
    const errors = configs.filter(c => stOf(c.code)?.status === 'erro').length;
    const push = configs.filter(c => c.type === 'webhook').length;
    const totalCollected = status.reduce((acc, x) => acc + (x.collected || 0), 0);
    return { total: configs.length, active, errors, push, totalCollected };
  }, [configs, status, stOf]);

  if (!canRead && !canUpdate) {
    return <EmptyState icon="lock" title="Acesso restrito" sub="Seu perfil não possui permissões de integrações (connectors.read / connectors.update)." />;
  }

  const tenantName = (id: string) => tenants.find(t => t.id === id)?.name ?? id;

  const copyCurl = (c: ConnectorConfig) => {
    const key = 'troque-esta-chave';
    const txt = `curl -X POST http://<sopir-api>/api/v1/ingest \\\n  -H "Content-Type: application/json" \\\n  -H "X-Api-Key: ${key}" \\\n  -d '{ "source": "${TYPE_META[c.type]?.label ?? c.type}", "tenant": "${c.tenant}", "rule": "Evento", "severity": "high", "host": "ativo-01" }'`;
    navigator.clipboard?.writeText(txt).then(() => {
      setCopied(c.code);
      setTimeout(() => setCopied(null), 1600);
      toast('ok', 'Comando copiado para a área de transferência');
    }).catch(() => toast('err', 'Não foi possível copiar'));
  };

  const runTest = async (c: ConnectorConfig) => {
    setTesting({ code: c.code, busy: true });
    const res = await srv.testConnectorSaved(c.code);
    setTesting(null);
    if (res?.ok) toast('ok', `${c.name}: ${res.message}`);
    else toast('err', `${c.name}: ${res?.message ?? 'falha no teste'}`);
  };

  const toggleEnabled = async (c: ConnectorConfig) => {
    const enabled = !c.enabled;
    if (online) {
      const res = await srv.updateConnector(c.code, { enabled });
      if (!res?.ok) { toast('err', 'Falha ao atualizar.'); return; }
    } else {
      setConfigs(p => p.map(x => x.code === c.code ? { ...x, enabled } : x));
    }
    toast('ok', `${c.name} ${enabled ? 'ativado' : 'desativado'}`);
    void load();
  };

  const removeConnector = (c: ConnectorConfig) => setConfirm({
    title: 'Remover connector', msg: `Remover "${c.name}" [${c.code}]? A coleta para este cliente será interrompida.`,
    action: async () => {
      if (online) await srv.deleteConnector(c.code);
      else setConfigs(p => p.filter(x => x.code !== c.code));
      toast('ok', 'Connector removido');
      void load();
    },
  });

  return (
    <div className="flex h-full flex-col">
      {/* cabeçalho + resumo */}
      <div className="a-up shrink-0 border-b border-line bg-panel/40 px-5 py-3.5">
        <div className="flex flex-wrap items-center gap-3">
          <div className="flex items-center gap-4">
            <Stat label="Connectors" value={summary.total} color="var(--color-ink)" icon="layers" />
            <Stat label="Coletando" value={summary.active} color="#2fd6a5" icon="activity" pulse={summary.active > 0} />
            <Stat label="Em erro" value={summary.errors} color={summary.errors ? '#ff4d5e' : '#8fa3c8'} icon="alertTriangle" />
            <Stat label="Push" value={summary.push} color="#56c4ff" icon="zap" />
            <Stat label="Eventos coletados" value={summary.totalCollected.toLocaleString('pt-BR')} color="#ffc53d" icon="database" />
          </div>
          <div className="ml-auto flex items-center gap-2">
            <select className="select py-1.5! text-[11.5px]" value={tenantFilter} onChange={e => setTenantFilter(e.target.value)}>
              <option value="all">Todos os clientes</option>
              {tenants.map(t => <option key={t.id} value={t.id}>{t.name}</option>)}
            </select>
            <select className="select py-1.5! text-[11.5px]" value={typeFilter} onChange={e => setTypeFilter(e.target.value)}>
              <option value="all">Todos os tipos</option>
              {types.map(t => <option key={t.id} value={t.id}>{t.label}</option>)}
            </select>
            <div className="relative w-[180px]">
              <span className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-faint"><Icon name="search" size={13} /></span>
              <input className="input w-full pl-8 py-1.5! text-[11.5px]" placeholder="Buscar…" value={q} onChange={e => setQ(e.target.value)} />
            </div>
            {canUpdate && (
              <button className="btn btn-primary btn-xs" onClick={() => setModal('new')}><Icon name="plus" size={12} /> Novo connector</button>
            )}
          </div>
        </div>
      </div>

      {/* lista */}
      <div className="min-h-0 flex-1 overflow-y-auto p-5">
        {loading ? (
          <div className="flex h-full items-center justify-center text-[12px] text-faint">carregando…</div>
        ) : filtered.length === 0 ? (
          <EmptyState icon="layers" title="Nenhum connector"
            sub={configs.length === 0
              ? 'Conecte o SIEM de um cliente para começar a receber eventos.'
              : 'Nenhum connector corresponde aos filtros.'} />
        ) : (
          <div className="grid grid-cols-1 gap-3.5 xl:grid-cols-2">
            {filtered.map((c, i) => {
              const st = stOf(c.code);
              const meta = TYPE_META[c.type] ?? { label: c.type, icon: 'layers' as IconName, color: '#8fa3c8' };
              const sMeta = !c.enabled ? { label: 'Desativado', color: '#8fa3c8' }
                : c.type === 'webhook' ? STATUS_META.push
                : STATUS_META[st?.status ?? 'inicializando'] ?? STATUS_META.inicializando;
              return (
                <div key={c.code} className={`panel a-up p-4 transition-all hover:border-line2 ${!c.enabled ? 'opacity-55' : ''}`} style={{ animationDelay: `${Math.min(i, 8) * 45}ms` }}>
                  <div className="flex items-start gap-3">
                    <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg border" style={{ borderColor: meta.color + '55', background: meta.color + '12', color: meta.color }}>
                      <Icon name={meta.icon} size={17} />
                    </span>
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="truncate text-[13.5px] font-semibold text-ink">{c.name}</span>
                        <span className="font-mono text-[10px] text-faint">{c.code}</span>
                      </div>
                      <div className="mt-1 flex items-center gap-2 flex-wrap">
                        <Pill label={meta.label} color={meta.color} sm />
                        <span className="flex items-center gap-1 rounded border border-cyan/35 bg-cyan/10 px-1.5 py-0.5 text-[10px] text-cyan">
                          <Icon name="globe" size={10} /> {c.tenantName ?? tenantName(c.tenant)}
                        </span>
                        <span className="inline-flex items-center gap-1.5 rounded px-1.5 py-0.5 text-[10px] font-medium" style={{ color: sMeta.color, background: sMeta.color + '16', border: `1px solid ${sMeta.color}40` }}>
                          <span className={`h-1.5 w-1.5 rounded-full ${c.enabled && st?.status === 'coletando' ? 'dot-live' : ''}`} style={{ background: sMeta.color }} />
                          {sMeta.label}
                        </span>
                      </div>
                    </div>
                  </div>

                  {/* métricas / erro */}
                  <div className="mt-3 grid grid-cols-3 gap-2 border-t border-line pt-3">
                    <div>
                      <div className="lbl">Eventos</div>
                      <div className="mt-0.5 font-mono text-[14px] font-semibold text-ink tabular-nums">{(st?.collected ?? 0).toLocaleString('pt-BR')}</div>
                    </div>
                    <div>
                      <div className="lbl">{c.type === 'webhook' ? 'Modo' : 'Intervalo'}</div>
                      <div className="mt-0.5 font-mono text-[12px] text-sub">{c.type === 'webhook' ? 'push' : `${c.pollSeconds}s`}</div>
                    </div>
                    <div>
                      <div className="lbl">Última coleta</div>
                      <div className="mt-0.5 font-mono text-[12px] text-sub">{st?.lastOk ? timeAgo(st.lastOk) : (c.type === 'webhook' ? '—' : 'nunca')}</div>
                    </div>
                  </div>
                  {st?.status === 'erro' && st.lastError && (
                    <div className="mt-2.5 flex items-start gap-2 rounded-md border border-crit/40 bg-crit/10 px-3 py-2 text-[11px] leading-snug text-crit">
                      <Icon name="alertTriangle" size={13} className="mt-0.5 shrink-0" /> {st.lastError}
                    </div>
                  )}

                  {/* webhook: instruções de push */}
                  {c.type === 'webhook' && (
                    <div className="mt-2.5 rounded-md border border-line bg-input-bg px-3 py-2.5">
                      <div className="flex items-center justify-between">
                        <span className="font-mono text-[10px] text-faint">POST /api/v1/ingest · tenant <span className="text-cyan">{c.tenant}</span></span>
                        <button className="btn btn-ghost btn-xs" onClick={() => copyCurl(c)}>
                          <Icon name={copied === c.code ? 'check' : 'copy'} size={12} /> {copied === c.code ? 'Copiado' : 'Copiar curl'}
                        </button>
                      </div>
                    </div>
                  )}

                  {/* ações */}
                  <div className="mt-3 flex items-center gap-1.5">
                    {c.type !== 'webhook' && (
                      <button className="btn btn-xs" onClick={() => void runTest(c)} disabled={testing?.code === c.code && testing.busy}>
                        <Icon name="refresh" size={12} /> {testing?.code === c.code && testing.busy ? 'Testando…' : 'Testar'}
                      </button>
                    )}
                    {canUpdate && (
                      <>
                        <button className="btn btn-ghost btn-xs" title="Editar" onClick={() => setModal(c)}><Icon name="edit" size={13} /></button>
                        <button className="btn btn-ghost btn-xs" title={c.enabled ? 'Desativar' : 'Ativar'} onClick={() => void toggleEnabled(c)}>
                          <Icon name="power" size={13} className={c.enabled ? '' : 'text-teal'} />
                        </button>
                        <button className="btn btn-ghost btn-xs hover:!text-crit" title="Remover" onClick={() => removeConnector(c)}><Icon name="trash" size={13} /></button>
                      </>
                    )}
                    <span className="ml-auto font-mono text-[9.5px] text-faint">→ alimenta {tenantName(c.tenant)}</span>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* modal criar/editar */}
      <ConnectorModal state={modal} onClose={() => setModal(null)} types={types} tenants={tenants} online={online}
        onSaved={() => { setModal(null); toast('ok', 'Connector salvo'); void load(); }} setLocal={setConfigs} />

      <Modal open={!!confirm} onClose={() => setConfirm(null)} title={confirm?.title ?? ''} width={430}
        footer={<>
          <button className="btn btn-xs" onClick={() => setConfirm(null)}>Cancelar</button>
          <button className="btn btn-danger btn-xs" onClick={() => { void confirm?.action(); setConfirm(null); }}>Confirmar</button>
        </>}>
        <p className="text-[12.5px] leading-relaxed text-sub">{confirm?.msg}</p>
      </Modal>
    </div>
  );
}

function Stat({ label, value, color, icon, pulse = false }: { label: string; value: number | string; color: string; icon: IconName; pulse?: boolean }) {
  return (
    <div className="flex items-center gap-2.5">
      <span className={`flex h-8 w-8 items-center justify-center rounded-lg border ${pulse ? 'dot-live' : ''}`} style={{ borderColor: color + '40', background: color + '10', color }}>
        <Icon name={icon} size={14} />
      </span>
      <div>
        <div className="font-mono text-[16px] font-bold leading-none tabular-nums" style={{ color }}>{value}</div>
        <div className="mt-0.5 text-[9.5px] uppercase tracking-wide text-faint">{label}</div>
      </div>
    </div>
  );
}

function ConnectorModal({ state, onClose, types, tenants, online, onSaved, setLocal }: {
  state: ConnectorConfig | 'new' | null; onClose: () => void;
  types: ConnectorType[]; tenants: { id: string; name: string; short: string }[];
  online: boolean; onSaved: () => void; setLocal: React.Dispatch<React.SetStateAction<ConnectorConfig[]>>;
}) {
  const editing = state !== null && state !== 'new' ? state : null;
  const [name, setName] = useLocal(editing?.name ?? '');
  const [type, setType] = useLocal(editing?.type ?? 'wazuh_indexer');
  const [tenant, setTenant] = useLocal(editing?.tenant ?? (tenants[0]?.id ?? ''));
  const [pollSeconds, setPollSeconds] = useLocal(String(editing?.pollSeconds ?? 20));
  const [settings, setSettings] = useState<Record<string, string>>(() => {
    const s: Record<string, string> = {};
    if (editing) for (const [k, v] of Object.entries(editing.settings ?? {})) s[k] = String(v ?? '');
    return s;
  });
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);
  const [test, setTest] = useState<{ ok: boolean; message: string } | null>(null);
  const [testBusy, setTestBusy] = useState(false);

  useEffect(() => { if (state !== null) { setErr(''); setTest(null); } }, [state]);

  const typeMeta = types.find(t => t.id === type) ?? types[0];
  const isPush = Boolean(typeMeta?.push);

  const setField = (key: string, val: string | boolean) => {
    setSettings(p => ({ ...p, [key]: typeof val === 'boolean' ? (val ? 'true' : 'false') : val }));
    setTest(null);
  };

  const doTest = async () => {
    setTestBusy(true); setTest(null);
    const res = await srv.testConnector({ type, settings });
    setTestBusy(false);
    setTest(res ?? { ok: false, message: 'Falha ao testar.' });
  };

  const save = async () => {
    setErr('');
    if (!name.trim()) { setErr('Informe um nome para o connector.'); return; }
    if (!tenant) { setErr('Selecione o cliente (tenant) de destino.'); return; }
    if (!isPush && !settings.url) { setErr('Informe a URL da fonte.'); return; }
    setBusy(true);
    const body = { name: name.trim(), type, tenant, settings, enabled: true, pollSeconds: Number(pollSeconds) || 20 };
    if (online) {
      const res = editing ? await srv.updateConnector(editing.code, body) : await srv.createConnector(body);
      if (!res?.ok) { setErr(res?.error ?? 'Falha ao salvar.'); setBusy(false); return; }
    } else if (!editing) {
      const code = 'CON-DEMO-' + Math.floor(Math.random() * 900 + 100);
      setLocal(p => [...p, { code, name: body.name, type, tenant, tenantName: null, settings, enabled: true, pollSeconds: body.pollSeconds, push: isPush }]);
    }
    setBusy(false);
    onSaved();
  };

  return (
    <Modal open={state !== null} onClose={onClose} title={editing ? 'Editar connector' : 'Novo connector'} width={520}
      footer={<>
        <button className="btn btn-xs" onClick={onClose}>Cancelar</button>
        <button className="btn btn-primary btn-xs" onClick={() => void save()} disabled={busy}>
          {busy ? 'Salvando…' : <><Icon name="check" size={12} /> Salvar connector</>}
        </button>
      </>}>
      <div className="flex flex-col gap-3.5">
        <Field label="Nome da integração">
          <input className="input w-full" value={name} onChange={e => setName(e.target.value)} placeholder="Ex.: Wazuh — Cliente X" autoFocus />
        </Field>
        <div className="grid grid-cols-2 gap-3">
          <Field label="Tipo de fonte">
            <select className="select w-full" value={type} disabled={!!editing} onChange={e => { setType(e.target.value); setSettings({}); setTest(null); }}>
              {types.map(t => <option key={t.id} value={t.id}>{t.label}</option>)}
            </select>
          </Field>
          <Field label="Cliente (tenant) de destino">
            <select className="select w-full" value={tenant} onChange={e => setTenant(e.target.value)}>
              {tenants.map(t => <option key={t.id} value={t.id}>{t.name}</option>)}
            </select>
          </Field>
        </div>

        {typeMeta && typeMeta.fields.length > 0 && (
          <div className="grid grid-cols-2 gap-3">
            {typeMeta.fields.map(f => (
              <div key={f.key} className={f.key === 'url' ? 'col-span-2' : ''}>
                {f.type === 'checkbox' ? (
                  <label className="flex items-center gap-2 py-2 text-[12px] text-sub cursor-pointer">
                    <input type="checkbox" className="checkbox" checked={settings[f.key] === 'true'} onChange={e => setField(f.key, String(e.target.checked))} />
                    <span>{f.label}</span>
                  </label>
                ) : (
                  <Field label={f.label}>
                    <input className="input w-full font-mono text-[11.5px]" type={f.type === 'password' ? 'password' : 'text'}
                      value={settings[f.key] ?? ''} onChange={e => setField(f.key, e.target.value)} placeholder={f.placeholder}
                      autoComplete="new-password" />
                  </Field>
                )}
              </div>
            ))}
          </div>
        )}

        {!isPush && (
          <Field label="Intervalo de coleta (segundos)">
            <input className="input w-24 font-mono" type="number" min={5} value={pollSeconds} onChange={e => setPollSeconds(e.target.value)} />
          </Field>
        )}

        {isPush && (
          <div className="rounded-md border border-line bg-panel px-3 py-2.5 text-[11.5px] leading-relaxed text-sub">
            <span className="text-cyan font-medium">Push:</span> a fonte envia eventos para <span className="font-mono text-teal">POST /api/v1/ingest</span> com o header
            <span className="font-mono text-teal"> X-Api-Key</span>. Após salvar, copie o comando curl na lista.
          </div>
        )}

        <div className="flex items-center gap-2">
          <button className="btn btn-xs" onClick={() => void doTest()} disabled={testBusy || isPush}>
            <Icon name="refresh" size={12} /> {testBusy ? 'Testando…' : 'Testar conexão'}
          </button>
          {test && (
            <span className={`flex items-center gap-1.5 text-[11.5px] ${test.ok ? 'text-teal' : 'text-crit'}`}>
              <Icon name={test.ok ? 'check' : 'x'} size={13} /> {test.message}
            </span>
          )}
        </div>

        {err && <div className="flex items-center gap-2 rounded-md border border-crit/40 bg-crit/10 px-3 py-2 text-[11.5px] text-crit"><Icon name="alertTriangle" size={13} /> {err}</div>}
        <div className="rounded-md border border-line bg-panel px-3 py-2 font-mono text-[10px] leading-relaxed text-faint">
          Os eventos coletados são <span className="text-teal">normalizados</span> e gravados isolados no tenant selecionado. Senhas nunca retornam na API.
        </div>
      </div>
    </Modal>
  );
}
