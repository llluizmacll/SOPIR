import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import type {
  Alert, AlertStatus, Asset, AssetStatus, AuditEntry, AuditKind, Case, CaseStage, Ev,
  Incident, IncStatus, Playbook, PlayRun, Priority, Severity, Tenant, Vuln, VulnStatus,
} from '../data/mock';
import {
  ANALYSTS, CASE_SLA_MIN_DEMO, CASE_TEMPLATES_DEMO, DEMO_USERS, SEED_AUDIT, SEED_CORRELATIONS,
  SEED_PLAYBOOKS, SLA_HOURS, SLA_POLICY_DEMO, TENANTS, normalizeCase, sevToPriority, makeEvent,
} from '../data/mock';
import { api as srv, setToken, setUnauthorizedHandler } from './api';
import type { AuthUser, CorrPolicy, SavedInvestigation, SessionInfo } from './api';

export interface LoginOutcome {
  ok: boolean;
  error?: string;
  /** 'verify' = pedir código MFA · 'enroll' = matrícula MFA obrigatória */
  mfa?: 'verify' | 'enroll';
  mfaToken?: string;
  username?: string;
}
import type { GNode, GraphData, GraphNodeType } from './graph';
import { expandLocal } from './graph';

export type Route =
  | 'dashboard' | 'explorer' | 'ingestion' | 'alerts' | 'incidents' | 'cases'
  | 'playbooks' | 'vulns' | 'assets' | 'correlation' | 'investigation'
  | 'connectors' | 'sla' | 'admin' | 'reports' | 'audit' | 'portal';

export type Role = 'Admin' | 'SOC Manager' | 'SOC Analyst' | 'Security Engineer' | 'Customer';

// Registro mutável: perfis customizados (vindos da API) são registrados aqui
// no login, e o RBAC do frontend passa a respeitá-los como os embutidos.
const ROLE_PERMS: Record<string, string[]> = {
  Admin: ['*'],
  'SOC Manager': ['alerts.*', 'incidents.*', 'cases.*', 'assets.*', 'vulns.read', 'investigations.read', 'investigations.update', 'response.execute', 'response.approve', 'reports.export', 'audit.read', 'portal.read'],
  'SOC Analyst': ['alerts.read', 'alerts.update', 'incidents.read', 'incidents.update', 'cases.read', 'cases.update', 'assets.read', 'investigations.read', 'investigations.update', 'portal.read'],
  'Security Engineer': ['vulns.*', 'remediation.execute', 'assets.read', 'assets.update', 'investigations.read'],
  Customer: ['portal.read'],
};
const ROLE_USER: Record<string, string> = {
  Admin: 'Luiz Almeida',
  'SOC Manager': 'Ana Ribeiro',
  'SOC Analyst': 'Carlos Mendes',
  'Security Engineer': 'Marina Sousa',
  Customer: 'Portal do Cliente',
};
export function can(role: string, perm: string): boolean {
  return (ROLE_PERMS[role] ?? []).some(p => p === '*' || p === perm || (p.endsWith('.*') && perm.startsWith(p.slice(0, -1))));
}
/** Permissões de um papel (embutido ou customizado registrado). */
export function permsFor(role: string): string[] {
  return ROLE_PERMS[role] ?? [];
}
/** Registra/atualiza as permissões de um papel customizado vindo da API. */
export function registerRolePerms(role: string, perms: string[]) {
  ROLE_PERMS[role] = perms;
}

export interface Toast { id: number; kind: 'ok' | 'warn' | 'err' | 'info'; msg: string }
export interface Focus { type: string; id: string }

export interface AppState {
  route: Route;
  tenant: string;
  env: string;
  environments: { id: string; tenant: string; name: string; kind: string }[];
  role: string;
  user: AuthUser | null;
  tenants: Tenant[];
  events: Ev[];
  alerts: Alert[];
  incidents: Incident[];
  cases: Case[];
  vulns: Vuln[];
  assets: Asset[];
  playbooks: Playbook[];
  runs: PlayRun[];
  audit: AuditEntry[];
  correlations: CorrPolicy[];
  toasts: Toast[];
  focus: Focus | null;
  explorerQuery: string;
  paused: boolean;
  backend: 'checking' | 'online' | 'demo';
  eps: Record<string, number> | null;
  connectors: { name: string; configured: boolean; status: string; lastError: string | null; collected: number; mode: string | null }[];
  // Investigation Graph
  graph: GraphData;
  graphSel: string | null;
  graphRoot: { type: GraphNodeType; value: string } | null;
  investigations: SavedInvestigation[];
}

const DEMO_ENVS: AppState['environments'] = [
  { id: 'ENV-1', tenant: 'vetra', name: 'Produção', kind: 'producao' },
  { id: 'ENV-2', tenant: 'vetra', name: 'Laboratório', kind: 'laboratorio' },
  { id: 'ENV-3', tenant: 'atlantico', name: 'Produção', kind: 'producao' },
  { id: 'ENV-4', tenant: 'medcore', name: 'Produção', kind: 'producao' },
  { id: 'ENV-5', tenant: 'medcore', name: 'DR / Contingência', kind: 'dr' },
];

const initialState: AppState = {
  route: 'dashboard',
  tenant: 'vetra',
  env: 'all',
  environments: [...DEMO_ENVS],
  role: 'Admin',
  user: null,
  tenants: [...TENANTS],
  events: [],
  alerts: [],
  incidents: [],
  cases: [],
  vulns: [],
  assets: [],
  playbooks: SEED_PLAYBOOKS,
  runs: [],
  audit: SEED_AUDIT,
  correlations: SEED_CORRELATIONS,
  toasts: [],
  focus: null,
  explorerQuery: '',
  paused: false,
  backend: 'checking',
  eps: null,
  connectors: [],
  graph: { nodes: [], edges: [] },
  graphSel: null,
  graphRoot: null,
  investigations: [],
};

// ── formatadores ─────────────────────────────────────────────
export function timeAgo(ts: number): string {
  const s = Math.max(0, Math.floor((Date.now() - ts) / 1000));
  if (s < 8) return 'agora';
  if (s < 60) return `há ${s}s`;
  const mn = Math.floor(s / 60);
  if (mn < 60) return `há ${mn}min`;
  const hr = Math.floor(mn / 60);
  if (hr < 24) return `há ${hr}h${mn % 60 ? ` ${mn % 60}min` : ''}`;
  const dd = Math.floor(hr / 24);
  return `há ${dd}d`;
}
const MESES = ['jan', 'fev', 'mar', 'abr', 'mai', 'jun', 'jul', 'ago', 'set', 'out', 'nov', 'dez'];
export function fmtDT(ts: number): string {
  const t = new Date(ts);
  return `${String(t.getDate()).padStart(2, '0')} ${MESES[t.getMonth()]} · ${String(t.getHours()).padStart(2, '0')}:${String(t.getMinutes()).padStart(2, '0')}`;
}
export function fmtClock(ts: number): string {
  const t = new Date(ts);
  return `${String(t.getHours()).padStart(2, '0')}:${String(t.getMinutes()).padStart(2, '0')}:${String(t.getSeconds()).padStart(2, '0')}`;
}
export function fmtDur(ms: number): string {
  const abs = Math.abs(ms);
  const hr = Math.floor(abs / 3_600_000);
  const mn = Math.floor((abs % 3_600_000) / 60_000);
  if (hr >= 24) return `${Math.floor(hr / 24)}d ${hr % 24}h`;
  if (hr > 0) return `${hr}h ${mn}min`;
  return `${mn}min`;
}
export function download(filename: string, content: string, mime = 'application/json') {
  const blob = new Blob([content], { type: mime + ';charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = filename; a.click();
  setTimeout(() => URL.revokeObjectURL(url), 800);
}
export function toCSV(rows: Record<string, string | number>[]): string {
  if (!rows.length) return '';
  const keys = Object.keys(rows[0]);
  const esc = (v: string | number) => `"${String(v).replace(/"/g, '""')}"`;
  return [keys.join(';'), ...rows.map(r => keys.map(k => esc(r[k] ?? '')).join(';'))].join('\n');
}

export function useNow(interval = 1000): number {
  const [nowTs, setNowTs] = useState(Date.now());
  useEffect(() => {
    const t = setInterval(() => setNowTs(Date.now()), interval);
    return () => clearInterval(t);
  }, [interval]);
  return nowTs;
}

/**
 * SLA de um incidente: resolução (top-level, retrocompatível) + resposta.
 * Online usa o objeto `inc.sla` calculado pela API; demo calcula local
 * com a política padrão (SLA_POLICY_DEMO).
 */
export function slaInfo(inc: Incident, nowTs: number) {
  // resolução
  const total = inc.slaH * 3_600_000;
  const resAt = inc.resolvedAt ?? null;
  const elapsed = (resAt ?? nowTs) - inc.ts;
  const left = total - elapsed;
  // resposta
  const pol = SLA_POLICY_DEMO[inc.severity] ?? SLA_POLICY_DEMO.medium;
  const respTotal = pol.responseMin * 60_000;
  const frAt = inc.firstResponseAt ?? inc.sla?.firstResponseAt ?? null;
  const respElapsed = (frAt ?? nowTs) - inc.ts;
  const respLeft = respTotal - respElapsed;
  const onlineRes = inc.sla?.resolution;
  const onlineResp = inc.sla?.response;
  return {
    left, pct: Math.max(0, Math.min(1, left / total)), breached: left < 0, total,
    at: resAt, actualMin: resAt ? Math.round(elapsed / 60_000) : null,
    targetMin: onlineRes?.targetMin ?? Math.round(total / 60_000),
    resp: {
      left: onlineResp?.leftMs ?? respLeft,
      pct: onlineResp?.pct ?? Math.max(0, Math.min(1, respLeft / respTotal)),
      breached: (onlineResp?.breached ?? respLeft < 0),
      total: onlineResp ? onlineResp.targetMin * 60_000 : respTotal,
      at: frAt,
      actualMin: frAt ? Math.round((frAt - inc.ts) / 60_000) : null,
      targetMin: onlineResp?.targetMin ?? pol.responseMin,
      done: !!frAt,
    },
  };
}

/**
 * Transição de etapa de um case: registra a duração da etapa que está
 * sendo deixada, grava na timeline e trata abertura/fechamento do ciclo.
 */
function stageChange(c: Case, target: CaseStage, actor: string, note?: string): Case {
  if (c.stage === target) return c;
  const now = Date.now();
  const prevChangedAt = [...(c.timeline ?? [])].reverse().find(t => t.kind === 'stage')?.ts ?? c.openedAt ?? c.ts;
  const durations = { ...(c.stageDurations ?? {}) };
  durations[c.stage] = Math.max(1, Math.round((now - prevChangedAt) / 60_000));
  const closing = target === 'Encerrado';
  return {
    ...c,
    stage: target,
    status: closing ? 'closed' : 'active',
    closedAt: closing ? now : null,
    slaBreached: closing ? ((c.closedAt ?? now) - (c.openedAt ?? c.ts)) > (c.slaMin ?? 0) * 60_000 : c.slaBreached,
    stageDurations: durations,
    timeline: [...(c.timeline ?? []), { ts: now, text: note ?? `Etapa alterada: ${c.stage} → ${target}`, kind: 'stage' as const, author: actor }],
  };
}

// ── API ──────────────────────────────────────────────────────
export interface StoreApi {
  s: AppState;
  me: string;
  tenantName: string;
  envName: string;
  tenantEnvs: { id: string; name: string; kind: string }[];
  scope: <T extends { tenant: string }>(list: T[]) => T[];
  nav: (r: Route, focus?: Focus | null) => void;
  setTenant: (t: string) => void;
  setEnv: (e: string) => void;
  setRole: (r: Role) => void;
  syncTenants: (list: Tenant[]) => void;
  login: (username: string, password: string) => Promise<LoginOutcome>;
  verifyMfa: (mfaToken: string, code: string) => Promise<{ ok: boolean; error?: string }>;
  mfaSetup: (mfaToken?: string) => Promise<{ secret: string; otpauth: string; error?: string }>;
  mfaEnable: (code: string, mfaToken?: string) => Promise<{ ok: boolean; error?: string; recoveryCodes?: string[] }>;
  mfaDisable: (code: string) => Promise<{ ok: boolean; error?: string }>;
  regenRecoveryCodes: () => Promise<string[]>;
  listSessions: () => Promise<SessionInfo[]>;
  revokeSession: (sid: string) => Promise<boolean>;
  revokeOtherSessions: () => Promise<void>;
  forgotPassword: (username: string) => Promise<{ ok: boolean; devToken?: string }>;
  resetPasswordToken: (token: string, password: string) => Promise<{ ok: boolean; error?: string }>;
  applySsoToken: (token: string) => Promise<boolean>;
  logout: () => void;
  toggleCorrelation: (id: string) => void;
  // Investigation Graph
  startInvestigation: (type: GraphNodeType, value: string) => void;
  expandNode: (id: string) => void;
  selectGraphNode: (id: string | null) => void;
  clearGraph: () => void;
  saveInvestigation: (name: string) => void;
  loadInvestigation: (inv: SavedInvestigation) => void;
  closeInvestigation: (id: string) => void;
  togglePause: () => void;
  setExplorerQuery: (q: string) => void;
  toast: (kind: Toast['kind'], msg: string) => void;
  dismiss: (id: number) => void;
  log: (action: string, target: string, kind?: AuditKind, actor?: string) => void;
  ingest: () => void;
  reportEvent: (evId: string) => void;
  ack: (id: string) => void;
  patchAlert: (id: string, patch: Partial<Alert>, logMsg?: string) => void;
  assignAlert: (id: string, user: string) => void;
  escalate: (alertId: string) => void;
  addIncident: (d: { title: string; severity: Severity; desc: string; asset?: string }) => void;
  patchIncident: (id: string, patch: Partial<Incident>, tl?: string) => void;
  toggleTask: (incId: string, taskId: string) => void;
  openCaseFromIncident: (incId: string) => void;
  addCase: (d: { title: string; severity: Severity; priority?: Priority; templateId?: string }) => void;
  setCaseStage: (id: string, stage: CaseStage) => void;
  advanceCase: (id: string) => void;
  addComment: (id: string, text: string) => void;
  // ciclo operacional do case (fase 9)
  patchCaseMeta: (id: string, patch: Partial<Pick<Case, 'priority' | 'status' | 'assignee'>>, logMsg?: string) => void;
  closeCase: (id: string, summary?: string) => void;
  reopenCase: (id: string) => void;
  addCaseTask: (id: string, text: string) => void;
  toggleCaseTask: (id: string, taskId: string) => void;
  removeCaseTask: (id: string, taskId: string) => void;
  addCaseRelation: (id: string, kind: 'alert' | 'incident' | 'asset' | 'ioc' | 'evidence', value: string) => void;
  removeCaseRelation: (id: string, kind: 'alert' | 'incident' | 'asset' | 'ioc' | 'evidence', value: string) => void;
  setVuln: (id: string, status: VulnStatus, logMsg?: string) => void;
  setAssetStatus: (name: string, status: AssetStatus) => void;
  startRun: (pbId: string) => void;
  tickRun: (runId: string) => void;
  approveRun: (runId: string) => void;
  rejectRun: (runId: string) => void;
  backend: AppState['backend'];
  refresh: () => void;
}

const Ctx = createContext<StoreApi | null>(null);

export function useStore(): StoreApi {
  const v = useContext(Ctx);
  if (!v) throw new Error('useStore fora do provider');
  return v;
}

export function StoreProvider({ children }: { children: ReactNode }) {
  const [s, setS] = useState<AppState>(initialState);
  const seq = useRef(300);
  const alertSeq = useRef(3129);
  const incSeq = useRef(2042);
  const caseSeq = useRef(119);
  const runSeq = useRef(1);

  const set = useCallback((fn: (p: AppState) => AppState) => setS(fn), []);

  const backendRef = useRef<AppState['backend']>('checking');

  const refresh = useCallback(async (tenant: string) => {
    const [data, corrs] = await Promise.all([srv.bootstrap(tenant), srv.correlations()]);
    if (data) {
      setS(p => ({
        ...p, events: data.events, alerts: data.alerts, incidents: data.incidents,
        cases: data.cases.map(normalizeCase), vulns: data.vulns, assets: data.assets, runs: data.runs,
        audit: data.audit, eps: data.eps, connectors: data.connectors,
        correlations: corrs ?? p.correlations,
        tenants: data.tenants?.length ? data.tenants.map(t => ({ id: t.id, name: t.name, short: t.short })) : p.tenants,
        environments: data.environments ?? p.environments,
      }));
    }
  }, []);

  // boot: conecta na sopir-api; se indisponível → modo demonstração
  useEffect(() => {
    let alive = true;
    // token expirado/inválido → derruba a sessão
    setUnauthorizedHandler(() => {
      setToken(null);
      localStorage.removeItem('sopir.user');
      setS(p => ({ ...p, user: null }));
    });
    (async () => {
      const ok = await srv.ping();
      if (!alive) return;
      if (ok) {
        backendRef.current = 'online';
        // sessão persistida? valida o token
        const savedUser = localStorage.getItem('sopir.user');
        if (savedUser) {
          const meRes = await srv.me();
          if (alive && meRes?.user) {
            if (meRes.user.permissions?.length) registerRolePerms(meRes.user.role, meRes.user.permissions);
            setS(p => ({
              ...p, backend: 'online', user: meRes.user, role: meRes.user.role,
              tenant: meRes.user.tenant ?? p.tenant,
              route: meRes.user.role === 'Customer' ? 'portal' : p.route,
              toasts: [...p.toasts.slice(-3), { id: Date.now() + 1, kind: 'ok' as const, msg: `Sessão restaurada — bem-vindo(a), ${meRes.user.name}` }],
            }));
            void refresh(meRes.user.tenant ?? 'vetra');
            return;
          }
          // token inválido → limpa
          setToken(null);
          localStorage.removeItem('sopir.user');
        }
        setS(p => ({
          ...p, backend: 'online',
          toasts: [...p.toasts.slice(-3), { id: Date.now() + 1, kind: 'ok' as const, msg: 'sopir-api conectado — persistência e collectors ativos' }],
        }));
        return;
      }
      // API indisponível: fallback para modo offline (sem dados seed)
      backendRef.current = 'demo';
      let user: AuthUser | null = null;
      try {
        const savedUser = localStorage.getItem('sopir.user');
        if (savedUser) user = JSON.parse(savedUser) as AuthUser;
      } catch { user = null; }
      setS(p => ({
        ...p, backend: 'demo', user, role: (user?.role as Role) ?? 'Admin',
        events: [], alerts: [], incidents: [], cases: [], vulns: [], assets: [],
        toasts: [...p.toasts.slice(-3), { id: Date.now() + 1, kind: 'info' as const, msg: 'sopir-api indisponível — conecte o Wazuh/FortiSIEM e reinicie' }],
      }));
    })();
    return () => { alive = false; };
  }, []);

  // mantém o estado sincronizado com o backend quando online
  useEffect(() => {
    if (s.backend !== 'online') return;
    const t = setInterval(() => { void refresh(s.tenant); }, 8000);
    return () => clearInterval(t);
  }, [s.backend, s.tenant, refresh]);

  const api = useMemo<StoreApi>(() => {
    const pushToast = (kind: Toast['kind'], msg: string) => {
      const id = Date.now() + Math.random();
      set(p => ({ ...p, toasts: [...p.toasts.slice(-3), { id, kind, msg }] }));
    };
    const pushAudit = (p: AppState, action: string, target: string, kind: AuditKind, actor: string): AppState => ({
      ...p,
      audit: [{ id: 'au' + Date.now() + Math.floor(Math.random() * 999), ts: Date.now(), actor, action, target, kind }, ...p.audit].slice(0, 120),
    });

    // integração com a sopir-api (ignora silenciosamente em modo demo)
    const online = () => backendRef.current === 'online';
    const push = (promise: Promise<unknown>) => { if (online()) void promise; };
    const sync = (promise: Promise<unknown>) => {
      if (online()) void promise.then(() => refresh(s.tenant));
    };

    // ── helpers de autenticação ───────────────────────────
    const persistUser = (u: AuthUser) => {
      try { localStorage.setItem('sopir.user', JSON.stringify(u)); } catch { /* sessão segue em memória */ }
    };
    const applyAuth = (token: string | null, user: AuthUser) => {
      if (token) setToken(token);
      if (user.permissions?.length) registerRolePerms(user.role, user.permissions);
      persistUser(user);
      set(p => ({ ...p, user, role: user.role, tenant: user.tenant ?? p.tenant, route: user.role === 'Customer' ? 'portal' : p.route }));
      void refresh(user.tenant ?? s.tenant);
    };
    const demoMfaKey = (uname: string) => 'sopir.demo.mfa.' + uname;

    return {
      s,
      me: s.user?.name ?? ROLE_USER[s.role],
      backend: s.backend,
      refresh: () => { void refresh(s.tenant); },
      tenantName: s.tenant === 'all' ? 'MSSP — todos os clientes' : (s.tenants.find(t => t.id === s.tenant)?.name ?? s.tenant),
      tenantEnvs: s.environments.filter(e => e.tenant === s.tenant),
      envName: s.env === 'all' ? 'Todos os ambientes' : (s.environments.find(e => e.id === s.env)?.name ?? s.env),
      scope: (list) => {
        let out = s.tenant === 'all' ? list : list.filter(x => x.tenant === s.tenant);
        // itens sem env marcado são "globais" e aparecem em qualquer ambiente
        if (s.env !== 'all') {
          out = out.filter(x => {
            const e = (x as unknown as { env?: string | null }).env;
            return e == null || e === s.env;
          });
        }
        return out;
      },

      nav: (r, focus = null) => set(p => ({ ...p, route: p.role === 'Customer' && r !== 'portal' ? 'portal' : r, focus })),
      setTenant: (t) => set(p => ({ ...p, tenant: t, env: 'all', focus: null })),
      setEnv: (e) => set(p => ({ ...p, env: e, focus: null })),
      setRole: (r) => set(p => ({ ...p, role: r, route: r === 'Customer' ? 'portal' : p.route })),

      syncTenants: (list) => {
        // mantém o seletor do topo e o store sempre com a lista real de clientes
        const clean = list.filter(t => t && t.id).map(t => ({ id: t.id, name: t.name, short: t.short }));
        set(p => ({ ...p, tenants: clean.length ? clean : p.tenants }));
      },

      login: async (username, password) => {
        try {
          if (backendRef.current === 'online') {
            const res = await srv.login(username, password);
            if (!res) return { ok: false, error: 'Credenciais inválidas, conta suspensa ou sopir-api inacessível.' };
            if (res.mfaRequired && res.mfaToken) {
              return { ok: false, mfa: 'verify' as const, mfaToken: res.mfaToken, username: res.user?.username };
            }
            if (res.mustEnroll && res.mfaToken) {
              return { ok: false, mfa: 'enroll' as const, mfaToken: res.mfaToken, username: res.user?.username };
            }
            if (res.token && res.user) {
              applyAuth(res.token, res.user);
              return { ok: true };
            }
            return { ok: false, error: res.error ?? 'Usuário ou senha inválidos.' };
          }
          // modo demonstração: valida contra os usuários locais
          const u = DEMO_USERS.find(x => x.username === username.toLowerCase().trim() && x.password === password);
          if (!u) return { ok: false, error: 'Usuário ou senha inválidos. Use uma das contas de demonstração (senha: sopir).' };
          try {
            if (localStorage.getItem(demoMfaKey(u.username))) {
              return { ok: false, mfa: 'verify' as const, mfaToken: 'demo:' + u.username, username: u.username };
            }
          } catch { /* sem localStorage */ }
          applyAuth(null, { username: u.username, name: u.name, role: u.role, tenant: u.tenant });
          return { ok: true };
        } catch {
          return { ok: false, error: 'Falha inesperada na autenticação. Tente novamente.' };
        }
      },

      // ── MFA ─────────────────────────────────────────────
      verifyMfa: async (mfaToken, code) => {
        if (backendRef.current === 'online') {
          const res = await srv.mfaVerify(mfaToken, code);
          if (!res) return { ok: false, error: 'Falha de comunicação com a API.' };
          if (res.token && res.user) { applyAuth(res.token, res.user); return { ok: true }; }
          return { ok: false, error: res.error ?? 'Código inválido.' };
        }
        // demo: qualquer código de 6 dígitos é aceito
        const uname = mfaToken.startsWith('demo:') ? mfaToken.slice(5) : '';
        const u = DEMO_USERS.find(x => x.username === uname);
        if (!u || !/^\d{6}$/.test(code)) return { ok: false, error: 'Código inválido.' };
        applyAuth(null, { username: u.username, name: u.name, role: u.role, tenant: u.tenant });
        return { ok: true };
      },

      mfaSetup: async (mfaToken) => {
        if (backendRef.current === 'online') {
          const res = await srv.mfaSetup(mfaToken);
          return res ?? { secret: '', otpauth: '', error: 'Falha ao iniciar configuração MFA.' };
        }
        const secret = Array.from({ length: 16 }, () => 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'[Math.floor(Math.random() * 32)]).join('');
        return { secret, otpauth: `otpauth://totp/SOPIR:${s.user?.username ?? 'demo'}?secret=${secret}&issuer=SOPIR` };
      },

      mfaEnable: async (code, mfaToken) => {
        if (backendRef.current === 'online') {
          const res = await srv.mfaEnable(code, mfaToken);
          if (!res) return { ok: false, error: 'Falha de comunicação com a API.' };
          if (!res.ok && !res.token) return { ok: false, error: res.error ?? 'Código inválido.' };
          if (res.token && res.user) applyAuth(res.token, res.user);
          else if (s.user) set(p => ({ ...p, user: p.user ? { ...p.user, mfaEnabled: true } : p.user }));
          return { ok: true, recoveryCodes: res.recoveryCodes };
        }
        if (!/^\d{6}$/.test(code)) return { ok: false, error: 'Código inválido.' };
        const uname = mfaToken?.startsWith('demo:') ? mfaToken.slice(5) : s.user?.username;
        if (uname) {
          const u = DEMO_USERS.find(x => x.username === uname);
          const codes = Array.from({ length: 8 }, () => Math.random().toString(16).slice(2, 7) + '-' + Math.random().toString(16).slice(2, 7));
          try {
            localStorage.setItem(demoMfaKey(uname), '1');
            localStorage.setItem('sopir.demo.codes.' + uname, JSON.stringify(codes));
          } catch { /* noop */ }
          if (u) applyAuth(null, { username: u.username, name: u.name, role: u.role, tenant: u.tenant });
          return { ok: true, recoveryCodes: codes };
        }
        return { ok: false, error: 'Sessão inválida.' };
      },

      mfaDisable: async (code) => {
        if (backendRef.current === 'online') {
          const res = await srv.mfaDisable(code);
          if (!res?.ok) return { ok: false, error: res?.error ?? 'Código inválido.' };
          set(p => ({ ...p, user: p.user ? { ...p.user, mfaEnabled: false } : p.user }));
          return { ok: true };
        }
        if (s.user) { try { localStorage.removeItem(demoMfaKey(s.user.username)); } catch { /* noop */ } }
        set(p => ({ ...p, user: p.user ? { ...p.user, mfaEnabled: false } : p.user }));
        return { ok: true };
      },

      regenRecoveryCodes: async () => {
        if (backendRef.current === 'online') {
          const res = await srv.regenRecoveryCodes();
          return res?.codes ?? [];
        }
        const codes = Array.from({ length: 8 }, () => Math.random().toString(16).slice(2, 7) + '-' + Math.random().toString(16).slice(2, 7));
        if (s.user) { try { localStorage.setItem('sopir.demo.codes.' + s.user.username, JSON.stringify(codes)); } catch { /* noop */ } }
        return codes;
      },

      // ── Sessões ─────────────────────────────────────────
      listSessions: async () => {
        if (backendRef.current === 'online') {
          return (await srv.sessions()) ?? [];
        }
        const nowTs = Date.now();
        return [{ id: 'demo-current', ip: null, ua: typeof navigator !== 'undefined' ? navigator.userAgent : null, created: nowTs - 3_600_000, expires: nowTs + 11 * 3_600_000, lastSeen: nowTs, revoked: null, current: true }];
      },

      revokeSession: async (sid) => {
        if (backendRef.current === 'online') {
          const res = await srv.revokeSession(sid);
          if (!res?.ok) return false;
        }
        pushToast('ok', 'Sessão encerrada');
        return true;
      },

      revokeOtherSessions: async () => {
        if (backendRef.current === 'online') {
          const res = await srv.revokeOtherSessions();
          pushToast(res ? 'ok' : 'err', res ? `${res.revoked} sessão(ões) encerrada(s)` : 'Falha ao encerrar sessões');
          return;
        }
        pushToast('ok', 'Sessões encerradas');
      },

      // ── Recuperação de senha ────────────────────────────
      forgotPassword: async (username) => {
        if (backendRef.current === 'online') {
          const res = await srv.forgot(username);
          return res ?? { ok: false };
        }
        return { ok: true, devToken: 'demo' };
      },

      resetPasswordToken: async (token, password) => {
        if (backendRef.current === 'online') {
          const res = await srv.resetToken(token, password);
          if (!res) return { ok: false, error: 'Falha de comunicação com a API.' };
          if (res.error) return { ok: false, error: res.error };
          return { ok: true };
        }
        return { ok: true };
      },

      // ── SSO ─────────────────────────────────────────────
      applySsoToken: async (token) => {
        setToken(token);
        const me = await srv.me();
        if (me?.user) {
          applyAuth(token, me.user);
          return true;
        }
        setToken(null);
        return false;
      },

      logout: () => {
        setToken(null);
        localStorage.removeItem('sopir.user');
        set(p => ({ ...p, user: null }));
      },

      toggleCorrelation: (id) => {
        const pol = s.correlations.find(c => c.id === id);
        if (!pol) return;
        const enabled = !pol.enabled;
        set(p => ({ ...p, correlations: p.correlations.map(c => c.id === id ? { ...c, enabled } : c) }));
        push(srv.toggleCorrelation(id, enabled));
        pushToast('info', `Política ${id} ${enabled ? 'ativada' : 'desativada'}`);
      },

      // ── Investigation Graph ──────────────────────────────
      startInvestigation: (type, value) => {
        const rootId = `${type}:${value}`;
        // nó raiz imediato (feedback instantâneo) + expansão assíncrona
        set(p => ({
          ...p, route: 'investigation',
          graphRoot: { type, value }, graphSel: rootId,
          graph: { nodes: [{ id: rootId, type, value, sub: 'raiz da investigação', x: 0, y: 0, vx: 0, vy: 0 }], edges: [] },
        }));
        void api.expandNode(rootId);
      },

      expandNode: (id) => {
        const [type, ...rest] = id.split(':');
        const value = rest.join(':');
        if (!type || !value) return;
        const apply = (nodes: GNode[], edges: GraphData['edges']) => {
          set(p => {
            const nMap = new Map(p.graph.nodes.map(n => [n.id, n]));
            for (const n of nodes) if (!nMap.has(n.id)) nMap.set(n.id, n);
            const eMap = new Map(p.graph.edges.map(e => [e.id, e]));
            for (const e of edges) if (!eMap.has(e.id)) eMap.set(e.id, e);
            return { ...p, graph: { nodes: [...nMap.values()], edges: [...eMap.values()] } };
          });
        };
        if (backendRef.current === 'online') {
          void srv.graphExpand(type, value, s.tenant).then(g => {
            if (!g) return;
            apply(
              g.nodes.map(n => ({ ...n, type: n.type as GraphNodeType, sub: n.sub ?? '', x: 0, y: 0, vx: 0, vy: 0 })),
              g.edges,
            );
          });
        } else {
          const g = expandLocal(type as GraphNodeType, value, { events: s.events, alerts: s.alerts, incidents: s.incidents, assets: s.assets });
          apply(g.nodes, g.edges);
        }
      },

      selectGraphNode: (id) => set(p => ({ ...p, graphSel: id })),
      clearGraph: () => set(p => ({ ...p, graph: { nodes: [], edges: [] }, graphSel: null, graphRoot: null })),

      saveInvestigation: (name) => {
        if (!s.graph.nodes.length) { pushToast('warn', 'Grafo vazio — nada para salvar'); return; }
        const body = {
          name, rootType: s.graphRoot?.type ?? '', rootValue: s.graphRoot?.value ?? '',
          graph: {
            nodes: s.graph.nodes.map(({ id, type, value, sub }) => ({ id, type, value, sub })),
            edges: s.graph.edges.map(({ id, source, target, label }) => ({ id, source, target, label })),
          },
          tenant: s.tenant === 'all' ? 'vetra' : s.tenant,
        };
        // otimista local (demo)
        const localInv: SavedInvestigation = { ...body, id: 'INV-' + Date.now(), status: 'aberta', ts: Date.now(), owner: ROLE_USER[s.role] };
        set(p => ({ ...p, investigations: [localInv, ...p.investigations] }));
        pushToast('ok', `Investigação "${name}" salva`);
        if (backendRef.current === 'online') {
          void srv.saveInvestigation(body).then(() => srv.investigations()).then(list => {
            if (list) set(p => ({ ...p, investigations: list }));
          });
        }
      },

      loadInvestigation: (inv) => {
        set(p => ({
          ...p, route: 'investigation',
          graphRoot: { type: (inv.rootType || 'ip') as GraphNodeType, value: inv.rootValue || '' },
          graphSel: null,
          graph: {
            nodes: inv.graph.nodes.map(n => ({ ...n, type: n.type as GraphNodeType, x: 0, y: 0, vx: 0, vy: 0 })),
            edges: inv.graph.edges,
          },
        }));
        pushToast('info', `Investigação "${inv.name}" carregada`);
      },

      closeInvestigation: (id) => {
        set(p => ({ ...p, investigations: p.investigations.filter(i => i.id !== id) }));
        push(srv.patchInvestigation(id, { status: 'fechada' }));
        pushToast('ok', 'Investigação encerrada');
      },

      togglePause: () => set(p => ({ ...p, paused: !p.paused })),
      setExplorerQuery: (q) => set(p => ({ ...p, explorerQuery: q })),

      toast: pushToast,
      dismiss: (id) => set(p => ({ ...p, toasts: p.toasts.filter(t => t.id !== id) })),
      log: (action, target, kind = 'system', actor) =>
        set(p => pushAudit(p, action, target, kind, actor ?? ROLE_USER[p.role])),

      ingest: () => {
        // com backend online, o simulador/colector roda no servidor
        if (backendRef.current === 'online') return;
        seq.current += 1;
        const ev = makeEvent(seq.current, Date.now(), s.tenant === 'all' ? undefined : s.tenant);
        set(p => {
          let next: AppState = { ...p, events: [ev, ...p.events].slice(0, 400) };
          const roll = Math.random();
          if (roll < 0.10 && (ev.severity === 'high' || ev.severity === 'critical')) {
            alertSeq.current += 1;
            const alert: Alert = {
              id: 'ALT-' + alertSeq.current, tenant: ev.tenant, title: ev.rule, severity: ev.severity,
              status: 'novo', source: ev.source, rule: ev.rule, ruleId: ev.ruleId, srcIp: ev.srcIp,
              dstIp: ev.dstIp, user: ev.user, host: ev.host, ts: ev.ts, desc: ev.desc,
            };
            next = pushAudit({ ...next, alerts: [alert, ...next.alerts] }, 'gerou alerta automático via correlação', alert.id, 'system', 'correlação SOPIR');
          }
          return next;
        });
      },

      reportEvent: (evId) => {
        const ev = s.events.find(e => e.id === evId);
        if (!ev) return;
        alertSeq.current += 1;
        const alert: Alert = {
          id: 'ALT-' + alertSeq.current, tenant: ev.tenant, title: ev.rule, severity: ev.severity,
          status: 'novo', source: ev.source, rule: ev.rule, ruleId: ev.ruleId, srcIp: ev.srcIp,
          dstIp: ev.dstIp, user: ev.user, host: ev.host, ts: Date.now(), desc: ev.desc,
        };
        set(p => pushAudit({ ...p, alerts: [alert, ...p.alerts] }, 'criou alerta a partir de evento', `${alert.id} ← ${evId}`, 'triage', ROLE_USER[p.role]));
        pushToast('ok', `Alerta ${alert.id} criado a partir de ${evId}`);
        push(srv.postAlertFromEvent(evId));
      },

      ack: (id) => {
        const prev = s.alerts.find(x => x.id === id);
        set(p => {
          const a = p.alerts.find(x => x.id === id);
          if (!a || a.status !== 'novo') return p;
          return pushAudit(
            { ...p, alerts: p.alerts.map(x => x.id === id ? { ...x, status: 'reconhecido' as AlertStatus, assignee: x.assignee ?? ROLE_USER[p.role] } : x) },
            'reconheceu alerta', id, 'triage', ROLE_USER[p.role]);
        });
        if (prev && prev.status === 'novo') {
          push(srv.patchAlert(id, { status: 'reconhecido', assignee: prev.assignee ?? ROLE_USER[s.role] }));
        }
      },

      patchAlert: (id, patch, logMsg) => {
        set(p =>
          pushAudit(
            { ...p, alerts: p.alerts.map(x => x.id === id ? { ...x, ...patch } : x) },
            logMsg ?? 'atualizou alerta', id, 'triage', ROLE_USER[p.role]));
        push(srv.patchAlert(id, { ...patch }));
      },

      assignAlert: (id, user) => {
        set(p =>
          pushAudit(
            { ...p, alerts: p.alerts.map(x => x.id === id ? { ...x, assignee: user, status: x.status === 'novo' ? 'reconhecido' as AlertStatus : x.status } : x) },
            `atribuiu alerta para ${user}`, id, 'triage', ROLE_USER[p.role]));
        push(srv.patchAlert(id, { assignee: user }));
      },

      escalate: (alertId) => {
        const a = s.alerts.find(x => x.id === alertId);
        if (!a) return;
        incSeq.current += 1;
        const incId = 'INC-' + incSeq.current;
        const inc: Incident = {
          id: incId, tenant: a.tenant, title: a.title, severity: a.severity,
          priority: sevToPriority(a.severity), status: 'aberto',
          assignee: ROLE_USER[s.role], ts: Date.now(), slaH: SLA_HOURS[a.severity],
          alertIds: [a.id], iocs: a.srcIp !== '—' ? [a.srcIp] : [], asset: a.host !== '—' ? a.host : undefined,
          tasks: [
            { id: 't1', text: 'Triagem inicial e validação do escopo', done: false },
            { id: 't2', text: 'Coleta de evidências', done: false },
            { id: 't3', text: 'Definir ações de contenção', done: false },
          ],
          timeline: [
            { ts: Date.now(), text: `Incidente criado a partir do alerta ${a.id} (${a.rule})`, kind: 'system' },
            { ts: Date.now(), text: `Prioridade ${sevToPriority(a.severity)} · SLA resposta ${SLA_POLICY_DEMO[a.severity].responseMin}min / resolução ${SLA_HOURS[a.severity]}h`, kind: 'action', author: ROLE_USER[s.role] },
          ],
        };
        set(p => pushAudit({
          ...p,
          incidents: [inc, ...p.incidents],
          alerts: p.alerts.map(x => x.id === alertId ? { ...x, status: 'escalado' as AlertStatus, incidentId: incId } : x),
        }, `escalou alerta para incidente ${incId}`, alertId, 'triage', ROLE_USER[p.role]));
        pushToast('ok', `${incId} criado a partir de ${alertId}`);
        sync(srv.escalateAlert(alertId, { title: a.title, severity: a.severity }));
      },

      addIncident: (d) => {
        incSeq.current += 1;
        const incId = 'INC-' + incSeq.current;
        const inc: Incident = {
          id: incId, tenant: s.tenant === 'all' ? 'vetra' : s.tenant, title: d.title, severity: d.severity,
          priority: sevToPriority(d.severity), status: 'aberto',
          assignee: ROLE_USER[s.role], ts: Date.now(), slaH: SLA_HOURS[d.severity],
          alertIds: [], iocs: [], asset: d.asset,
          tasks: [{ id: 't1', text: 'Triagem inicial', done: false }, { id: 't2', text: 'Coleta de evidências', done: false }],
          timeline: [{ ts: Date.now(), text: `Incidente aberto manualmente (${sevToPriority(d.severity)}): ${d.desc || 'sem descrição'}`, kind: 'user', author: ROLE_USER[s.role] }],
        };
        set(p => pushAudit({ ...p, incidents: [inc, ...p.incidents] }, 'abriu incidente manualmente', incId, 'triage', ROLE_USER[s.role]));
        pushToast('ok', `${incId} aberto — SLA de ${SLA_HOURS[d.severity]}h iniciado`);
        sync(srv.postIncident({ title: d.title, severity: d.severity, desc: d.desc, asset: d.asset, tenant: inc.tenant }));
      },

      patchIncident: (id, patch, tl) => {
        set(p => {
          const actor = ROLE_USER[p.role];
          return pushAudit(
            {
              ...p,
              incidents: p.incidents.map(x => {
                if (x.id !== id) return x;
                const stamped: Partial<Incident> = { ...patch };
                // primeiro movimento de status saindo de 'aberto' → carimba resposta
                if (patch.status && patch.status !== 'aberto' && x.status === 'aberto' && !x.firstResponseAt) {
                  stamped.firstResponseAt = Date.now();
                }
                // resolução / reabertura
                if (patch.status && ['resolvido', 'fechado'].includes(patch.status) && !x.resolvedAt) {
                  stamped.resolvedAt = Date.now();
                } else if (patch.status && !['resolvido', 'fechado'].includes(patch.status) && x.resolvedAt) {
                  stamped.resolvedAt = null;
                }
                return {
                  ...x, ...stamped,
                  timeline: tl ? [...x.timeline, { ts: Date.now(), text: tl, kind: 'action' as const, author: actor }] : x.timeline,
                };
              }),
            },
            tl ?? 'atualizou incidente', id, 'triage', actor);
        });
        push(srv.patchIncident(id, { ...patch, log: tl }));
      },

      toggleTask: (incId, taskId) => {
        const inc = s.incidents.find(x => x.id === incId);
        const task = inc?.tasks.find(t => t.id === taskId);
        const done = !(task?.done ?? false);
        set(p => ({
          ...p,
          incidents: p.incidents.map(x => x.id === incId ? {
            ...x,
            tasks: x.tasks.map(t => t.id === taskId ? { ...t, done: !t.done } : t),
          } : x),
        }));
        push(srv.patchTask(incId, taskId, done));
      },

      openCaseFromIncident: (incId) => {
        const inc = s.incidents.find(x => x.id === incId);
        if (!inc || inc.caseId) return;
        caseSeq.current += 1;
        const caseId = 'CASE-' + caseSeq.current;
        const now = Date.now();
        const c: Case = normalizeCase({
          id: caseId, tenant: inc.tenant, title: inc.title, severity: inc.severity, stage: 'Investigação',
          assignee: inc.assignee, ts: now, alertIds: [...inc.alertIds], incidentIds: [inc.id],
          assetNames: inc.asset ? [inc.asset] : [], iocs: [...inc.iocs], evidence: [], comments: [],
          priority: sevToPriority(inc.severity), openedAt: now, status: 'active',
          tasks: [
            { id: 'ct1', text: 'Confirmar escopo e impacto', done: false },
            { id: 'ct2', text: 'Coletar e preservar evidências', done: false },
            { id: 'ct3', text: 'Executar contenção inicial', done: false },
          ],
          timeline: [{ ts: now, text: `Case criado a partir do incidente ${inc.id}`, kind: 'system' }],
        });
        set(p => pushAudit({
          ...p,
          cases: [c, ...p.cases],
          incidents: p.incidents.map(x => x.id === incId ? {
            ...x, caseId,
            timeline: [...x.timeline, { ts: Date.now(), text: `Case ${caseId} aberto para gestão do ciclo de vida`, kind: 'action' as const, author: ROLE_USER[p.role] }],
          } : x),
        }, `abriu case ${caseId} a partir do incidente`, incId, 'triage', ROLE_USER[p.role]));
        pushToast('ok', `${caseId} criado e vinculado a ${incId}`);
        sync(srv.openCaseFromIncident(incId));
      },

      addCase: (d) => {
        caseSeq.current += 1;
        const caseId = 'CASE-' + caseSeq.current;
        const now = Date.now();
        const tpl = d.templateId ? CASE_TEMPLATES_DEMO.find(t => t.id === d.templateId) ?? null : null;
        const c: Case = normalizeCase({
          id: caseId, tenant: s.tenant === 'all' ? 'vetra' : s.tenant, title: d.title, severity: d.severity,
          stage: 'Triagem', assignee: ROLE_USER[s.role], ts: now, alertIds: [], incidentIds: [],
          assetNames: [], iocs: [], evidence: [], comments: [],
          priority: d.priority ?? sevToPriority(d.severity), openedAt: now, status: 'active',
          tasks: (tpl?.tasks ?? []).map((t, i) => ({ id: 'ct' + (i + 1), text: t, done: false })),
          timeline: [{ ts: now, text: tpl ? `Case criado a partir do template “${tpl.name}”` : 'Case criado manualmente', kind: 'system' }],
        });
        set(p => pushAudit({ ...p, cases: [c, ...p.cases] }, 'criou case manualmente', caseId, 'triage', ROLE_USER[s.role]));
        pushToast('ok', `${caseId} criado`);
        sync(srv.postCase({ title: d.title, severity: d.severity, priority: c.priority, templateId: d.templateId, tenant: c.tenant }));
      },

      setCaseStage: (id, stage) => {
        const actor = ROLE_USER[s.role];
        set(p =>
          pushAudit(
            { ...p, cases: p.cases.map(x => x.id === id ? stageChange(x, stage, actor) : x) },
            `moveu case para ${stage}`, id, 'triage', actor));
        push(srv.patchCase(id, { stage }));
      },

      advanceCase: (id) => {
        const STAGES: CaseStage[] = ['Triagem', 'Investigação', 'Contenção', 'Recuperação', 'Encerrado'];
        const c = s.cases.find(x => x.id === id);
        if (!c) return;
        const next = STAGES[Math.min(STAGES.indexOf(c.stage) + 1, STAGES.length - 1)];
        if (next === c.stage) return;
        const actor = ROLE_USER[s.role];
        set(p =>
          pushAudit(
            { ...p, cases: p.cases.map(x => x.id === id ? stageChange(x, next, actor) : x) },
            `avançou case para ${next}`, id, 'triage', actor));
        sync(srv.patchCase(id, { advance: true }));
      },

      patchCaseMeta: (id, patch, logMsg) => {
        const actor = ROLE_USER[s.role];
        set(p =>
          pushAudit(
            { ...p, cases: p.cases.map(x => x.id === id ? { ...x, ...patch } : x) },
            logMsg ?? 'atualizou case', id, 'triage', actor));
        push(srv.patchCase(id, { ...patch }));
      },

      closeCase: (id, summary) => {
        const actor = ROLE_USER[s.role];
        set(p =>
          pushAudit(
            {
              ...p,
              cases: p.cases.map(x => {
                if (x.id !== id) return x;
                const closed = stageChange(x, 'Encerrado', actor, summary ? `Case encerrado: ${summary}` : 'Case encerrado');
                return { ...closed, status: 'closed' as const, closedAt: Date.now() };
              }),
            },
            'encerrou case' + (summary ? ` — ${summary}` : ''), id, 'triage', actor));
        pushToast('ok', `${id} encerrado`);
        sync(srv.patchCase(id, { stage: 'Encerrado', status: 'closed', summary }));
      },

      reopenCase: (id) => {
        const actor = ROLE_USER[s.role];
        set(p =>
          pushAudit(
            {
              ...p,
              cases: p.cases.map(x => x.id === id
                ? { ...stageChange(x, 'Recuperação', actor, 'Case reaberto'), status: 'active' as const, closedAt: null }
                : x),
            },
            'reabriu case', id, 'triage', actor));
        pushToast('info', `${id} reaberto na etapa Recuperação`);
        sync(srv.patchCase(id, { stage: 'Recuperação', status: 'active' }));
      },

      addCaseTask: (id, text) => {
        const taskId = 'ct' + Date.now();
        set(p => ({
          ...p,
          cases: p.cases.map(x => x.id === id ? { ...x, tasks: [...(x.tasks ?? []), { id: taskId, text, done: false }] } : x),
        }));
        push(srv.postCaseTask(id, text));
      },

      toggleCaseTask: (id, taskId) => {
        const c = s.cases.find(x => x.id === id);
        const task = c?.tasks?.find(t => t.id === taskId);
        const done = !(task?.done ?? false);
        set(p => ({
          ...p,
          cases: p.cases.map(x => x.id === id ? {
            ...x,
            tasks: (x.tasks ?? []).map(t => t.id === taskId ? { ...t, done: !t.done } : t),
          } : x),
        }));
        push(srv.patchCaseTask(id, taskId, done));
      },

      removeCaseTask: (id, taskId) => {
        set(p => ({
          ...p,
          cases: p.cases.map(x => x.id === id ? { ...x, tasks: (x.tasks ?? []).filter(t => t.id !== taskId) } : x),
        }));
        push(srv.deleteCaseTask(id, taskId));
      },

      addCaseRelation: (id, kind, value) => {
        const REL_FIELD = { alert: 'alertIds', incident: 'incidentIds', asset: 'assetNames', ioc: 'iocs', evidence: 'evidence' } as const;
        const field = REL_FIELD[kind];
        const actor = ROLE_USER[s.role];
        const now = Date.now();
        set(p => ({
          ...p,
          cases: p.cases.map(x => {
            if (x.id !== id) return x;
            const list = (x[field] ?? []) as string[];
            if (list.includes(value)) return x;
            return {
              ...x,
              [field]: [...list, value],
              timeline: [...(x.timeline ?? []), { ts: now, text: `Vinculou ${kind}: ${value}`, kind: 'relation' as const, author: actor }],
            };
          }),
        }));
        push(srv.addCaseRelation(id, kind, value));
      },

      removeCaseRelation: (id, kind, value) => {
        const REL_FIELD = { alert: 'alertIds', incident: 'incidentIds', asset: 'assetNames', ioc: 'iocs', evidence: 'evidence' } as const;
        const field = REL_FIELD[kind];
        const actor = ROLE_USER[s.role];
        const now = Date.now();
        set(p => ({
          ...p,
          cases: p.cases.map(x => {
            if (x.id !== id) return x;
            return {
              ...x,
              [field]: ((x[field] ?? []) as string[]).filter(v => v !== value),
              timeline: [...(x.timeline ?? []), { ts: now, text: `Removeu vínculo ${kind}: ${value}`, kind: 'relation' as const, author: actor }],
            };
          }),
        }));
        push(srv.removeCaseRelation(id, kind, value));
      },

      addComment: (id, text) => {
        set(p => ({
          ...p,
          cases: p.cases.map(x => x.id === id ? { ...x, comments: [...x.comments, { ts: Date.now(), author: ROLE_USER[p.role], text }] } : x),
        }));
        push(srv.postComment(id, text, ROLE_USER[s.role]));
      },

      setVuln: (id, status, logMsg) => {
        set(p =>
          pushAudit(
            { ...p, vulns: p.vulns.map(x => x.id === id ? { ...x, status } : x) },
            logMsg ?? 'atualizou vulnerabilidade', id, 'data', ROLE_USER[p.role]));
        push(srv.patchVuln(id, status));
      },

      setAssetStatus: (name, status) => {
        set(p =>
          pushAudit(
            { ...p, assets: p.assets.map(x => x.name === name ? { ...x, status } : x) },
            status === 'isolado' ? 'executou isolamento de endpoint' : status === 'online' ? 'liberou endpoint do isolamento' : 'atualizou status do ativo',
            name, 'response', ROLE_USER[p.role]));
        push(srv.patchAsset(name, status));
      },

      startRun: (pbId) => {
        const pb = s.playbooks.find(x => x.id === pbId);
        if (!pb) return;
        const run: PlayRun = {
          id: 'RUN-' + String(runSeq.current++).padStart(3, '0'), pbId, pbName: pb.name,
          step: 0, status: 'andamento', ts: Date.now(),
          tenant: s.tenant === 'all' ? 'vetra' : s.tenant, actor: ROLE_USER[s.role],
        };
        set(p => pushAudit({ ...p, runs: [run, ...p.runs] }, `iniciou execução de playbook`, pb.name, 'response', ROLE_USER[p.role]));
        pushToast('info', `Playbook "${pb.name}" iniciado`);
        sync(srv.startRun(pbId, ROLE_USER[s.role]));
      },

      tickRun: (runId) => {
        // online, a Response Engine roda no servidor (polling traz o progresso)
        if (backendRef.current === 'online') return;
        set(p => {
        const run = p.runs.find(r => r.id === runId);
        if (!run || run.status !== 'andamento') return p;
        const pb = p.playbooks.find(x => x.id === run.pbId);
        if (!pb) return p;
        const step = pb.steps[run.step];
        if (!step) {
          return pushAudit({ ...p, runs: p.runs.map(r => r.id === runId ? { ...r, status: 'concluido' as const } : r) }, 'concluiu playbook', pb.name, 'response', run.actor);
        }
        if (step.approval) {
          return pushAudit(
            { ...p, runs: p.runs.map(r => r.id === runId ? { ...r, status: 'aprovacao' as const } : r) },
            `solicitou aprovação para: ${step.label}`, pb.name, 'response', `Playbook ${pb.id}`);
        }
        let next = p;
        if (step.effect?.isolate) next = { ...next, assets: next.assets.map(a => a.name === step.effect!.isolate ? { ...a, status: 'isolado' as AssetStatus } : a) };
        next = pushAudit(
          { ...next, runs: next.runs.map(r => r.id === runId ? { ...r, step: run.step + 1 } : r) },
          `executou passo: ${step.label}`, pb.name, 'response', `Playbook ${pb.id}`);
        if (run.step + 1 >= pb.steps.length) {
          next = pushAudit({ ...next, runs: next.runs.map(r => r.id === runId ? { ...r, status: 'concluido' as const } : r) }, 'concluiu playbook com sucesso', pb.name, 'response', `Playbook ${pb.id}`);
        }
        return next;
        });
      },

      approveRun: (runId) => {
        set(p => {
          const run = p.runs.find(r => r.id === runId);
          if (!run) return p;
          const pb = p.playbooks.find(x => x.id === run.pbId);
          const step = pb?.steps[run.step];
          let next = pushAudit(
            { ...p, runs: p.runs.map(r => r.id === runId ? { ...r, status: 'andamento' as const, step: run.step + 1 } : r) },
            `aprovou passo: ${step?.label ?? 'ação'}`, pb?.name ?? runId, 'response', ROLE_USER[p.role]);
          if (step?.effect?.isolate) next = { ...next, assets: next.assets.map(a => a.name === step.effect!.isolate ? { ...a, status: 'isolado' as AssetStatus } : a) };
          if (pb && run.step + 1 >= pb.steps.length) {
            next = pushAudit({ ...next, runs: next.runs.map(r => r.id === runId ? { ...r, status: 'concluido' as const } : r) }, 'concluiu playbook com sucesso', pb.name, 'response', `Playbook ${pb.id}`);
          }
          return next;
        });
        sync(srv.approveRun(runId, ROLE_USER[s.role]));
      },

      rejectRun: (runId) => {
        set(p => {
          const run = p.runs.find(r => r.id === runId);
          if (!run) return p;
          return pushAudit(
            { ...p, runs: p.runs.map(r => r.id === runId ? { ...r, status: 'rejeitado' as const } : r) },
            'rejeitou passo — execução abortada', run.pbName, 'response', ROLE_USER[p.role]);
        });
        sync(srv.rejectRun(runId, ROLE_USER[s.role]));
      },
    };
  }, [s, set]);

  return <Ctx.Provider value={api}>{children}</Ctx.Provider>;
}

// ── Security Score ───────────────────────────────────────────
export function securityScore(lists: {
  alerts: Alert[]; incidents: Incident[]; vulns: Vuln[]; assets: Asset[];
}): { score: number; factors: { label: string; delta: number }[] } {
  const openAlerts = lists.alerts.filter(a => !['fechado', 'falso_positivo', 'escalado'].includes(a.status));
  const activeInc = lists.incidents.filter(i => !['resolvido', 'fechado'].includes(i.status));
  const openVulns = lists.vulns.filter(v => !['resolvida', 'aceita'].includes(v.status));
  const nowTs = Date.now();
  const breached = lists.incidents.filter(i => !['resolvido', 'fechado'].includes(i.status) && i.ts + i.slaH * 3_600_000 < nowTs).length;
  const factors = [
    { label: 'Vulnerabilidades críticas abertas', delta: -openVulns.filter(v => v.severity === 'critical').length * 3.4 },
    { label: 'Vulnerabilidades altas abertas', delta: -openVulns.filter(v => v.severity === 'high').length * 1.3 },
    { label: 'Incidentes críticos ativos', delta: -activeInc.filter(i => i.severity === 'critical').length * 6.5 },
    { label: 'Incidentes altos ativos', delta: -activeInc.filter(i => i.severity === 'high').length * 2.8 },
    { label: 'Alertas críticos pendentes', delta: -openAlerts.filter(a => a.severity === 'critical').length * 1.1 },
    { label: 'SLA estourado', delta: -breached * 2.2 },
    { label: 'Cobertura de monitoramento', delta: lists.assets.filter(a => a.status === 'online').length / Math.max(1, lists.assets.length) * 4 },
  ];
  const score = Math.round(Math.max(8, Math.min(98, 96 + factors.reduce((acc, f) => acc + f.delta, 0))));
  return { score, factors };
}

export { ANALYSTS, TENANTS };
