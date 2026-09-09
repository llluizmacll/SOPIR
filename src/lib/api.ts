// ─────────────────────────────────────────────────────────────
// Cliente da sopir-api. Se a API não responde, o frontend
// opera em modo demonstração (simulação local) — zero quebra.
// ─────────────────────────────────────────────────────────────
import type {
  Alert, Asset, AuditEntry, Case, CaseTemplate, Ev, Incident, PlayRun, Tenant, Vuln,
} from '../data/mock';

const env = (import.meta as unknown as { env?: Record<string, string | undefined> }).env;
const BASE = env?.VITE_API_BASE ?? '/api/v1';

const TOKEN_KEY = 'sopir.token';
let token: string | null = typeof localStorage !== 'undefined' ? localStorage.getItem(TOKEN_KEY) : null;
let onUnauthorized: (() => void) | null = null;

export function setToken(t: string | null) {
  token = t;
  if (t) localStorage.setItem(TOKEN_KEY, t);
  else localStorage.removeItem(TOKEN_KEY);
}
export function getToken() { return token; }
export function setUnauthorizedHandler(fn: () => void) { onUnauthorized = fn; }

async function req<T>(method: string, path: string, body?: unknown, timeoutMs = 2500): Promise<T | null> {
  try {
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), timeoutMs);
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (token) headers.Authorization = `Bearer ${token}`;
    const res = await fetch(BASE + path, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: ctl.signal,
    });
    clearTimeout(timer);
    if (res.status === 401 && path !== '/auth/login' && path !== '/auth/me') {
      onUnauthorized?.();
      return null;
    }
    if (!res.ok) return null;
    return (await res.json()) as T;
  } catch {
    return null;
  }
}

export interface BootstrapData {
  tenants: Tenant[];
  orgs?: { id: string; name: string; short: string }[];
  environments?: { id: string; tenant: string; name: string; kind: string }[];
  events: Ev[];
  alerts: Alert[];
  incidents: Incident[];
  cases: Case[];
  vulns: Vuln[];
  assets: Asset[];
  runs: PlayRun[];
  audit: AuditEntry[];
  eps: Record<string, number> | null;
  connectors: { name: string; configured: boolean; status: string; lastError: string | null; collected: number; mode: string | null }[];
}

export const api = {
  ping: () => req<{ ok: boolean }>('GET', '/health', undefined, 1800),
  bootstrap: (tenant: string) =>
    req<BootstrapData>('GET', `/bootstrap?tenant=${encodeURIComponent(tenant)}`, undefined, 6000),

  // alertas
  postAlertFromEvent: (eventId: string) => req<{ id: string }>('POST', '/alerts', { eventId }),
  patchAlert: (id: string, patch: Record<string, unknown>) => req<{ ok: boolean }>('PATCH', `/alerts/${id}`, patch),
  escalateAlert: (id: string, body: { title: string; severity: string }) =>
    req<{ incidentId: string }>('POST', `/alerts/${id}/escalate`, body),

  // incidentes
  postIncident: (body: Record<string, unknown>) => req<{ id: string }>('POST', '/incidents', body),
  patchIncident: (id: string, patch: Record<string, unknown>) => req<{ ok: boolean }>('PATCH', `/incidents/${id}`, patch),
  patchTask: (incId: string, taskId: string, done: boolean) =>
    req<{ ok: boolean }>('PATCH', `/incidents/${incId}/tasks/${taskId}`, { done }),
  openCaseFromIncident: (incId: string) => req<{ caseId: string }>('POST', `/incidents/${incId}/case`),

  // cases (ciclo operacional — fase 9)
  caseTemplates: () => req<CaseTemplate[]>('GET', '/cases/templates', undefined, 3000),
  caseMetrics: (tenant?: string) =>
    req<CaseMetrics>('GET', `/cases/metrics${tenant && tenant !== 'all' ? `?tenant=${encodeURIComponent(tenant)}` : ''}`, undefined, 4000),
  caseDetail: (id: string) => req<Case>('GET', `/cases/${id}`, undefined, 3000),
  postCase: (body: Record<string, unknown>) => req<{ id: string }>('POST', '/cases', body),
  patchCase: (id: string, patch: Record<string, unknown>) => req<{ ok: boolean }>('PATCH', `/cases/${id}`, patch),
  postCaseTask: (caseId: string, text: string) => req<{ id: string }>('POST', `/cases/${caseId}/tasks`, { text }),
  patchCaseTask: (caseId: string, taskId: string, done: boolean) =>
    req<{ ok: boolean }>('PATCH', `/cases/${caseId}/tasks/${taskId}`, { done }),
  deleteCaseTask: (caseId: string, taskId: string) => req<{ ok: boolean }>('DELETE', `/cases/${caseId}/tasks/${taskId}`),
  addCaseRelation: (caseId: string, kind: string, value: string) =>
    req<{ ok: boolean }>('POST', `/cases/${caseId}/relations`, { kind, value }),
  removeCaseRelation: (caseId: string, kind: string, value: string) =>
    req<{ ok: boolean }>('DELETE', `/cases/${caseId}/relations`, { kind, value }),
  postComment: (caseId: string, text: string, author: string) =>
    req<{ ok: boolean }>('POST', `/cases/${caseId}/comments`, { text, author }),

  // vulnerabilidades / ativos
  patchVuln: (id: string, status: string) => req<{ ok: boolean }>('PATCH', `/vulnerabilities/${id}`, { status }),
  patchAsset: (name: string, status: string) => req<{ ok: boolean }>('PATCH', `/assets/${encodeURIComponent(name)}/status`, { status }),

  // response engine
  startRun: (pbId: string, actor: string) => req<{ id: string }>('POST', `/playbooks/${pbId}/run`, { actor }),
  approveRun: (id: string, actor: string) => req<{ ok: boolean }>('POST', `/runs/${id}/approve`, { actor }),
  rejectRun: (id: string, actor: string) => req<{ ok: boolean }>('POST', `/runs/${id}/reject`, { actor }),

  // autenticação JWT
  login: (username: string, password: string) =>
    req<LoginResult>('POST', '/auth/login', { username, password }, 5000),
  me: () => req<{ user: AuthUser }>('GET', '/auth/me', undefined, 3000),

  // MFA / sessões / recuperação / SSO
  mfaSetup: (mfaToken?: string) =>
    req<{ secret: string; otpauth: string }>('POST', '/auth/mfa/setup', mfaToken ? { mfaToken } : {}, 4000),
  mfaEnable: (code: string, mfaToken?: string) =>
    req<LoginResult & { ok: boolean; recoveryCodes?: string[] }>('POST', '/auth/mfa/enable', { code, ...(mfaToken ? { mfaToken } : {}) }, 4000),
  mfaDisable: (code: string) => req<{ ok: boolean; error?: string }>('POST', '/auth/mfa/disable', { code }),
  mfaVerify: (mfaToken: string, code: string) =>
    req<LoginResult>('POST', '/auth/mfa/verify', { mfaToken, code }, 5000),
  resetUserMfa: (username: string) => req<{ ok: boolean; error?: string }>('POST', '/auth/mfa/reset', { username }),
  regenRecoveryCodes: () => req<{ codes: string[] }>('GET', '/auth/recovery-codes/regen', undefined, 4000),
  sessions: () => req<SessionInfo[]>('GET', '/auth/sessions', undefined, 4000),
  revokeSession: (sid: string) => req<{ ok: boolean }>('DELETE', `/auth/sessions/${encodeURIComponent(sid)}`),
  revokeOtherSessions: () => req<{ ok: boolean; revoked: number }>('POST', '/auth/sessions/revoke-others'),
  forgot: (username: string) => req<{ ok: boolean; devToken?: string }>('POST', '/auth/forgot', { username }, 5000),
  resetToken: (token: string, password: string) =>
    req<{ ok: boolean; error?: string }>('POST', '/auth/reset', { token, password }, 5000),
  ssoProviders: () => req<SsoProviderPublic[]>('GET', '/auth/sso/providers', undefined, 3000),

  // administração de identidade (SSO + políticas)
  identitySettings: () => req<IdentitySettings>('GET', '/admin/identity/settings', undefined, 4000),
  patchIdentitySettings: (b: Partial<IdentitySettings>) =>
    req<IdentitySettings>('PATCH', '/admin/identity/settings', b),
  idpProviders: () => req<IdpProvider[]>('GET', '/admin/identity/providers', undefined, 4000),
  createIdp: (b: Record<string, unknown>) => req<{ ok: boolean; code?: string; error?: string }>('POST', '/admin/identity/providers', b),
  patchIdp: (code: string, b: Record<string, unknown>) =>
    req<{ ok: boolean; error?: string }>('PATCH', `/admin/identity/providers/${encodeURIComponent(code)}`, b),
  deleteIdp: (code: string) => req<{ ok: boolean; error?: string }>('DELETE', `/admin/identity/providers/${encodeURIComponent(code)}`),
  testIdp: (issuer: string) => req<DiscoveryInfo>('POST', '/admin/identity/providers/test', { issuer }, 10000),

  // motor de correlação
  correlations: () => req<CorrPolicy[]>('GET', '/correlations', undefined, 3000),
  toggleCorrelation: (id: string, enabled: boolean) =>
    req<CorrPolicy>('PATCH', `/correlations/${id}`, { enabled }),
  createCorrelation: (b: CorrPolicyInput) => req<{ code: string }>('POST', '/correlations', b),
  updateCorrelation: (id: string, b: Partial<CorrPolicyInput>) =>
    req<{ ok: boolean; error?: string }>('PUT', `/correlations/${encodeURIComponent(id)}`, b),
  deleteCorrelation: (id: string) =>
    req<{ ok: boolean; error?: string }>('DELETE', `/correlations/${encodeURIComponent(id)}`),
  backtest: (b: CorrPolicyInput) => req<BacktestResult>('POST', '/correlations/backtest', b),
  riskScores: (type: string, tenant?: string) =>
    req<RiskScore[]>('GET', `/risk/scores?type=${encodeURIComponent(type)}${tenant && tenant !== 'all' ? `&tenant=${encodeURIComponent(tenant)}` : ''}`, undefined, 4000),
  aggregate: (by: string, hours: number, tenant?: string) =>
    req<AggRow[]>('GET', `/events/aggregate?by=${encodeURIComponent(by)}&hours=${hours}${tenant && tenant !== 'all' ? `&tenant=${encodeURIComponent(tenant)}` : ''}`, undefined, 4000),

  // ── SLA & performance (Incident Management) ──
  slaPolicies: (tenant: string) =>
    req<SlaPolicy[]>('GET', `/sla/policies?tenant=${encodeURIComponent(tenant)}`, undefined, 3000),
  updateSlaPolicy: (tenant: string, severity: string, responseMin: number, resolutionMin: number) =>
    req<{ ok: boolean; error?: string }>('PUT', '/sla/policies', { tenant, severity, responseMin, resolutionMin }),
  slaMetrics: (tenant?: string) =>
    req<SlaMetrics>('GET', `/sla/metrics${tenant && tenant !== 'all' ? `?tenant=${encodeURIComponent(tenant)}` : ''}`, undefined, 4000),

  // Investigation Graph
  graphExpand: (type: string, value: string, tenant: string) =>
    req<ApiGraph>('GET', `/graph/expand?type=${encodeURIComponent(type)}&value=${encodeURIComponent(value)}&tenant=${encodeURIComponent(tenant)}`, undefined, 4000),
  investigations: () => req<SavedInvestigation[]>('GET', '/investigations', undefined, 3000),
  saveInvestigation: (body: { name: string; rootType: string; rootValue: string; graph: unknown; tenant: string }) =>
    req<{ id: string }>('POST', '/investigations', body),
  patchInvestigation: (id: string, body: { status?: string; graph?: unknown }) =>
    req<{ ok: boolean }>('PATCH', `/investigations/${id}`, body),

  // ── administração (usuários, perfis, clientes) ──
  users: () => req<AdminUser[]>('GET', '/admin/users', undefined, 4000),
  createUser: (b: Record<string, unknown>) => req<{ ok: boolean; error?: string }>('POST', '/admin/users', b),
  updateUser: (u: string, b: Record<string, unknown>) =>
    req<{ ok: boolean; error?: string }>('PATCH', `/admin/users/${encodeURIComponent(u)}`, b),
  resetPassword: (u: string, password: string) =>
    req<{ ok: boolean; error?: string }>('POST', `/admin/users/${encodeURIComponent(u)}/password`, { password }),
  deleteUser: (u: string) => req<{ ok: boolean; error?: string }>('DELETE', `/admin/users/${encodeURIComponent(u)}`),
  adminResetMfa: (u: string) => req<{ ok: boolean; error?: string }>('POST', `/admin/users/${encodeURIComponent(u)}/reset-mfa`),

  roles: () => req<AdminRole[]>('GET', '/admin/roles', undefined, 4000),
  createRole: (b: Record<string, unknown>) => req<{ ok: boolean; error?: string }>('POST', '/admin/roles', b),
  updateRole: (n: string, b: Record<string, unknown>) =>
    req<{ ok: boolean; error?: string }>('PATCH', `/admin/roles/${encodeURIComponent(n)}`, b),
  deleteRole: (n: string) => req<{ ok: boolean; error?: string }>('DELETE', `/admin/roles/${encodeURIComponent(n)}`),

  tenants: () => req<AdminTenant[]>('GET', '/admin/tenants', undefined, 4000),
  createTenant: (b: Record<string, unknown>) => req<{ ok: boolean; error?: string }>('POST', '/admin/tenants', b),
  updateTenant: (id: string, b: Record<string, unknown>) =>
    req<{ ok: boolean; error?: string }>('PATCH', `/admin/tenants/${encodeURIComponent(id)}`, b),
  deleteTenant: (id: string) => req<{ ok: boolean; error?: string }>('DELETE', `/admin/tenants/${encodeURIComponent(id)}`),
  patchTenantStatus: (id: string, active: boolean) =>
    req<{ ok: boolean; error?: string }>('PATCH', `/admin/tenants/${encodeURIComponent(id)}/status`, { active }),

  // ── multi-tenancy (organizações, ambientes, onboarding, isolamento) ──
  orgs: () => req<Org[]>('GET', '/admin/orgs', undefined, 4000),
  createOrg: (b: { name: string; short?: string }) => req<{ ok: boolean; id?: string; error?: string }>('POST', '/admin/orgs', b),
  deleteOrg: (id: string) => req<{ ok: boolean; error?: string }>('DELETE', `/admin/orgs/${encodeURIComponent(id)}`),
  environments: (tenant: string) => req<Environment[]>('GET', `/admin/tenants/${encodeURIComponent(tenant)}/environments`, undefined, 3000),
  createEnvironment: (tenant: string, b: { name: string; kind?: string }) =>
    req<{ ok: boolean; id?: string; error?: string }>('POST', `/admin/tenants/${encodeURIComponent(tenant)}/environments`, b),
  deleteEnvironment: (code: string) => req<{ ok: boolean; error?: string }>('DELETE', `/admin/environments/${encodeURIComponent(code)}`),
  onboard: (b: Record<string, unknown>) =>
    req<{ ok: boolean; id?: string; environment?: string; portalUser?: string; error?: string }>('POST', '/admin/onboard', b, 8000),
  isolationMatrix: () => req<IsolationRow[]>('GET', '/admin/isolation', undefined, 6000),

  // ── integrações (connectors por cliente) ──
  connectorTypes: () => req<ConnectorType[]>('GET', '/admin/connectors/types', undefined, 3000),
  connectors: () => req<ConnectorConfig[]>('GET', '/admin/connectors', undefined, 4000),
  createConnector: (b: Record<string, unknown>) => req<{ ok: boolean; code?: string; error?: string }>('POST', '/admin/connectors', b),
  updateConnector: (code: string, b: Record<string, unknown>) =>
    req<{ ok: boolean; error?: string }>('PATCH', `/admin/connectors/${encodeURIComponent(code)}`, b),
  deleteConnector: (code: string) => req<{ ok: boolean; error?: string }>('DELETE', `/admin/connectors/${encodeURIComponent(code)}`),
  testConnector: (b: { type: string; settings: Record<string, unknown> }) =>
    req<{ ok: boolean; message: string }>('POST', '/admin/connectors/test', b, 12000),
  testConnectorSaved: (code: string) =>
    req<{ ok: boolean; message: string }>('POST', `/admin/connectors/${encodeURIComponent(code)}/test`, undefined, 12000),
  connectorStatus: () =>
    req<{ epsBySource: Record<string, number>; connectors: ConnectorState[] }>('GET', '/connectors', undefined, 3000),

  // ── event management (ingestão + supressão) ──
  ingestStats: () => req<IngestStats>('GET', '/ingest/stats', undefined, 3000),
  ingestTest: (event: Record<string, unknown>) =>
    req<IngestTestResult>('POST', '/ingest/test', { event }, 6000),
  suppressionRules: () => req<SuppressionRule[]>('GET', '/alerts/suppression', undefined, 3000),
  createSuppression: (b: Record<string, unknown>) =>
    req<{ id?: number; error?: string }>('POST', '/alerts/suppression', b),
  deleteSuppression: (id: number) =>
    req<{ ok?: boolean; error?: string }>('DELETE', `/alerts/suppression/${id}`),
  toggleSuppression: (id: number, enabled: boolean) =>
    req<{ ok?: boolean; error?: string }>('PATCH', `/alerts/suppression/${id}`, { enabled }),

  // ── auditoria & compliance ──
  auditQuery: (params: Record<string, string | number | undefined>) => {
    const qs = new URLSearchParams();
    for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== '') qs.set(k, String(v));
    const s = qs.toString();
    return req<AuditEntry[]>('GET', `/audit${s ? '?' + s : ''}`, undefined, 5000);
  },
  verifyAudit: () => req<AuditVerify>('GET', '/audit/verify', undefined, 8000),
  auditCompliance: () => req<AuditCompliance>('GET', '/audit/compliance', undefined, 6000),
};

export interface ConnectorTypeField { key: string; label: string; placeholder: string; type: string }
export interface ConnectorType { id: string; label: string; push: boolean; fields: ConnectorTypeField[] }
export interface ConnectorConfig {
  code: string; name: string; type: string;
  tenant: string; tenantName: string | null;
  settings: Record<string, unknown>; enabled: boolean; pollSeconds: number; push: boolean;
}
export interface ConnectorState {
  key: string; name: string; type: string; tenant: string;
  configured: boolean; push: boolean;
  status: string; lastOk: number | null; lastError: string | null;
  collected: number; lastTs: number | null;
}

export interface ApiGraph {
  nodes: { id: string; type: string; value: string; sub?: string }[];
  edges: { id: string; source: string; target: string; label: string }[];
}
export interface SavedInvestigation {
  id: string; tenant: string; name: string; rootType: string; rootValue: string;
  graph: { nodes: { id: string; type: string; value: string; sub?: string }[]; edges: { id: string; source: string; target: string; label: string }[] };
  status: string; ts: number; owner: string;
}

export interface AuthUser {
  username: string;
  name: string;
  role: string;
  tenant: string | null;
  permissions?: string[];
  mfaEnabled?: boolean;
}

export interface LoginResult {
  token?: string;
  user?: AuthUser;
  mfaRequired?: boolean;
  mustEnroll?: boolean;
  mfaToken?: string;
  error?: string;
}

export interface SessionInfo {
  id: string; ip: string | null; ua: string | null;
  created: number; expires: number; lastSeen: number | null;
  revoked: number | null; current?: boolean;
}

export interface IdentitySettings {
  session_ttl_hours: number;
  min_password_length: number;
  mfa_required_roles: string[];
  sso_enabled: boolean;
  sso_auto_provision: boolean;
}

export interface IdpProvider {
  code: string; name: string; type: string; issuer: string;
  clientId: string; autoProvision: boolean; defaultRole: string;
  enabled: boolean; created: number | null;
}

export interface DiscoveryInfo {
  ok: boolean; message: string;
  endpoints?: { authorization: string; token: string; userinfo: string | null; jwks: string | null };
}

export interface SsoProviderPublic { code: string; name: string; type: string }

export interface AdminUser {
  username: string; name: string; role: string;
  tenant: string | null; tenantName: string | null;
  active: boolean; lastLogin: number | null;
  mfaEnabled?: boolean;
}
export interface AdminRole {
  name: string; display: string; description: string;
  permissions: string[]; builtin: boolean; users: number;
}
export interface Org {
  id: string; name: string; short: string;
  tenants: { id: string; name: string; short: string }[];
}

export interface Environment {
  id: string; tenant: string; name: string; kind: string; created: number | null;
}

export interface IsolationRow {
  tenant: string; tenantName: string;
  cells: { table: string; label: string; count: number }[];
}

export interface AuditVerify {
  ok: boolean; total: number; verified: number; legacy: number;
  firstBad: string | null; tip: string | null;
}
export interface IngestStats {
  recent: Ev[]; epsBySource: Record<string, number>;
  pipeline: { normalized: number; deduped: number; autoAlerts: number; correlations: number; suppressed: number; uptimeSec: number };
}
export interface IngestTestResult {
  accepted: boolean; code: string | null; severity: string;
  alertCreated: string | null; correlationsFired: number; note: string;
}
export interface SuppressionRule {
  id: number; ruleId: string | null; host: string | null; srcIp: string | null;
  reason: string; tenant: string | null; enabled: boolean;
  expiresAt: number; createdAt: number;
}
export interface AuditCompliance {
  controls: { control: string; n: number }[];
  perDay: number[];
  signals: { id: string; label: string; count: number; severity: 'low' | 'medium' | 'high' }[];
}

export interface AdminTenant {
  id: string; name: string; short: string; contact: string | null;
  orgId: string | null; orgName: string | null;
  brandColor: string | null; tagline: string | null;
  quotas: { maxUsers: number | null; maxAssets: number | null; maxConnectors: number | null };
  created: number | null; assets: number; alerts: number;
  incidents: number; users: number; vulns: number; connectors: number;
  environments: { id: string; name: string; kind: string }[];
  active: boolean;
}

export interface CorrPolicy {
  id: string;
  name: string;
  severity: string;
  windowSec: number;
  threshold: number;
  groupBy: string[];
  groupByLabel: string;
  logic: string;
  mitre: string | null;
  mode: string | null;
  matchDef: Record<string, unknown> | null;
  builtin: boolean;
  enabled: boolean;
  fires: number;
  lastFire: number | null;
}
export interface CorrPolicyInput {
  name: string; description?: string; severity: string;
  windowSec: number; threshold: number; groupBy: string[];
  match?: Record<string, unknown>; mode?: string; mitre?: string;
}
export interface BacktestResult {
  policy: string; windowSec: number; threshold: number;
  evaluated: number; firedCount: number;
  fired: { title: string; count: number; key: Record<string, string> }[];
}
export interface RiskScore {
  entity: string; score: number;
  factors: { eventos24h: number; alertasAbertos: number; incidentes: number; vulnsCriticas: number };
  detail: { criticalEvents: number; highEvents: number; openAlerts: number; activeIncidents: number; criticalVulns: number };
}
export interface CaseMetrics {
  total: number; open: number; closed: number; onHold: number;
  slaCompliance: number; avgCloseHours: number | null;
  activeBreaches: { code: string; severity: string; stage: string; overMin: number }[];
  byStage: Record<string, number>; bySeverity: Record<string, number>; byAssignee: Record<string, number>;
}
export interface SlaPolicy {
  tenant: string; severity: string; responseMin: number; resolutionMin: number;
}
export interface SlaMetrics {
  compliance: { response: number; resolution: number };
  mttr: { responseMin: number | null; resolutionMin: number | null };
  total: number;
  activeBreaches: { code: string; severity: string; status: string; overMin: number }[];
  bySeverity: Record<string, { total: number; respBreached: number; resBreached: number }>;
}
export interface AggRow {
  entity: string; total: number;
  critical: number; high: number; medium: number; low: number;
  firstTs: number; lastTs: number;
}
