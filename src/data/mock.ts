// ─────────────────────────────────────────────────────────────
// SOPIR — modelo de dados normalizado + seeds + gerador de fluxo
// ─────────────────────────────────────────────────────────────

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type AlertStatus = 'novo' | 'reconhecido' | 'investigando' | 'escalado' | 'falso_positivo' | 'fechado';
export type IncStatus = 'aberto' | 'investigacao' | 'contido' | 'erradicado' | 'resolvido' | 'fechado';
export type CaseStage = 'Triagem' | 'Investigação' | 'Contenção' | 'Recuperação' | 'Encerrado';
export type VulnStatus = 'aberta' | 'confirmada' | 'em_correcao' | 'mitigada' | 'resolvida' | 'aceita';
export type AssetType = 'servidor' | 'endpoint' | 'firewall' | 'switch' | 'ap' | 'vm' | 'container';
export type AssetStatus = 'online' | 'offline' | 'isolado';
export type AuditKind = 'auth' | 'triage' | 'response' | 'data' | 'system';

export interface Tenant { id: string; name: string; short: string }
export interface Ev {
  id: string; ts: number; tenant: string; env?: string | null; source: string;
  rule: string; ruleId: string; severity: Severity;
  srcIp: string; dstIp: string; user: string; host: string; agent: string;
  desc: string; raw: string;
}
export interface Alert {
  id: string; tenant: string; env?: string | null; title: string; severity: Severity; status: AlertStatus;
  source: string; rule: string; ruleId: string; srcIp: string; dstIp: string;
  user: string; host: string; ts: number; desc: string;
  assignee?: string; classification?: string; incidentId?: string;
}
export interface TimelineEntry { ts: number; text: string; kind: 'system' | 'user' | 'action'; author?: string }
export interface Task { id: string; text: string; done: boolean }
export type Priority = 'P1' | 'P2' | 'P3' | 'P4';
export interface IncidentSlaSide {
  targetMin: number; elapsedMin: number; leftMs: number; breached: boolean;
  at: number | null; actualMin: number | null; pct: number;
}
export interface IncidentSla {
  severity: Severity;
  response: IncidentSlaSide; resolution: IncidentSlaSide;
  firstResponseAt: number | null; resolvedAt: number | null;
}
export interface Incident {
  id: string; tenant: string; title: string; severity: Severity; status: IncStatus;
  assignee: string; ts: number; slaH: number; alertIds: string[]; caseId?: string;
  iocs: string[]; tasks: Task[]; timeline: TimelineEntry[]; asset?: string;
  priority?: Priority; firstResponseAt?: number | null; resolvedAt?: number | null;
  sla?: IncidentSla | null;
}
export interface CaseComment { ts: number; author: string; text: string }
export interface CaseTask { id: string; text: string; done: boolean }
export interface CaseTimelineEntry { ts: number; text: string; kind: 'system' | 'stage' | 'relation' | 'user'; author?: string }
export interface Case {
  id: string; tenant: string; title: string; severity: Severity; stage: CaseStage;
  assignee: string; ts: number; alertIds: string[]; incidentIds: string[];
  assetNames: string[]; iocs: string[]; evidence: string[]; comments: CaseComment[];
  // ciclo operacional (fase 9)
  priority?: Priority; status?: 'active' | 'on_hold' | 'closed';
  openedAt?: number; closedAt?: number | null;
  slaMin?: number; slaBreached?: boolean;
  stageDurations?: Record<string, number> | null;
  tasks?: CaseTask[]; timeline?: CaseTimelineEntry[];
}
export interface CaseTemplate { id: string; name: string; severity: Severity; tasks: string[] }
export interface Vuln {
  id: string; cve: string; tenant: string; env?: string | null; title: string; cvss: number; severity: Severity;
  asset: string; status: VulnStatus; found: number; fix: string;
}
export interface Asset {
  id: string; tenant: string; env?: string | null; name: string; type: AssetType; ip: string; os: string;
  crit: number; status: AssetStatus; owner: string;
}
export interface PlayStep { id: string; label: string; desc?: string; approval?: boolean; effect?: { isolate?: string; block?: string } }
export interface Playbook { id: string; name: string; trigger: string; severity: Severity; steps: PlayStep[] }
export interface PlayRun {
  id: string; pbId: string; pbName: string; step: number;
  status: 'andamento' | 'aprovacao' | 'concluido' | 'rejeitado';
  ts: number; tenant: string; actor: string;
}
export interface AuditEntry {
  id: string; ts: number; actor: string; action: string; target: string; kind: AuditKind;
  tenant?: string | null; ip?: string | null; ua?: string | null; sid?: string | null;
  outcome?: 'ok' | 'denied'; before?: Record<string, unknown> | null; after?: Record<string, unknown> | null;
  control?: string | null; hash?: string | null; prevHash?: string | null; tsMs?: number;
}

// ── metadados ────────────────────────────────────────────────
export const SEV_META: Record<Severity, { label: string; color: string; level: number }> = {
  critical: { label: 'Crítico', color: '#ff4d5e', level: 14 },
  high:     { label: 'Alto',    color: '#ff9142', level: 11 },
  medium:   { label: 'Médio',   color: '#ffc53d', level: 7 },
  low:      { label: 'Baixo',   color: '#5aa2ff', level: 4 },
  info:     { label: 'Info',    color: '#8fa3c8', level: 2 },
};
export const SEV_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
export const SLA_HOURS: Record<Severity, number> = { critical: 4, high: 8, medium: 24, low: 48, info: 72 };

export const PRIORITY_META: Record<Priority, { label: string; color: string; desc: string }> = {
  P1: { label: 'P1', color: '#ff4d5e', desc: 'Crítico — parada total / comprometimento ativo' },
  P2: { label: 'P2', color: '#ff9142', desc: 'Alto — impacto significativo em curso' },
  P3: { label: 'P3', color: '#ffc53d', desc: 'Médio — impacto parcial / sem propagação' },
  P4: { label: 'P4', color: '#5aa2ff', desc: 'Baixo — sem impacto operacional' },
};
export const PRIORITY_ORDER: Priority[] = ['P1', 'P2', 'P3', 'P4'];
export const sevToPriority = (sev: Severity): Priority =>
  sev === 'critical' ? 'P1' : sev === 'high' ? 'P2' : sev === 'medium' ? 'P3' : 'P4';

/** Política de SLA do modo demonstração (minutos): resposta / resolução. */
export const SLA_POLICY_DEMO: Record<Severity, { responseMin: number; resolutionMin: number }> = {
  critical: { responseMin: 15, resolutionMin: 240 },
  high: { responseMin: 30, resolutionMin: 480 },
  medium: { responseMin: 60, resolutionMin: 1440 },
  low: { responseMin: 120, resolutionMin: 2880 },
  info: { responseMin: 240, resolutionMin: 4320 },
};

export const ALERT_STATUS_META: Record<AlertStatus, { label: string; color: string }> = {
  novo:           { label: 'Novo',           color: '#ff4d5e' },
  reconhecido:    { label: 'Reconhecido',    color: '#56c4ff' },
  investigando:   { label: 'Em investigação', color: '#ffc53d' },
  escalado:       { label: 'Escalado → INC', color: '#ff9142' },
  falso_positivo: { label: 'Falso positivo', color: '#8fa3c8' },
  fechado:        { label: 'Fechado',        color: '#2fd6a5' },
};
export const INC_STATUS_META: Record<IncStatus, { label: string; color: string }> = {
  aberto:      { label: 'Aberto',        color: '#ff4d5e' },
  investigacao:{ label: 'Investigação',  color: '#ffc53d' },
  contido:     { label: 'Contido',       color: '#56c4ff' },
  erradicado:  { label: 'Erradicado',    color: '#5aa2ff' },
  resolvido:   { label: 'Resolvido',     color: '#2fd6a5' },
  fechado:     { label: 'Fechado',       color: '#8fa3c8' },
};
export const INC_FLOW: IncStatus[] = ['aberto', 'investigacao', 'contido', 'erradicado', 'resolvido', 'fechado'];
export const VULN_STATUS_META: Record<VulnStatus, { label: string; color: string }> = {
  aberta:      { label: 'Aberta',        color: '#ff4d5e' },
  confirmada:  { label: 'Confirmada',    color: '#ff9142' },
  em_correcao: { label: 'Em correção',   color: '#ffc53d' },
  mitigada:    { label: 'Mitigada',      color: '#56c4ff' },
  resolvida:   { label: 'Resolvida',     color: '#2fd6a5' },
  aceita:      { label: 'Risco aceito',  color: '#8fa3c8' },
};
export const CASE_STAGES: CaseStage[] = ['Triagem', 'Investigação', 'Contenção', 'Recuperação', 'Encerrado'];

export const CASE_STATUS_META: Record<'active' | 'on_hold' | 'closed', { label: string; color: string }> = {
  active: { label: 'Ativo', color: '#2fd6a5' },
  on_hold: { label: 'Em espera', color: '#ffc53d' },
  closed: { label: 'Encerrado', color: '#8fa3c8' },
};

/** SLA de case (minutos até fechamento) por severidade — modo demo. */
export const CASE_SLA_MIN_DEMO: Record<Severity, number> = {
  critical: 480, high: 1440, medium: 4320, low: 10080, info: 20160,
};

export const CASE_TEMPLATES_DEMO: CaseTemplate[] = [
  { id: 'incident', name: 'Incidente de Segurança', severity: 'high', tasks: ['Confirmar escopo e impacto', 'Coletar e preservar evidências', 'Executar contenção inicial', 'Erradicar causa raiz', 'Recuperar ativos', 'Lições aprendidas'] },
  { id: 'vuln', name: 'Remediação de Vulnerabilidade', severity: 'medium', tasks: ['Validar finding e ativo', 'Classificar risco', 'Definir plano de correção', 'Aplicar patch', 'Re-escanear'] },
  { id: 'phishing', name: 'Campanha de Phishing', severity: 'medium', tasks: ['Analisar e-mail', 'Extrair IOCs', 'Verificar cliques', 'Remover e-mail', 'Bloquear IOCs'] },
  { id: 'malware', name: 'Infecção por Malware', severity: 'high', tasks: ['Isolar endpoint', 'Identificar vetor', 'Coletar amostra', 'Varredura completa', 'Reimagem'] },
];

/** Preenche os campos do ciclo operacional ausentes (seeds e dados antigos da API). */
export function normalizeCase(c: Case): Case {
  const now = Date.now();
  const slaMin = c.slaMin ?? CASE_SLA_MIN_DEMO[c.severity] ?? 4320;
  const status = c.status ?? (c.stage === 'Encerrado' ? 'closed' : 'active');
  const openedAt = c.openedAt ?? c.ts;
  const closedAt = c.closedAt ?? (status === 'closed' ? c.ts + Math.round(slaMin * 0.6) * 60_000 : null);
  return {
    ...c,
    priority: c.priority ?? sevToPriority(c.severity),
    status,
    openedAt,
    closedAt,
    slaMin,
    slaBreached: c.slaBreached ?? (status !== 'closed' && now - openedAt > slaMin * 60_000),
    tasks: c.tasks ?? [],
    timeline: c.timeline ?? [{ ts: c.ts, text: 'Case criado', kind: 'system' as const }],
    stageDurations: c.stageDurations ?? null,
  };
}

export const TENANTS: Tenant[] = [
  { id: 'vetra',     name: 'Grupo Vetra S.A.',  short: 'VET' },
  { id: 'atlantico', name: 'Banco Atlântico',   short: 'ATL' },
  { id: 'medcore',   name: 'Hospital Medcore',  short: 'MED' },
];
export const ANALYSTS = ['Luiz Almeida', 'Ana Ribeiro', 'Carlos Mendes', 'Marina Sousa'];

export const ASSET_TYPE_META: Record<AssetType, { label: string; icon: string }> = {
  servidor:  { label: 'Servidor',  icon: 'server' },
  endpoint:  { label: 'Endpoint',  icon: 'monitor' },
  firewall:  { label: 'Firewall',  icon: 'shield' },
  switch:    { label: 'Switch',    icon: 'network' },
  ap:        { label: 'Access Point', icon: 'wifi' },
  vm:        { label: 'Máquina Virtual', icon: 'cpu' },
  container: { label: 'Container', icon: 'box' },
};

// ── seeds ────────────────────────────────────────────────────
const now = Date.now();
const m = (min: number) => now - min * 60_000;
const h = (hrs: number) => now - hrs * 3_600_000;
const d = (days: number) => now - days * 86_400_000;

export const SEED_ASSETS: Asset[] = [
  { id: 'as01', tenant: 'vetra', name: 'SRV-DC01',     type: 'servidor',  ip: '10.0.1.10',  os: 'Windows Server 2022', crit: 96, status: 'online',  owner: 'Infraestrutura' },
  { id: 'as02', tenant: 'vetra', name: 'SRV-DB01',     type: 'servidor',  ip: '10.0.1.20',  os: 'RHEL 9',              crit: 92, status: 'online',  owner: 'Dados' },
  { id: 'as03', tenant: 'vetra', name: 'SRV-APP02',    type: 'servidor',  ip: '10.0.1.32',  os: 'Ubuntu 22.04',        crit: 78, status: 'online',  owner: 'Aplicações' },
  { id: 'as04', tenant: 'vetra', name: 'WS-FIN-014',   type: 'endpoint',  ip: '10.0.4.18',  os: 'Windows 11',          crit: 85, status: 'isolado', owner: 'Financeiro' },
  { id: 'as05', tenant: 'vetra', name: 'WS-RH-022',    type: 'endpoint',  ip: '10.0.4.55',  os: 'Windows 11',          crit: 55, status: 'online',  owner: 'RH' },
  { id: 'as06', tenant: 'vetra', name: 'FW-MATRIZ',    type: 'firewall',  ip: '10.0.0.1',   os: 'FortiOS 7.4',         crit: 99, status: 'online',  owner: 'Redes' },
  { id: 'as07', tenant: 'vetra', name: 'SW-CORE-01',   type: 'switch',    ip: '10.0.0.11',  os: 'NX-OS 10.3',          crit: 88, status: 'online',  owner: 'Redes' },
  { id: 'as08', tenant: 'vetra', name: 'AP-ANDAR3',    type: 'ap',        ip: '10.0.0.53',  os: 'FortiAP 4.3',         crit: 40, status: 'online',  owner: 'Redes' },
  { id: 'as09', tenant: 'vetra', name: 'VM-K8S-01',    type: 'vm',        ip: '10.0.8.11',  os: 'Debian 12',           crit: 70, status: 'online',  owner: 'Engenharia' },
  { id: 'as10', tenant: 'vetra', name: 'CTR-NFS-02',   type: 'container', ip: '10.0.8.34',  os: 'Alpine 3.19',         crit: 48, status: 'online',  owner: 'Engenharia' },
  { id: 'as11', tenant: 'atlantico', name: 'SRV-CORE-BK', type: 'servidor', ip: '10.2.1.15', os: 'AIX 7.3',           crit: 98, status: 'online',  owner: 'Core Bancário' },
  { id: 'as12', tenant: 'atlantico', name: 'SRV-PIX-01',  type: 'servidor', ip: '10.2.1.40', os: 'RHEL 8',            crit: 94, status: 'online',  owner: 'Pagamentos' },
  { id: 'as13', tenant: 'atlantico', name: 'WS-TES-007',  type: 'endpoint', ip: '10.2.5.21', os: 'Windows 11',        crit: 75, status: 'online',  owner: 'Tesouraria' },
  { id: 'as14', tenant: 'atlantico', name: 'FW-AGENCIA',  type: 'firewall', ip: '10.2.0.1',  os: 'FortiOS 7.2',       crit: 95, status: 'online',  owner: 'Redes' },
  { id: 'as15', tenant: 'medcore', name: 'SRV-PACS-01',   type: 'servidor', ip: '10.3.1.12', os: 'Windows Server 2019', crit: 90, status: 'online', owner: 'Imagem' },
  { id: 'as16', tenant: 'medcore', name: 'WS-TRIAGE-03',  type: 'endpoint', ip: '10.3.6.30', os: 'Windows 10',        crit: 60, status: 'offline', owner: 'Emergência' },
  { id: 'as17', tenant: 'medcore', name: 'FW-HOSP',       type: 'firewall', ip: '10.3.0.1',  os: 'FortiOS 7.4',       crit: 96, status: 'online',  owner: 'TI' },
];

export const SEED_ALERTS: Alert[] = [
  { id: 'ALT-3128', tenant: 'vetra', title: 'Ransomware: modificação em massa de arquivos', severity: 'critical', status: 'investigando', source: 'Wazuh', rule: 'Mass file modification detected', ruleId: '5551', srcIp: '10.0.4.18', dstIp: '10.0.1.20', user: 'j.pereira', host: 'WS-FIN-014', ts: m(12), desc: 'Mais de 4.000 arquivos alterados em 90s no share financeiro. Assinatura compatível com LockBit 3.0.', assignee: 'Luiz Almeida', incidentId: 'INC-2041' },
  { id: 'ALT-3127', tenant: 'vetra', title: 'Conexão de saída para IP malicioso (C2)', severity: 'critical', status: 'reconhecido', source: 'FortiSIEM', rule: 'Outbound connection to known malicious IP', ruleId: '100201', srcIp: '10.0.4.18', dstIp: '45.155.205.86', user: 'j.pereira', host: 'WS-FIN-014', ts: m(18), desc: 'Beaconing de saída para IP listado em threat intel (APT29 infrastructure).', assignee: 'Luiz Almeida' },
  { id: 'ALT-3126', tenant: 'atlantico', title: 'Exfiltração suspeita via DNS tunneling', severity: 'critical', status: 'novo', source: 'FortiSIEM', rule: 'DNS tunneling heuristic', ruleId: '100240', srcIp: '10.2.1.40', dstIp: '91.240.118.172', user: 'svc.pix', host: 'SRV-PIX-01', ts: m(26), desc: 'Volume anômalo de consultas TXT com entropia elevada para domínio recém-registrado.', assignee: undefined },
  { id: 'ALT-3125', tenant: 'vetra', title: 'Brute force RDP — 214 tentativas', severity: 'high', status: 'escalado', source: 'Wazuh', rule: 'RDP brute force attempt', ruleId: '100215', srcIp: '185.220.101.34', dstIp: '10.0.1.32', user: 'administrator', host: 'SRV-APP02', ts: m(41), desc: '214 tentativas de login RDP em 5 minutos a partir de IP Tor exit node.', assignee: 'Carlos Mendes', incidentId: 'INC-2040' },
  { id: 'ALT-3124', tenant: 'vetra', title: 'Execução de PowerShell com comando encodado', severity: 'high', status: 'investigando', source: 'Wazuh', rule: 'Suspicious encoded PowerShell', ruleId: '100220', srcIp: '10.0.4.55', dstIp: '10.0.1.10', user: 'marina.sousa', host: 'WS-RH-022', ts: h(1.2), desc: 'powershell -enc com payload de download cradle apontando para domínio suspeito.', assignee: 'Ana Ribeiro' },
  { id: 'ALT-3123', tenant: 'medcore', title: 'Acesso fora de horário ao SRV-PACS-01', severity: 'medium', status: 'novo', source: 'Wazuh', rule: 'Off-hours admin access', ruleId: '100310', srcIp: '10.3.6.30', dstIp: '10.3.1.12', user: 'admin', host: 'SRV-PACS-01', ts: h(2), desc: 'Login administrativo às 03:12 em servidor de imagens médicas.' },
  { id: 'ALT-3122', tenant: 'atlantico', title: 'Múltiplas falhas de autenticação no core', severity: 'high', status: 'reconhecido', source: 'Wazuh', rule: 'Multiple authentication failures', ruleId: '5720', srcIp: '10.2.5.21', dstIp: '10.2.1.15', user: 'op.mesa', host: 'SRV-CORE-BK', ts: h(2.6), desc: '38 falhas consecutivas na conta op.mesa contra o core bancário.', assignee: 'Marina Sousa' },
  { id: 'ALT-3121', tenant: 'vetra', title: 'Shadow copy deletado via vssadmin', severity: 'critical', status: 'escalado', source: 'Wazuh', rule: 'Volume shadow copy deletion', ruleId: '5549', srcIp: '10.0.4.18', dstIp: '10.0.4.18', user: 'j.pereira', host: 'WS-FIN-014', ts: h(3), desc: 'vssadmin delete shadows /all /quiet — comportamento clássico pré-criptografia.', assignee: 'Luiz Almeida', incidentId: 'INC-2041' },
  { id: 'ALT-3120', tenant: 'vetra', title: 'Integridade alterada: /etc/passwd', severity: 'medium', status: 'novo', source: 'Wazuh', rule: 'File integrity change', ruleId: '5503', srcIp: '10.0.1.32', dstIp: '10.0.1.32', user: 'root', host: 'SRV-APP02', ts: h(4.2), desc: 'Hash alterado em /etc/passwd. Novo usuário "deployx" com UID 0.' },
  { id: 'ALT-3119', tenant: 'medcore', title: 'Scan de portas interno detectado', severity: 'low', status: 'novo', source: 'FortiSIEM', rule: 'Internal port scan', ruleId: '28002', srcIp: '10.3.6.30', dstIp: '10.3.0.0/16', user: '—', host: 'WS-TRIAGE-03', ts: h(5), desc: 'Varredura TCP SYN em 400 portas a partir de estação da emergência.' },
  { id: 'ALT-3118', tenant: 'atlantico', title: 'Ataque bloqueado pelo IPS (SQLi)', severity: 'medium', status: 'fechado', source: 'FortiSIEM', rule: 'IPS attack blocked', ruleId: '28010', srcIp: '201.17.44.10', dstIp: '10.2.0.1', user: '—', host: 'FW-AGENCIA', ts: h(7), desc: 'Tentativa de SQL injection bloqueada na borda. Nenhum impacto.', classification: 'Benigno' },
  { id: 'ALT-3117', tenant: 'vetra', title: 'Novo usuário criado no AD', severity: 'info', status: 'fechado', source: 'Wazuh', rule: 'New user created', ruleId: '5901', srcIp: '10.0.1.10', dstIp: '10.0.1.10', user: 'admin', host: 'SRV-DC01', ts: h(9), desc: 'Conta temporária criada para prestador — dentro do processo aprovado.', classification: 'Benigno' },
  { id: 'ALT-3116', tenant: 'vetra', title: 'Credencial exposta em vazamento público', severity: 'medium', status: 'novo', source: 'Wazuh', rule: 'Leaked credential match', ruleId: '100330', srcIp: '—', dstIp: '—', user: 'j.pereira', host: '—', ts: h(11), desc: 'Hash da conta j.pereira identificado em dump recente de combo list.' },
  { id: 'ALT-3115', tenant: 'medcore', title: 'Serviço DICOM parado inesperadamente', severity: 'medium', status: 'reconhecido', source: 'Wazuh', rule: 'Service stopped', ruleId: '502', srcIp: '10.3.1.12', dstIp: '10.3.1.12', user: '—', host: 'SRV-PACS-01', ts: h(14), desc: 'Serviço de comunicação DICOM caiu sem evento de manutenção programada.', assignee: 'Carlos Mendes' },
  { id: 'ALT-3114', tenant: 'atlantico', title: 'Login administrativo fora do horário comercial', severity: 'low', status: 'falso_positivo', source: 'Wazuh', rule: 'Admin login success', ruleId: '5715', srcIp: '10.2.9.8', dstIp: '10.2.1.40', user: 'dba.oncall', host: 'SRV-PIX-01', ts: h(19), desc: 'Plantão de DBA confirmado via chamado #4521.', classification: 'Falso positivo' },
  { id: 'ALT-3113', tenant: 'vetra', title: 'Vulnerabilidade crítica detectada: CVE-2025-1093', severity: 'medium', status: 'novo', source: 'Wazuh', rule: 'Critical vulnerability found', ruleId: '100301', srcIp: '10.0.1.10', dstIp: '10.0.1.10', user: '—', host: 'SRV-DC01', ts: h(22), desc: 'Scanner identificou CVE-2025-1093 (RCE) no domain controller.' },
  { id: 'ALT-3112', tenant: 'vetra', title: 'Cadeia de ransomware em WS-FIN-014 (2 técnicas)', severity: 'critical', status: 'escalado', source: 'Correlação', rule: 'Cadeia Ransomware', ruleId: 'COR-RANSOM', srcIp: '10.0.4.18', dstIp: '10.0.1.20', user: 'j.pereira', host: 'WS-FIN-014', ts: h(2.1), desc: 'Política COR-RANSOM disparou: shadow copy deletion + mass file modification no mesmo host em 10min.', incidentId: 'INC-2041' },
  { id: 'ALT-3111', tenant: 'vetra', title: 'Beaconing C2: WS-FIN-014 → 45.155.205.86 (7 conexões)', severity: 'critical', status: 'reconhecido', source: 'Correlação', rule: 'Beaconing C2', ruleId: 'COR-C2', srcIp: '10.0.4.18', dstIp: '45.155.205.86', user: 'j.pereira', host: 'WS-FIN-014', ts: m(50), desc: 'Política COR-C2 disparou: 7 conexões do mesmo host para destino externo em 10min.', assignee: 'Luiz Almeida' },
  { id: 'ALT-3110', tenant: 'atlantico', title: 'Brute force: 14 tentativas de 185.220.101.34', severity: 'high', status: 'escalado', source: 'Correlação', rule: 'Brute Force', ruleId: 'COR-BRUTE', srcIp: '185.220.101.34', dstIp: '10.2.0.1', user: 'administrator', host: 'FW-AGENCIA', ts: h(6), desc: 'Política COR-BRUTE disparou: 14 falhas de autenticação da mesma origem em 5min.', incidentId: 'INC-2040' },
];

export const SEED_INCIDENTS: Incident[] = [
  {
    id: 'INC-2041', tenant: 'vetra', title: 'Ransomware em estação financeira — WS-FIN-014',
    severity: 'critical', status: 'investigacao', assignee: 'Luiz Almeida', ts: h(2), slaH: 4,
    alertIds: ['ALT-3128', 'ALT-3127', 'ALT-3121'], caseId: 'CASE-118', asset: 'WS-FIN-014',
    iocs: ['45.155.205.86', 'evil.example-cdn.com', '3f2a9c14d8b7e5f6a0c3d2e1b9a8f7c6d5e4a3b2c1d0e9f8a7b6c5d4e3f2a1b0'],
    tasks: [
      { id: 't1', text: 'Isolar WS-FIN-014 da rede', done: true },
      { id: 't2', text: 'Coletar imagem forense de memória', done: true },
      { id: 't3', text: 'Bloquear IOCs no firewall de borda', done: false },
      { id: 't4', text: 'Verificar movimentação lateral no SRV-DB01', done: false },
      { id: 't5', text: 'Acionar plano de recuperação de backup', done: false },
    ],
    timeline: [
      { ts: h(2), text: 'Incidente criado a partir do alerta ALT-3128 (regra 5551)', kind: 'system' },
      { ts: m(114), text: 'Severidade elevada para Crítico. SLA de contenção: 4h.', kind: 'action', author: 'Luiz Almeida' },
      { ts: m(102), text: 'Endpoint WS-FIN-014 isolado via EDR — tráfego bloqueado exceto canal de gestão.', kind: 'action', author: 'Playbook PB-RANSOM' },
      { ts: m(80), text: 'Hash coletado confirmado como LockBit 3.0 no VirusTotal (47/72).', kind: 'user', author: 'Luiz Almeida' },
      { ts: m(35), text: 'Aguardando aprovação para bloqueio do C2 45.155.205.86 no FW-MATRIZ.', kind: 'action', author: 'Playbook PB-RANSOM' },
    ],
  },
  {
    id: 'INC-2040', tenant: 'vetra', title: 'Brute force RDP contra SRV-APP02',
    severity: 'high', status: 'contido', assignee: 'Carlos Mendes', ts: h(5), slaH: 8,
    alertIds: ['ALT-3125'], asset: 'SRV-APP02',
    iocs: ['185.220.101.34'],
    tasks: [
      { id: 't1', text: 'Bloquear IP de origem no firewall', done: true },
      { id: 't2', text: 'Forçar rotação de senha da conta administrator', done: true },
      { id: 't3', text: 'Revisar logins bem-sucedidos anteriores', done: false },
    ],
    timeline: [
      { ts: h(5), text: 'Incidente criado a partir do alerta ALT-3125', kind: 'system' },
      { ts: h(4.5), text: 'IP 185.220.101.34 bloqueado no FW-MATRIZ (ação automática aprovada).', kind: 'action', author: 'Playbook PB-BRUTE' },
      { ts: h(4.1), text: 'Nenhum login bem-sucedido da origem. Conta íntegra.', kind: 'user', author: 'Carlos Mendes' },
    ],
  },
  {
    id: 'INC-2038', tenant: 'atlantico', title: 'Possível exfiltração via DNS — SRV-PIX-01',
    severity: 'critical', status: 'aberto', assignee: 'Marina Sousa', ts: m(24), slaH: 4,
    alertIds: ['ALT-3126'], asset: 'SRV-PIX-01',
    iocs: ['91.240.118.172', 'cdn-metrics-update.example-ns.net'],
    tasks: [
      { id: 't1', text: 'Bloquear domínio de tunneling no resolvedor', done: false },
      { id: 't2', text: 'Analisar processo responsável no servidor PIX', done: false },
    ],
    timeline: [
      { ts: m(24), text: 'Incidente aberto automaticamente pela heurística de DNS tunneling', kind: 'system' },
      { ts: m(15), text: 'Atribuído à Marina Sousa. Iniciada coleta de netflow.', kind: 'user', author: 'Ana Ribeiro' },
    ],
  },
  {
    id: 'INC-2036', tenant: 'vetra', title: 'Credencial vazada — conta j.pereira',
    severity: 'medium', status: 'investigacao', assignee: 'Ana Ribeiro', ts: h(10), slaH: 24,
    alertIds: ['ALT-3116'], iocs: [],
    tasks: [
      { id: 't1', text: 'Revogar sessões ativas da conta', done: true },
      { id: 't2', text: 'Forçar MFA e rotação de senha', done: false },
    ],
    timeline: [
      { ts: h(10), text: 'Incidente criado a partir do alerta ALT-3116', kind: 'system' },
      { ts: h(9), text: 'Sessões revogadas via IdP. Sem uso anômalo até o momento.', kind: 'action', author: 'Ana Ribeiro' },
    ],
  },
  {
    id: 'INC-2033', tenant: 'vetra', title: 'Serviço crítico parado — SRV-DB01',
    severity: 'low', status: 'resolvido', assignee: 'Carlos Mendes', ts: d(1.2), slaH: 48,
    alertIds: [], asset: 'SRV-DB01', iocs: [],
    tasks: [{ id: 't1', text: 'Reiniciar serviço e validar integridade', done: true }],
    timeline: [
      { ts: d(1.2), text: 'Abertura manual após indisponibilidade do PostgreSQL', kind: 'user', author: 'Carlos Mendes' },
      { ts: d(1.1), text: 'Serviço restaurado. Causa: OOM killer durante job de backup.', kind: 'user', author: 'Carlos Mendes' },
    ],
  },
  {
    id: 'INC-2030', tenant: 'medcore', title: 'Scan interno não autorizado — origem WS-TRIAGE-03',
    severity: 'low', status: 'fechado', assignee: 'Marina Sousa', ts: d(3), slaH: 48,
    alertIds: ['ALT-3119'], asset: 'WS-TRIAGE-03', iocs: [],
    tasks: [{ id: 't1', text: 'Identificar ferramenta de scan', done: true }],
    timeline: [
      { ts: d(3), text: 'Incidente criado a partir do alerta ALT-3119', kind: 'system' },
      { ts: d(2.8), text: 'Encerrado: ferramenta legítima de inventário (Lansweeper) em janela aprovada.', kind: 'user', author: 'Marina Sousa' },
    ],
  },
];

export const SEED_CASES: Case[] = [
  {
    id: 'CASE-118', tenant: 'vetra', title: 'Campanha de ransomware — contenção e erradicação',
    severity: 'critical', stage: 'Contenção', assignee: 'Luiz Almeida', ts: h(1.8),
    alertIds: ['ALT-3128', 'ALT-3127', 'ALT-3121'], incidentIds: ['INC-2041'],
    assetNames: ['WS-FIN-014', 'SRV-DB01', 'FW-MATRIZ'],
    iocs: ['45.155.205.86', 'evil.example-cdn.com', '3f2a9c14d8b7...f2a1b0'],
    evidence: ['memdump-wsfin014-0312.raw', 'mft-snapshot.csv', 'pcap-egress-45.155.pcap'],
    comments: [
      { ts: h(1.5), author: 'Luiz Almeida', text: 'Imagem de memória coletada. Próximo passo: validar snapshots do share financeiro antes da recuperação.' },
      { ts: m(50), author: 'Ana Ribeiro', text: 'Backups de ontem íntegros (verificação de integridade OK). RPO aceitável.' },
    ],
  },
  {
    id: 'CASE-117', tenant: 'vetra', title: 'Brute force recorrente em RDP — endurecimento',
    severity: 'high', stage: 'Investigação', assignee: 'Carlos Mendes', ts: h(4.8),
    alertIds: ['ALT-3125'], incidentIds: ['INC-2040'], assetNames: ['SRV-APP02', 'FW-MATRIZ'],
    iocs: ['185.220.101.34'], evidence: ['rdp-auth-log-0312.txt'],
    comments: [{ ts: h(3), author: 'Carlos Mendes', text: 'Proposta: mover RDP para VPN com MFA e publicar via gateway.' }],
  },
  {
    id: 'CASE-116', tenant: 'atlantico', title: 'Phishing direcionado à diretoria',
    severity: 'medium', stage: 'Triagem', assignee: 'Ana Ribeiro', ts: h(8),
    alertIds: [], incidentIds: [], assetNames: [],
    iocs: ['pagamento-fatura.example-mail.com'], evidence: ['email-original.eml'],
    comments: [],
  },
  {
    id: 'CASE-114', tenant: 'medcore', title: 'Atualização emergencial — CVE-2024-47176 (CUPS)',
    severity: 'high', stage: 'Recuperação', assignee: 'Marina Sousa', ts: d(2),
    alertIds: [], incidentIds: [], assetNames: ['SRV-PACS-01'],
    iocs: [], evidence: ['scan-pre-patch.xml', 'scan-pos-patch.xml'],
    comments: [{ ts: d(1), author: 'Marina Sousa', text: 'Patch aplicado em homologação. Produção agendada para janela de domingo.' }],
  },
  {
    id: 'CASE-109', tenant: 'vetra', title: 'Falso positivo — regra IPS 28010 em FW-AGENCIA',
    severity: 'low', stage: 'Encerrado', assignee: 'Ana Ribeiro', ts: d(6),
    alertIds: ['ALT-3118'], incidentIds: [], assetNames: ['FW-MATRIZ'],
    iocs: [], evidence: [],
    comments: [{ ts: d(5.8), author: 'Ana Ribeiro', text: 'Ajustada exceção na assinatura. Encerrando.' }],
  },
];

export const SEED_VULNS: Vuln[] = [
  { id: 'VL-901', cve: 'CVE-2024-3400',  tenant: 'vetra',     title: 'RCE em FortiOS via path traversal (SSL VPN)', cvss: 10.0, severity: 'critical', asset: 'FW-MATRIZ',   status: 'aberta',      found: h(6),   fix: 'Atualizar FortiOS para 7.4.4+ ou aplicar workaround do vendor' },
  { id: 'VL-902', cve: 'CVE-2025-1093',  tenant: 'vetra',     title: 'RCE em serviço de diretório (AD CS)', cvss: 9.8, severity: 'critical', asset: 'SRV-DC01',    status: 'em_correcao', found: h(22),  fix: 'Aplicar patch de segurança de março + reiniciar AD CS' },
  { id: 'VL-903', cve: 'CVE-2025-0282',  tenant: 'atlantico', title: 'Stack overflow em appliance VPN', cvss: 9.8, severity: 'critical', asset: 'FW-AGENCIA',  status: 'confirmada',  found: d(1),   fix: 'Upgrade de firmware 7.2.10 e restringir acesso VPN' },
  { id: 'VL-904', cve: 'CVE-2025-24813', tenant: 'vetra',     title: 'RCE via deserialization no Tomcat', cvss: 9.8, severity: 'critical', asset: 'SRV-APP02',   status: 'aberta',      found: h(30),  fix: 'Atualizar Tomcat para 10.1.20+ e desabilitar partial PUT' },
  { id: 'VL-905', cve: 'CVE-2024-6387',  tenant: 'atlantico', title: 'regreSSHion — RCE no OpenSSH (signal handler)', cvss: 8.1, severity: 'high', asset: 'SRV-PIX-01', status: 'aberta',      found: d(2),   fix: 'Atualizar OpenSSH 9.8p1 ou definir LoginGraceTime 0' },
  { id: 'VL-906', cve: 'CVE-2024-47176', tenant: 'medcore',   title: 'CUPS cups-browsed — execução remota', cvss: 8.8, severity: 'high', asset: 'SRV-PACS-01', status: 'em_correcao', found: d(2),   fix: 'Remover/atualizar cups-browsed e bloquear UDP 631' },
  { id: 'VL-907', cve: 'CVE-2024-21887', tenant: 'vetra',     title: 'Command injection em appliance VPN', cvss: 9.1, severity: 'critical', asset: 'FW-MATRIZ',  status: 'mitigada',    found: d(4),   fix: 'Patch aplicado; validação pendente de re-scan' },
  { id: 'VL-908', cve: 'CVE-2024-23222', tenant: 'vetra',     title: 'Use-after-free em WebKit (execução de código)', cvss: 8.8, severity: 'high', asset: 'WS-RH-022', status: 'mitigada',    found: d(5),   fix: 'Atualizar navegador via GPO — rollout 100%' },
  { id: 'VL-909', cve: 'CVE-2023-46805', tenant: 'atlantico', title: 'Bypass de autenticação em appliance de acesso', cvss: 8.2, severity: 'high', asset: 'FW-AGENCIA', status: 'aceita',      found: d(12),  fix: 'Risco aceito até janela de manutenção de abril (ativo em descomissionamento)' },
  { id: 'VL-910', cve: 'CVE-2023-34362', tenant: 'medcore',   title: 'MOVEit Transfer — SQLi para RCE', cvss: 9.8, severity: 'critical', asset: 'SRV-PACS-01', status: 'resolvida', found: d(20),  fix: 'Patch aplicado e validado por re-scan' },
  { id: 'VL-911', cve: 'CVE-2024-27198', tenant: 'vetra',     title: 'Bypass de autenticação no TeamCity', cvss: 9.8, severity: 'critical', asset: 'VM-K8S-01',  status: 'resolvida', found: d(15),  fix: 'Upgrade para 2023.11.4 e rotação de tokens' },
  { id: 'VL-912', cve: 'CVE-2024-38063', tenant: 'atlantico', title: 'IPv6 stack — RCE remoto (KernelTunnel)', cvss: 8.8, severity: 'high', asset: 'SRV-CORE-BK', status: 'em_correcao', found: d(3), fix: 'Patch Tuesday aplicado; reboot pendente na janela' },
];

export const SEED_PLAYBOOKS: Playbook[] = [
  {
    id: 'PB-RANSOM', name: 'Resposta a Ransomware', trigger: 'Regra 5551 — modificação em massa de arquivos', severity: 'critical',
    steps: [
      { id: 's1', label: 'Criar incidente crítico', desc: 'Abre incidente vinculado aos alertas correlacionados' },
      { id: 's2', label: 'Identificar host afetado', desc: 'Resolve agente, usuário e criticidade do ativo' },
      { id: 's3', label: 'Isolar endpoint', desc: 'Network containment via EDR', approval: true, effect: { isolate: 'WS-FIN-014' } },
      { id: 's4', label: 'Consultar IOCs em threat intel', desc: 'VirusTotal, AbuseIPDB e feeds internos' },
      { id: 's5', label: 'Bloquear C2 no firewall', desc: 'Regra deny de saída no FW-MATRIZ', approval: true, effect: { block: '45.155.205.86' } },
      { id: 's6', label: 'Criar tarefas de erradicação', desc: 'Forense, varredura e reimage' },
      { id: 's7', label: 'Notificar responsável', desc: 'Canal #soc-critical + e-mail do owner' },
      { id: 's8', label: 'Gerar relatório preliminar', desc: 'PDF executivo para o cliente' },
    ],
  },
  {
    id: 'PB-BRUTE', name: 'Contenção de Brute Force', trigger: 'Regra 5720/100215 — falhas em sequência', severity: 'high',
    steps: [
      { id: 's1', label: 'Identificar origem', desc: 'GeoIP, ASN e histórico da fonte' },
      { id: 's2', label: 'Verificar volume de tentativas', desc: 'Threshold: 10 falhas / 5 min' },
      { id: 's3', label: 'Consultar reputação do IP', desc: 'Feeds de Tor/proxies/abuso' },
      { id: 's4', label: 'Bloquear IP no firewall', desc: 'Lista de bloqueio automática', approval: true, effect: { block: '185.220.101.34' } },
      { id: 's5', label: 'Verificar comprometimento', desc: 'Checa logins bem-sucedidos da origem' },
      { id: 's6', label: 'Criar incidente se necessário', desc: 'Somente se houver login bem-sucedido' },
    ],
  },
  {
    id: 'PB-PHISH', name: 'Triagem de Phishing', trigger: 'Reporte de usuário ou detecção de e-mail', severity: 'medium',
    steps: [
      { id: 's1', label: 'Extrair URLs e anexos', desc: 'Parser de cabeçalhos e corpo' },
      { id: 's2', label: 'Detonar anexos em sandbox', desc: 'Análise comportamental 120s' },
      { id: 's3', label: 'Consultar reputação de domínio', desc: 'WHOIS, idade, certificado' },
      { id: 's4', label: 'Remover e-mail das caixas', desc: 'Purge global via API do M365', approval: true },
      { id: 's5', label: 'Notificar usuários afetados', desc: 'Orientação de segurança' },
    ],
  },
  {
    id: 'PB-IOC', name: 'Bloqueio de IOC', trigger: 'IOC confirmado em investigação', severity: 'medium',
    steps: [
      { id: 's1', label: 'Validar IOC', desc: 'Tipo, formato e falsos positivos' },
      { id: 's2', label: 'Consultar feeds de ameaça', desc: 'Confiança mínima: 2 fontes' },
      { id: 's3', label: 'Bloquear IP/domínio', desc: 'Firewall + DNS sinkhole', approval: true, effect: { block: 'evil.example-cdn.com' } },
      { id: 's4', label: 'Criar regra de detecção no SIEM', desc: 'Correlação retroativa 30 dias' },
      { id: 's5', label: 'Registrar evidência no case', desc: 'Snapshot da consulta e decisão' },
    ],
  },
];

export const SEED_AUDIT: AuditEntry[] = [
  { id: 'au10', ts: m(9),   actor: 'Playbook PB-RANSOM', action: 'solicitou aprovação para bloqueio de C2', target: '45.155.205.86', kind: 'response' },
  { id: 'au09', ts: m(102), actor: 'Playbook PB-RANSOM', action: 'executou isolamento de endpoint', target: 'WS-FIN-014', kind: 'response' },
  { id: 'au08', ts: m(114), actor: 'Luiz Almeida', action: 'alterou severidade de Alto para Crítico', target: 'INC-2041', kind: 'triage' },
  { id: 'au07', ts: h(4.5), actor: 'Ana Ribeiro', action: 'aprovou bloqueio de IP no firewall', target: '185.220.101.34', kind: 'response' },
  { id: 'au06', ts: h(6),   actor: 'sistema', action: 'sincronizou 1.248 eventos via connector', target: 'Wazuh', kind: 'data' },
  { id: 'au05', ts: h(7.2), actor: 'Carlos Mendes', action: 'atribuiu alerta para si', target: 'ALT-3125', kind: 'triage' },
  { id: 'au04', ts: h(9),   actor: 'Ana Ribeiro', action: 'revogou sessões ativas de usuário', target: 'j.pereira', kind: 'response' },
  { id: 'au03', ts: h(18),  actor: 'Marina Sousa', action: 'fechou alerta como falso positivo', target: 'ALT-3114', kind: 'triage' },
  { id: 'au02', ts: d(1),   actor: 'Luiz Almeida', action: 'exportou relatório mensal de segurança (PDF)', target: 'Grupo Vetra S.A.', kind: 'data' },
  { id: 'au01', ts: d(1.4), actor: 'sistema', action: 'login bem-sucedido com MFA', target: 'ana.ribeiro', kind: 'auth' },
];

// ── usuários de demonstração (login offline / modo demo) ─────
export const DEMO_USERS: { username: string; password: string; name: string; role: string; tenant: string | null }[] = [
  { username: 'luiz.almeida', password: 'sopir', name: 'Luiz Almeida', role: 'Admin', tenant: null },
  { username: 'ana.ribeiro', password: 'sopir', name: 'Ana Ribeiro', role: 'SOC Manager', tenant: null },
  { username: 'carlos.mendes', password: 'sopir', name: 'Carlos Mendes', role: 'SOC Analyst', tenant: null },
  { username: 'marina.sousa', password: 'sopir', name: 'Marina Sousa', role: 'Security Engineer', tenant: null },
  { username: 'cliente.vetra', password: 'sopir', name: 'Portal — Grupo Vetra', role: 'Customer', tenant: 'vetra' },
];

// ── políticas de correlação (modo demo espelha o motor real) ─
export const SEED_CORRELATIONS = [
  { id: 'COR-BRUTE', name: 'Brute Force', severity: 'high', windowSec: 300, threshold: 8, groupBy: ['srcIp'], groupByLabel: 'srcIp', logic: '≥8 falhas de autenticação da mesma origem em 5min', mitre: 'T1110', mode: 'count', matchDef: null, builtin: true, enabled: true, fires: 14, lastFire: now - 22 * 60_000 },
  { id: 'COR-RANSOM', name: 'Cadeia Ransomware', severity: 'critical', windowSec: 600, threshold: 2, groupBy: ['host'], groupByLabel: 'host', logic: '≥2 regras distintas de integridade/mass-modification no mesmo host em 10min', mitre: 'T1486', mode: 'distinct', matchDef: null, builtin: true, enabled: true, fires: 3, lastFire: now - 110 * 60_000 },
  { id: 'COR-C2', name: 'Beaconing C2', severity: 'critical', windowSec: 600, threshold: 5, groupBy: ['host', 'dstIp'], groupByLabel: 'host + dstIp', logic: '≥5 conexões do mesmo host para um destino externo em 10min', mitre: 'T1071', mode: 'count', matchDef: null, builtin: true, enabled: true, fires: 6, lastFire: now - 8 * 60_000 },
  { id: 'COR-LATERAL', name: 'Movimentação Lateral', severity: 'high', windowSec: 900, threshold: 2, groupBy: ['srcIp'], groupByLabel: 'srcIp', logic: 'falha de login seguida de login administrativo bem-sucedido da mesma origem (15min)', mitre: 'T1021', mode: 'count', matchDef: null, builtin: true, enabled: true, fires: 5, lastFire: now - 41 * 60_000 },
  { id: 'COR-PRIVESC', name: 'Escalação de Privilégio', severity: 'high', windowSec: 300, threshold: 1, groupBy: ['host'], groupByLabel: 'host', logic: 'criação de usuário após falhas de autenticação no mesmo host (5min)', mitre: 'T1078', mode: 'count', matchDef: null, builtin: true, enabled: true, fires: 2, lastFire: now - 5 * 3_600_000 },
  { id: 'COR-DLP', name: 'Exfiltração DNS', severity: 'high', windowSec: 600, threshold: 10, groupBy: ['host', 'dstIp'], groupByLabel: 'host + dstIp', logic: '≥10 consultas/eventos de rede do mesmo host para o mesmo destino externo (10min)', mitre: 'T1048', mode: 'count', matchDef: null, builtin: true, enabled: false, fires: 1, lastFire: now - 26 * 3_600_000 },
];

export const SEED_REPORTS = [
  { id: 'rp1', name: 'Relatório mensal de segurança — Vetra', period: 'Fevereiro 2026', format: 'PDF', ts: d(9), by: 'Luiz Almeida' },
  { id: 'rp2', name: 'Resumo executivo de incidentes', period: 'Q1 2026', format: 'PDF', ts: d(16), by: 'Ana Ribeiro' },
  { id: 'rp3', name: 'Vulnerabilidades & SLA de correção — Atlântico', period: 'Fevereiro 2026', format: 'XLSX', ts: d(21), by: 'Marina Sousa' },
  { id: 'rp4', name: 'Postura de segurança — Medcore', period: 'Janeiro 2026', format: 'PDF', ts: d(34), by: 'Luiz Almeida' },
];

// ── gerador de fluxo de eventos ──────────────────────────────
interface RuleTpl { rule: string; id: string; source: string; sev: Severity; w: number; desc: string }
const RULE_POOL: RuleTpl[] = [
  { rule: 'Autenticação SSH falhou', id: '5716', source: 'Wazuh', sev: 'low', w: 6, desc: 'Falha de login SSH via senha inválida' },
  { rule: 'Múltiplas falhas de autenticação', id: '5720', source: 'Wazuh', sev: 'high', w: 2, desc: 'Sequência de falhas acima do threshold' },
  { rule: 'Integridade de arquivo alterada', id: '5503', source: 'Wazuh', sev: 'medium', w: 4, desc: 'Hash modificado em arquivo monitorado' },
  { rule: 'Modificação em massa de arquivos', id: '5551', source: 'Wazuh', sev: 'critical', w: 1, desc: 'Milhares de arquivos alterados em curto intervalo' },
  { rule: 'Conexão de saída para IP malicioso', id: '100201', source: 'FortiSIEM', sev: 'high', w: 2, desc: 'Tráfego de saída para IP em lista de ameaça' },
  { rule: 'PowerShell com comando encodado', id: '100220', source: 'Wazuh', sev: 'high', w: 2, desc: 'Execução powershell -enc com download cradle' },
  { rule: 'Ataque bloqueado pelo IPS', id: '28010', source: 'FortiSIEM', sev: 'medium', w: 5, desc: 'Assinatura de ataque interceptada na borda' },
  { rule: 'Novo usuário criado', id: '5901', source: 'Wazuh', sev: 'info', w: 3, desc: 'Conta criada no diretório' },
  { rule: 'Serviço parado inesperadamente', id: '502', source: 'Wazuh', sev: 'medium', w: 3, desc: 'Serviço monitorado reportou estado parado' },
  { rule: 'Login administrativo bem-sucedido', id: '5715', source: 'Wazuh', sev: 'info', w: 5, desc: 'Autenticação administrativa com sucesso' },
  { rule: 'Brute force RDP', id: '100215', source: 'FortiSIEM', sev: 'high', w: 2, desc: 'Rajada de tentativas RDP de origem externa' },
  { rule: 'Scan de portas detectado', id: '28002', source: 'FortiSIEM', sev: 'low', w: 3, desc: 'Varredura TCP SYN em múltiplas portas' },
  { rule: 'Vulnerabilidade crítica detectada', id: '100301', source: 'Wazuh', sev: 'medium', w: 2, desc: 'Scanner identificou CVE crítico no ativo' },
  { rule: 'Beaconing C2 suspeito', id: '100240', source: 'FortiSIEM', sev: 'critical', w: 1, desc: 'Padrão periódico de conexão para domínio DGA' },
];
const USERS_POOL = ['luiz.almeida', 'ana.ribeiro', 'carlos.mendes', 'marina.sousa', 'j.pereira', 'root', 'svc.backup', 'admin', 'op.mesa'];
const SRC_IPS = ['45.155.205.86', '185.220.101.34', '91.240.118.172', '201.17.44.10', '103.25.60.11', '10.0.4.18', '10.2.5.21', '172.16.3.9'];

function pickWeighted(rules: RuleTpl[]): RuleTpl {
  const total = rules.reduce((s, r) => s + r.w, 0);
  let x = Math.random() * total;
  for (const r of rules) { x -= r.w; if (x <= 0) return r; }
  return rules[0];
}
const pick = <T,>(arr: T[]): T => arr[Math.floor(Math.random() * arr.length)];

export function makeEvent(seq: number, ts: number, tenantId?: string): Ev {
  const tenant = tenantId ?? pick(['vetra', 'vetra', 'vetra', 'atlantico', 'atlantico', 'medcore']);
  const hosts = SEED_ASSETS.filter(a => a.tenant === tenant);
  const host = pick(hosts);
  const tpl = pickWeighted(RULE_POOL);
  const srcIp = tpl.sev === 'high' || tpl.sev === 'critical' ? pick(SRC_IPS.slice(0, 5)) : pick(SRC_IPS);
  const user = pick(USERS_POOL);
  const raw = JSON.stringify({
    timestamp: new Date(ts).toISOString(),
    rule: { id: tpl.id, description: tpl.rule, level: SEV_META[tpl.sev].level },
    agent: { id: '0' + (120 + hosts.indexOf(host)), name: host.name },
    data: { srcip: srcIp, dstip: host.ip, srcuser: user },
    decoder: { name: tpl.source.toLowerCase() },
    location: '/var/log/secure',
  });
  return {
    id: 'EV-' + (78200 + seq), ts, tenant, source: tpl.source, rule: tpl.rule, ruleId: tpl.id,
    severity: tpl.sev, srcIp, dstIp: host.ip, user, host: host.name, agent: host.name,
    desc: tpl.desc, raw,
  };
}

export function seedEvents(count = 210): Ev[] {
  const out: Ev[] = [];
  for (let i = 0; i < count; i++) {
    const ts = now - Math.pow(Math.random(), 1.55) * 46 * 3_600_000;
    out.push(makeEvent(i, ts));
  }
  return out.sort((a, b) => b.ts - a.ts);
}
