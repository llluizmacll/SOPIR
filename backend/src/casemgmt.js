// ─────────────────────────────────────────────────────────────
// SOPIR API · Case Management — ciclo operacional completo
//  · templates de caso (estruturas pré-definidas)
//  · SLA de caso por severidade (minutos até fechamento)
//  · tempo por stage + métricas de performance
// ─────────────────────────────────────────────────────────────
import { sql } from './db.js';

export const CASE_STAGES = ['Triagem', 'Investigação', 'Contenção', 'Recuperação', 'Encerrado'];

// SLA de caso (minutos) por severidade — meta até fechamento
export const CASE_SLA_MIN = {
  critical: 480,   // 8h
  high: 1440,      // 24h
  medium: 4320,    // 3d
  low: 10080,      // 7d
  info: 20160,     // 14d
};

// Templates de caso: estrutura inicial (tarefas + severidade sugerida)
export const CASE_TEMPLATES = [
  {
    id: 'incident', name: 'Incidente de Segurança', severity: 'high',
    tasks: [
      'Confirmar escopo e impacto do incidente',
      'Coletar e preservar evidências',
      'Executar contenção inicial',
      'Erradicar a causa raiz',
      'Recuperar ativos afetados',
      'Redigir lições aprendidas',
    ],
  },
  {
    id: 'vuln', name: 'Remediação de Vulnerabilidade', severity: 'medium',
    tasks: [
      'Validar o finding e o ativo afetado',
      'Classificar risco e criticidade',
      'Definir plano de correção/mitigação',
      'Aplicar patch ou workaround',
      'Re-escanear para confirmar resolução',
    ],
  },
  {
    id: 'phishing', name: 'Campanha de Phishing', severity: 'medium',
    tasks: [
      'Analisar cabeçalhos e artefatos do e-mail',
      'Extrair e consultar IOCs (URLs/domínios/anexos)',
      'Verificar usuários que clicaram/abriram',
      'Remover e-mail das caixas',
      'Bloquear IOCs no firewall/proxy',
      'Notificar e conscientizar usuários afetados',
    ],
  },
  {
    id: 'malware', name: 'Infecção por Malware', severity: 'high',
    tasks: [
      'Isolar o endpoint infectado',
      'Identificar vetor de entrada',
      'Coletar amostra e hash do binário',
      'Varredura completa do host',
      'Verificar movimentação lateral',
      'Reimagem do endpoint',
    ],
  },
  {
    id: 'review', name: 'Revisão / Hardening', severity: 'low',
    tasks: [
      'Mapear o escopo da revisão',
      'Coletar baseline de configuração',
      'Identificar desvios e gaps',
      'Aplicar recomendações de hardening',
      'Validar mudanças e documentar',
    ],
  },
];

/** Garante colunas de ciclo de vida populadas em casos antigos (idempotente). */
export async function backfillCases() {
  await sql(`UPDATE cases SET opened_at = ts WHERE opened_at IS NULL`).catch(() => {});
  await sql(`UPDATE cases SET status = CASE WHEN stage = 'Encerrado' THEN 'closed' ELSE 'active' END WHERE status IS NULL`).catch(() => {});
  await sql(`UPDATE cases SET closed_at = ts WHERE stage = 'Encerrado' AND closed_at IS NULL`).catch(() => {});
}

/**
 * Tempo (ms) que o caso passou em cada stage até agora.
 * Usa a timeline para reconstruir as transições de stage.
 */
export async function stageDurations(caseCode, currentStage, openedAtMs, nowMs = Date.now()) {
  const tl = await sql(
    `SELECT ts, text FROM case_timeline WHERE case_code=$1 AND text LIKE 'Stage:%' ORDER BY ts`,
    [caseCode]);
  const marks = [{ stage: 'Triagem', at: openedAtMs }];
  for (const row of tl.rows) {
    const m = row.text.match(/^Stage: (.+)$/);
    if (m) marks.push({ stage: m[1], at: Date.parse(row.ts) });
  }
  marks.push({ stage: currentStage, at: nowMs });

  const durations = {};
  for (const st of CASE_STAGES) durations[st] = 0;
  for (let i = 0; i < marks.length - 1; i++) {
    const cur = marks[i];
    const next = marks[i + 1];
    if (durations[cur.stage] !== undefined) durations[cur.stage] += next.at - cur.at;
  }
  return durations;
}

/** Métricas de performance de cases de um tenant (ou todos). */
export async function getCaseMetrics(tenant = null) {
  const t = tenant && tenant !== 'all' ? tenant : null;
  const where = t ? 'WHERE tenant = $1' : '';
  const params = t ? [t] : [];

  const rows = await sql(`SELECT code, severity, stage, status, ts, opened_at, closed_at, assignee FROM cases ${where}`, params);

  let open = 0, closed = 0, onHold = 0;
  let slaOk = 0, slaTotal = 0, breachActive = [];
  let closeSum = 0, closeN = 0;
  const byStage = {}; const bySeverity = {}; const byAssignee = {};
  const nowMs = Date.now();

  for (const c of rows.rows) {
    const st = byStage[c.stage] ?? (byStage[c.stage] = 0);
    byStage[c.stage] = st + 1;
    const sv = bySeverity[c.severity] ?? (bySeverity[c.severity] = 0);
    bySeverity[c.severity] = sv + 1;
    const as = byAssignee[c.assignee ?? '—'] ?? (byAssignee[c.assignee ?? '—'] = 0);
    byAssignee[c.assignee ?? '—'] = as + 1;

    const isClosed = c.status === 'closed' || c.stage === 'Encerrado';
    if (isClosed) closed += 1;
    else if (c.status === 'on_hold') onHold += 1;
    else open += 1;

    // SLA de fechamento
    const slaMin = CASE_SLA_MIN[c.severity] ?? CASE_SLA_MIN.medium;
    const openedMs = c.opened_at ? Date.parse(c.opened_at) : Date.parse(c.ts);
    const endMs = c.closed_at ? Date.parse(c.closed_at) : nowMs;
    const elapsed = endMs - openedMs;
    slaTotal += 1;
    if (elapsed <= slaMin * 60_000) slaOk += 1;
    else if (!isClosed) breachActive.push({ code: c.code, severity: c.severity, stage: c.stage, overMin: Math.round((elapsed - slaMin * 60_000) / 60_000) });

    if (c.closed_at) { closeSum += Date.parse(c.closed_at) - openedMs; closeN += 1; }
  }

  return {
    total: rows.rows.length, open, closed, onHold,
    slaCompliance: slaTotal ? Math.round((slaOk / slaTotal) * 100) : 100,
    avgCloseHours: closeN ? Math.round(closeSum / closeN / 3_600_000) : null,
    activeBreaches: breachActive,
    byStage, bySeverity, byAssignee,
  };
}
