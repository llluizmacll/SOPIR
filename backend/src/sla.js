// ─────────────────────────────────────────────────────────────
// SOPIR API · Incident Management — SLA duplo & conformidade
//
//  · SLA de RESPOSTA: ts → first_response_at (min = policy.response_min)
//  · SLA de RESOLUÇÃO: ts → resolved_at (min = policy.resolution_min)
//  · computeIncidentSla() — situação atual de um incidente
//  · getSlaMetrics() — conformidade, MTTR e violações
// ─────────────────────────────────────────────────────────────
import { sql } from './db.js';

// políticas padrão (minutos) por severidade — resposta / resolução
export const DEFAULT_SLA = {
  critical: { response: 15, resolution: 240 },   // 4h
  high:     { response: 30, resolution: 480 },   // 8h
  medium:   { response: 60, resolution: 1440 },  // 24h
  low:      { response: 120, resolution: 2880 }, // 48h
  info:     { response: 240, resolution: 4320 }, // 72h
};

/** Prioridade padrão derivada da severidade (P1–P4). */
const SEV_PRIORITY = { critical: 'P1', high: 'P2', medium: 'P3', low: 'P4', info: 'P4' };
export const sevToPriority = (sev) => SEV_PRIORITY[sev] ?? 'P3';

/** Garante políticas de SLA para todos os tenants (idempotente). */
export async function ensureSlaPolicies() {
  const tenants = await sql('SELECT id FROM tenants');
  const sevs = Object.keys(DEFAULT_SLA);
  for (const t of tenants.rows) {
    for (const sev of sevs) {
      const d = DEFAULT_SLA[sev];
      await sql(
        `INSERT INTO sla_policies (tenant, severity, response_min, resolution_min)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (tenant, severity) DO NOTHING`,
        [t.id, sev, d.response, d.resolution]);
    }
  }
  console.log('[seed] políticas de SLA garantidas');
}

/** Busca a política de SLA de um tenant+severidade (com fallback padrão). */
export async function getSlaPolicy(tenant, severity) {
  const r = await sql(
    'SELECT * FROM sla_policies WHERE tenant = $1 AND severity = $2',
    [tenant, severity]);
  if (r.rowCount) return r.rows[0];
  const d = DEFAULT_SLA[severity] ?? DEFAULT_SLA.medium;
  return { response_min: d.response, resolution_min: d.resolution, enabled: true };
}

/**
 * Situação de SLA de um incidente (resposta + resolução).
 * `inc` deve ter: ts, severity, tenant, first_response_at, resolved_at, status.
 */
export async function computeIncidentSla(inc, nowMs = Date.now()) {
  const pol = await getSlaPolicy(inc.tenant, inc.severity);
  const created = Date.parse(inc.ts);
  const respMs = pol.response_min * 60_000;
  const resMs = pol.resolution_min * 60_000;

  const respondedAt = inc.first_response_at ? Date.parse(inc.first_response_at) : null;
  const resolvedAt = inc.resolved_at ? Date.parse(inc.resolved_at) : null;

  // resposta
  const responseElapsed = (respondedAt ?? nowMs) - created;
  const responseLeft = respMs - (respondedAt ? responseElapsed : nowMs - created);
  const responseBreached = responseElapsed > respMs;
  const responseMins = respondedAt ? Math.round(responseElapsed / 60_000) : null;

  // resolução
  const resolutionElapsed = (resolvedAt ?? nowMs) - created;
  const resolutionLeft = resMs - (resolvedAt ? resolutionElapsed : nowMs - created);
  const resolutionBreached = resolutionElapsed > resMs;
  const resolutionMins = resolvedAt ? Math.round(resolutionElapsed / 60_000) : null;

  return {
    severity: inc.severity,
    response: {
      targetMin: pol.response_min, elapsedMin: Math.round(responseElapsed / 60_000),
      leftMs: responseLeft, breached: responseBreached, at: respondedAt,
      actualMin: responseMins, pct: Math.max(0, Math.min(1, 1 - (respondedAt ? responseElapsed : nowMs - created) / respMs)),
    },
    resolution: {
      targetMin: pol.resolution_min, elapsedMin: Math.round(resolutionElapsed / 60_000),
      leftMs: resolutionLeft, breached: resolutionBreached, at: resolvedAt,
      actualMin: resolutionMins, pct: Math.max(0, Math.min(1, 1 - (resolvedAt ? resolutionElapsed : nowMs - created) / resMs)),
    },
    firstResponseAt: respondedAt, resolvedAt,
  };
}

/**
 * Métricas de conformidade SLA de um tenant (ou todos).
 */
export async function getSlaMetrics(tenant = null, nowMs = Date.now()) {
  const t = tenant && tenant !== 'all' ? tenant : null;
  const where = t ? 'WHERE tenant = $1' : '';
  const params = t ? [t] : [];

  const inc = await sql(
    `SELECT code, severity, status, ts, first_response_at, resolved_at FROM incidents ${where}`,
    params);

  let respOk = 0, respTotal = 0, resOk = 0, resTotal = 0;
  let respSum = 0, respN = 0, resSum = 0, resN = 0;
  const activeBreaches = [];
  const bySeverity = {};

  for (const i of inc.rows) {
    const pol = await getSlaPolicy(i.tenant ?? t, i.severity);
    const created = Date.parse(i.ts);
    const respMs = pol.response_min * 60_000;
    const resMs = pol.resolution_min * 60_000;
    const open = !['resolvido', 'fechado'].includes(i.status);

    const bucket = bySeverity[i.severity] ?? (bySeverity[i.severity] = { total: 0, respBreached: 0, resBreached: 0 });
    bucket.total += 1;

    // resposta
    const respondedAt = i.first_response_at ? Date.parse(i.first_response_at) : null;
    const respElapsed = (respondedAt ?? nowMs) - created;
    respTotal += 1;
    if (respElapsed <= respMs) respOk += 1; else bucket.respBreached += 1;
    if (respondedAt) { respSum += respElapsed; respN += 1; }

    // resolução
    const resolvedAt = i.resolved_at ? Date.parse(i.resolved_at) : null;
    const resElapsed = (resolvedAt ?? nowMs) - created;
    resTotal += 1;
    if (resElapsed <= resMs) resOk += 1; else {
      bucket.resBreached += 1;
      if (open) activeBreaches.push({ code: i.code, severity: i.severity, status: i.status, overMin: Math.round((resElapsed - resMs) / 60_000) });
    }
    if (resolvedAt) { resSum += resElapsed; resN += 1; }
  }

  return {
    compliance: {
      response: respTotal ? Math.round((respOk / respTotal) * 100) : 100,
      resolution: resTotal ? Math.round((resOk / resTotal) * 100) : 100,
    },
    mttr: {
      responseMin: respN ? Math.round(respSum / respN / 60_000) : null,
      resolutionMin: resN ? Math.round(resSum / resN / 60_000) : null,
    },
    total: inc.rows.length,
    activeBreaches,
    bySeverity,
  };
}
