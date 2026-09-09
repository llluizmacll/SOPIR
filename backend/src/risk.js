// ─────────────────────────────────────────────────────────────
// SOPIR API · Risk Scoring & Agrupamento (Detection & Correlation)
//
//  · computeRiskScores(type, tenant) — risco 0–100 por entidade
//    (host / IP de origem / usuário) a partir de eventos recentes,
//    alertas abertos, incidentes ativos e vulnerabilidades críticas.
//  · aggregateEvents(by, tenant, hours) — agrupa eventos por uma
//    dimensão com contagem, distribuição de severidade e janela.
// ─────────────────────────────────────────────────────────────
import { sql } from './db.js';

const SEV_WEIGHT = { critical: 15, high: 8, medium: 3, low: 1, info: 0 };
const ALERT_WEIGHT = { critical: 20, high: 10, medium: 4, low: 1, info: 0 };

const ENTITY_COL = { host: 'host', srcIp: 'src_ip', user: 'app_user', rule: 'rule' };

/**
 * Risco por entidade. Combina:
 *   eventos 24h (peso por severidade) + alertas abertos +
 *   incidentes ativos (host) + vulns críticas (host).
 */
export async function computeRiskScores(type, tenant) {
  const col = ENTITY_COL[type] ?? 'host';
  const params = [];
  const tenantClause = tenant ? ` AND tenant = $${(params.push(tenant), params.length)}` : '';

  // eventos últimas 24h, contados por severidade e entidade
  const ev = await sql(
    `SELECT ${col} AS entity, severity, count(*)::int AS n
       FROM events
      WHERE ${col} IS NOT NULL AND ${col} <> '—'
        AND ts > now() - interval '24 hours'${tenantClause}
      GROUP BY 1, 2`,
    params,
  );

  // alertas abertos por entidade
  const al = await sql(
    `SELECT ${col} AS entity, severity, count(*)::int AS n
       FROM alerts
      WHERE ${col} IS NOT NULL AND ${col} <> '—'
        AND status NOT IN ('fechado','falso_positivo')${tenantClause}
      GROUP BY 1, 2`,
    params,
  );

  const scores = new Map();
  const bump = (entity) => {
    if (!scores.has(entity)) {
      scores.set(entity, {
        entity, score: 0,
        factors: { eventos24h: 0, alertasAbertos: 0, incidentes: 0, vulnsCriticas: 0 },
        detail: { criticalEvents: 0, highEvents: 0, openAlerts: 0, activeIncidents: 0, criticalVulns: 0 },
      });
    }
    return scores.get(entity);
  };

  for (const r of ev.rows) {
    const s = bump(r.entity);
    s.factors.eventos24h += (SEV_WEIGHT[r.severity] ?? 0) * r.n;
    if (r.severity === 'critical') s.detail.criticalEvents += r.n;
    if (r.severity === 'high') s.detail.highEvents += r.n;
  }
  for (const r of al.rows) {
    const s = bump(r.entity);
    s.factors.alertasAbertos += (ALERT_WEIGHT[r.severity] ?? 0) * r.n;
    s.detail.openAlerts += r.n;
  }

  // incidentes ativos e vulns críticas apenas para hosts (ativos)
  if (type === 'host') {
    const inc = await sql(
      `SELECT asset AS entity, count(*)::int AS n FROM incidents
        WHERE asset IS NOT NULL AND status NOT IN ('resolvido','fechado')${tenantClause}
        GROUP BY 1`, params);
    for (const r of inc.rows) {
      const s = bump(r.entity);
      s.factors.incidentes += 25 * r.n;
      s.detail.activeIncidents += r.n;
    }
    const vu = await sql(
      `SELECT asset AS entity, count(*)::int AS n FROM vulnerabilities
        WHERE asset IS NOT NULL AND severity='critical'
          AND status NOT IN ('resolvida','aceita')${tenantClause}
        GROUP BY 1`, params);
    for (const r of vu.rows) {
      const s = bump(r.entity);
      s.factors.vulnsCriticas += 15 * r.n;
      s.detail.criticalVulns += r.n;
    }
  }

  const out = [];
  for (const s of scores.values()) {
    const raw = s.factors.eventos24h + s.factors.alertasAbertos + s.factors.incidentes + s.factors.vulnsCriticas;
    s.score = Math.max(0, Math.min(100, Math.round(raw)));
    out.push(s);
  }
  return out.sort((a, b) => b.score - a.score).slice(0, 50);
}

/**
 * Agrupa eventos por uma dimensão (host/srcIp/user/rule) com contagem,
 * distribuição de severidade e primeira/última ocorrência.
 */
export async function aggregateEvents(by, tenant, hours = 24) {
  const col = ENTITY_COL[by] ?? 'host';
  const params = [hours];
  const tenantClause = tenant ? ` AND tenant = $${(params.push(tenant), params.length)}` : '';

  const rows = await sql(
    `SELECT ${col} AS entity,
            count(*)::int AS total,
            count(*) FILTER (WHERE severity='critical')::int AS critical,
            count(*) FILTER (WHERE severity='high')::int AS high,
            count(*) FILTER (WHERE severity='medium')::int AS medium,
            count(*) FILTER (WHERE severity IN ('low','info'))::int AS low,
            min(ts) AS first_ts, max(ts) AS last_ts
       FROM events
      WHERE ${col} IS NOT NULL AND ${col} <> '—'
        AND ts > now() - ($1 || ' hours')::interval${tenantClause}
      GROUP BY 1
      ORDER BY total DESC
      LIMIT 40`,
    params,
  );

  return rows.rows.map((r) => ({
    entity: r.entity, total: r.total,
    critical: r.critical, high: r.high, medium: r.medium, low: r.low,
    firstTs: Date.parse(r.first_ts), lastTs: Date.parse(r.last_ts),
  }));
}
