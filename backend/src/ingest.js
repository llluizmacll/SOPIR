// ─────────────────────────────────────────────────────────────
// SOPIR API · pipeline de ingestão — evento normalizado → DB
// (dedup por id externo + geração automática de alertas)
// ─────────────────────────────────────────────────────────────
import { sql, nextCode, addAudit } from './db.js';
import { correlate } from './correlator.js';

// ── contadores do pipeline (em memória, por processo) ────────
const counters = { normalized: 0, deduped: 0, autoAlerts: 0, correlations: 0, suppressed: 0 };
const startedAt = Date.now();

export function bumpCounter(key, n = 1) { counters[key] += n; }
export function getIngestStats() {
  return { ...counters, uptimeSec: Math.round((Date.now() - startedAt) / 1000) };
}

/**
 * Persiste um evento normalizado. `extId` garante dedup
 * (mesmo evento coletado duas vezes não duplica).
 * Retorna o código gerado (EV-xxxxx) ou null se duplicado.
 */
export async function ingestNormalized(ev, extId, tenant, env = null) {
  const code = await nextCode('EV', 'seq_events');
  const res = await sql(
    `INSERT INTO events
       (code, ext_id, tenant, env, source, rule, rule_id, severity, src_ip, dst_ip,
        app_user, host, agent, description, raw, ts)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15, to_timestamp($16 / 1000.0))
     ON CONFLICT (ext_id) DO NOTHING
     RETURNING code`,
    [
      code, extId, tenant, env, ev.source, ev.rule, ev.ruleId, ev.severity,
      ev.srcIp, ev.dstIp, ev.user, ev.host, ev.agent, ev.description,
      ev.raw, ev.ts,
    ],
  );
  if (!res.rowCount) { bumpCounter('deduped'); return null; }

  bumpCounter('normalized');
  let alertCreated = null;
  if (
    (ev.severity === 'critical' || ev.severity === 'high') &&
    process.env.SOPIR_AUTO_ALERT !== 'false'
  ) {
    alertCreated = await maybeCreateAlert(ev, tenant, env);
  }

  // correlação por política (padrões, não severidade isolada)
  const fired = correlate(ev, tenant);
  for (const f of fired) {
    bumpCounter('correlations');
    await createCorrelationAlert(f, tenant, env);
  }

  return { code, alertCreated, correlationsFired: fired.length };
}

/**
 * Alerta gerado pelo motor de correlação: nasce de um PADRÃO
 * (N eventos agrupados na janela), não de um evento isolado.
 */
async function createCorrelationAlert(f, tenant, env = null) {
  const { policy, group } = f;
  const code = await nextCode('ALT', 'seq_alerts');
  const n = group.events.length;
  const sample = group.events.slice(0, 3).map((e) => `${e.rule} [${e.ruleId}]`).join('; ');
  const description =
    `Política ${policy.id} (${policy.name}) disparou: ${n} eventos agrupados em ` +
    `${policy.windowSec}s por ${policy.groupBy.join(' + ')}. Amostra: ${sample}.`;

  await sql(
    `INSERT INTO alerts
       (code, tenant, env, title, severity, status, source, rule, rule_id, src_ip,
        dst_ip, app_user, host, ts, description)
     VALUES ($1,$2,$3,$4,$5,'novo','Correlação',$6,$7,$8,$9,$10,$11, now(), $12)`,
    [
      code, tenant, env, policy.title(group), policy.severity, policy.name, policy.id,
      group.key.srcIp ?? null, group.key.dstIp ?? null, group.events[0]?.user ?? null,
      group.key.host ?? null, description,
    ],
  );
  await addAudit(`Correlação ${policy.id}`, 'disparou alerta por política', `${code} · ${policy.name}`, 'system', tenant);
  console.log(`[correlator] ${policy.id} disparou ${code} — ${policy.title(group)}`);
}

/**
 * Verifica se o evento casa com alguma regra de supressão ativa.
 */
export async function isSuppressed(ev, tenant) {
  const rules = await sql(
    `SELECT * FROM suppression_rules
      WHERE enabled AND (tenant IS NULL OR tenant = $1)
        AND expires_at > now()`,
    [tenant],
  ).catch(() => ({ rows: [] }));
  for (const r of rules.rows) {
    const matchField = (val, pattern) => {
      if (!pattern) return true;
      if (!val) return false;
      if (pattern.endsWith('*')) return String(val).startsWith(pattern.slice(0, -1));
      return String(val) === pattern;
    };
    if (
      matchField(ev.ruleId || ev.rule, r.rule_id) &&
      matchField(ev.host, r.host) &&
      matchField(ev.srcIp, r.src_ip)
    ) return true;
  }
  return false;
}

/**
 * Alerta automático para eventos high/critical, com dedup de 15 minutos
 * por regra + host (evita tempestade de alertas do mesmo fenômeno).
 * Retorna o código do alerta criado, ou null (dedup/supressão/desligado).
 */
async function maybeCreateAlert(ev, tenant, env = null) {
  if (await isSuppressed(ev, tenant)) { bumpCounter('suppressed'); return null; }

  const dup = await sql(
    `SELECT code FROM alerts
      WHERE rule_id = $1 AND host IS NOT DISTINCT FROM $2
        AND ts > now() - interval '15 minutes'
      LIMIT 1`,
    [ev.ruleId || ev.rule, ev.host],
  );
  if (dup.rowCount) { bumpCounter('deduped'); return null; }

  const code = await nextCode('ALT', 'seq_alerts');
  await sql(
    `INSERT INTO alerts
       (code, tenant, env, title, severity, status, source, rule, rule_id, src_ip,
        dst_ip, app_user, host, ts, description)
     VALUES ($1,$2,$3,$4,$5,'novo',$6,$7,$8,$9,$10,$11,$12, to_timestamp($13 / 1000.0),$14)`,
    [
      code, tenant, env, ev.rule, ev.severity, ev.source, ev.rule, ev.ruleId,
      ev.srcIp, ev.dstIp, ev.user, ev.host, ev.ts, ev.description,
    ],
  );
  bumpCounter('autoAlerts');
  console.log(`[ingest] alerta automático ${code} ← ${ev.rule} (${ev.severity})`);
  return code;
}
