// ─────────────────────────────────────────────────────────────
// SOPIR API · pipeline de ingestão — evento normalizado → DB
// (dedup por id externo + geração automática de alertas)
// ─────────────────────────────────────────────────────────────
import { sql, nextCode, addAudit } from './db.js';
import { correlate } from './correlator.js';

// ── contadores do pipeline (em memória, por processo, por tenant) ────
// GLOBAL guarda a soma de todos os tenants, usada na visão "MSSP — Todos"
const GLOBAL = '*';
const counters = new Map();
const startedAt = Date.now();

function bucket(tenant) {
  const key = tenant || GLOBAL;
  if (!counters.has(key)) counters.set(key, { normalized: 0, deduped: 0, autoAlerts: 0, correlations: 0, suppressed: 0 });
  return counters.get(key);
}

export function bumpCounter(key, tenant, n = 1) {
  bucket(tenant)[key] += n;
  if (tenant) bucket(null)[key] += n; // também soma no total global (visão "Todos")
}

export function getIngestStats(tenant) {
  const c = tenant ? bucket(tenant) : bucket(null);
  return { ...c, uptimeSec: Math.round((Date.now() - startedAt) / 1000) };
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
        app_user, host, agent, description, raw, ts, iocs, message, host_ip)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15, to_timestamp($16 / 1000.0), $17,$18,$19)
     ON CONFLICT (ext_id) DO NOTHING
     RETURNING code`,
    [
      code, extId, tenant, env, ev.source, ev.rule, ev.ruleId, ev.severity,
      ev.srcIp, ev.dstIp, ev.user, ev.host, ev.agent, ev.description,
      ev.raw, ev.ts, JSON.stringify(ev.iocs ?? []), ev.message ?? null, ev.hostIp ?? null,
    ],
  );
  if (!res.rowCount) { bumpCounter('deduped', tenant); return null; }

  bumpCounter('normalized', tenant);
  // carrega o código do evento persistido — usado pra linkar em alert_events
  // quando esse evento (sozinho ou em grupo) disparar um alerta
  const evc = { ...ev, code };

  let alertCreated = null;
  if (
    (ev.severity === 'critical' || ev.severity === 'high') &&
    process.env.SOPIR_AUTO_ALERT !== 'false'
  ) {
    alertCreated = await maybeCreateAlert(evc, tenant, env);
  }

  // correlação por política (padrões, não severidade isolada)
  const fired = correlate(evc, tenant);
  for (const f of fired) {
    bumpCounter('correlations', tenant);
    await createCorrelationAlert(f, tenant, env);
  }

  return { code, alertCreated, correlationsFired: fired.length };
}

async function linkAlertEvents(alertCode, eventCodes) {
  const codes = [...new Set(eventCodes.filter(Boolean))];
  for (const ec of codes) {
    await sql(
      'INSERT INTO alert_events (alert_code, event_code) VALUES ($1,$2) ON CONFLICT DO NOTHING',
      [alertCode, ec],
    );
  }
}

/** Combina (com dedup) os IOCs de todos os eventos de um grupo de correlação. */
function mergeIOCs(events) {
  const seen = new Set();
  const out = [];
  for (const ev of events) {
    for (const i of ev.iocs ?? []) {
      const key = `${i.type}:${i.value}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push(i);
    }
  }
  return out;
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
        dst_ip, app_user, host, ts, description, iocs)
     VALUES ($1,$2,$3,$4,$5,'novo','Correlação',$6,$7,$8,$9,$10,$11, now(), $12, $13)`,
    [
      code, tenant, env, policy.title(group), policy.severity, policy.name, policy.id,
      group.key.srcIp ?? null, group.key.dstIp ?? null, group.events[0]?.user ?? null,
      group.key.host ?? null, description, JSON.stringify(mergeIOCs(group.events)),
    ],
  );
  await addAudit(`Correlação ${policy.id}`, 'disparou alerta por política', `${code} · ${policy.name}`, 'system', tenant);
  await linkAlertEvents(code, group.events.map((e) => e.code));
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
  if (await isSuppressed(ev, tenant)) { bumpCounter('suppressed', tenant); return null; }

  const dup = await sql(
    `SELECT code FROM alerts
      WHERE rule_id = $1 AND host IS NOT DISTINCT FROM $2
        AND ts > now() - interval '15 minutes'
      LIMIT 1`,
    [ev.ruleId || ev.rule, ev.host],
  );
  if (dup.rowCount) { bumpCounter('deduped', tenant); return null; }

  const code = await nextCode('ALT', 'seq_alerts');
  await sql(
    `INSERT INTO alerts
       (code, tenant, env, title, severity, status, source, rule, rule_id, src_ip,
        dst_ip, app_user, host, ts, description, iocs, message)
     VALUES ($1,$2,$3,$4,$5,'novo',$6,$7,$8,$9,$10,$11,$12, to_timestamp($13 / 1000.0),$14,$15,$16)`,
    [
      code, tenant, env, ev.rule, ev.severity, ev.source, ev.rule, ev.ruleId,
      ev.srcIp, ev.dstIp, ev.user, ev.host, ev.ts, ev.description, JSON.stringify(ev.iocs ?? []), ev.message ?? null,
    ],
  );
  bumpCounter('autoAlerts', tenant);
  await linkAlertEvents(code, [ev.code]);
  console.log(`[ingest] alerta automático ${code} ← ${ev.rule} (${ev.severity})`);
  return code;
}
