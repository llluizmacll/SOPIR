// ─────────────────────────────────────────────────────────────
// SOPIR API · Retenção de eventos
//
// Controla por quanto tempo a telemetria bruta (tabela `events`)
// fica guardada antes de ser apagada. Segue o mesmo modelo das
// políticas de SLA: uma linha `tenant = '*'` é o padrão global,
// e qualquer outro tenant pode ter um prazo próprio (override).
//
// Só afeta a tabela `events` — alertas, incidentes e cases nunca
// são apagados por essa rotina (retenção de evidência/auditoria
// é uma decisão separada).
// ─────────────────────────────────────────────────────────────

import { sql, addAudit } from './db.js';

const GLOBAL = '*';
const DEFAULT_DAYS = 90;
const PURGE_INTERVAL_MS = 6 * 3_600_000; // reavalia a cada 6h

/** Garante que existe uma política global (roda no boot). */
export async function ensureRetentionDefault() {
  await sql(
    `INSERT INTO retention_policies (tenant, days, enabled) VALUES ($1,$2,true)
     ON CONFLICT (tenant) DO NOTHING`,
    [GLOBAL, DEFAULT_DAYS],
  );
}

/** Dias de retenção efetivos pra um tenant: override → padrão global → 90 fixo. */
export async function getEffectiveRetention(tenant) {
  const r = await sql('SELECT days, enabled FROM retention_policies WHERE tenant = $1', [tenant]);
  if (r.rowCount) return r.rows[0];
  const g = await sql('SELECT days, enabled FROM retention_policies WHERE tenant = $1', [GLOBAL]);
  if (g.rowCount) return g.rows[0];
  return { days: DEFAULT_DAYS, enabled: true };
}

/** Lista o padrão global + o override de cada tenant cadastrado (pra tela de configuração). */
export async function listRetentionPolicies() {
  const [pols, tenants] = await Promise.all([
    sql('SELECT tenant, days, enabled, updated_at FROM retention_policies'),
    sql('SELECT id, name FROM tenants ORDER BY name'),
  ]);
  const byTenant = new Map(pols.rows.map((r) => [r.tenant, r]));
  const global = byTenant.get(GLOBAL) ?? { days: DEFAULT_DAYS, enabled: true };
  const perTenant = tenants.rows.map((t) => {
    const override = byTenant.get(t.id);
    return {
      tenant: t.id,
      tenantName: t.name,
      days: override?.days ?? null, // null = está usando o padrão global
      enabled: override?.enabled ?? true,
      effectiveDays: override?.days ?? global.days,
      hasOverride: !!override,
    };
  });
  return { global: { days: global.days, enabled: global.enabled }, tenants: perTenant };
}

/** Define (ou remove, se days=null) o override de um tenant. tenant='*' edita o padrão global. */
export async function setRetentionPolicy(actor, tenant, days, enabled = true) {
  if (tenant !== GLOBAL && days === null) {
    await sql('DELETE FROM retention_policies WHERE tenant = $1', [tenant]);
    await addAudit(actor, 'removeu override de retenção (volta ao padrão global)', tenant, 'system', tenant);
    return;
  }
  const d = Math.max(1, Number(days) || DEFAULT_DAYS);
  await sql(
    `INSERT INTO retention_policies (tenant, days, enabled, updated_at) VALUES ($1,$2,$3, now())
     ON CONFLICT (tenant) DO UPDATE SET days = EXCLUDED.days, enabled = EXCLUDED.enabled, updated_at = now()`,
    [tenant, d, enabled],
  );
  await addAudit(actor, `definiu retenção de ${d} dia(s)${enabled ? '' : ' (desativada)'}`,
    tenant === GLOBAL ? 'padrão global' : tenant, 'system', tenant === GLOBAL ? null : tenant);
}

/**
 * Apaga eventos mais antigos que o prazo efetivo de cada tenant.
 * Roda no boot (com atraso) e depois periodicamente. Também limpa
 * vínculos `alert_events` que sobrarem apontando pra eventos apagados.
 */
export async function purgeOldEvents(actor = 'sistema') {
  const tenants = await sql('SELECT id FROM tenants ORDER BY id');
  const results = [];
  for (const t of tenants.rows) {
    const pol = await getEffectiveRetention(t.id);
    if (!pol.enabled) { results.push({ tenant: t.id, days: pol.days, deleted: 0, skipped: true }); continue; }
    const r = await sql(
      `DELETE FROM events WHERE tenant = $1 AND ts < now() - ($2 || ' days')::interval`,
      [t.id, pol.days],
    );
    if (r.rowCount) {
      await sql(`DELETE FROM alert_events WHERE NOT EXISTS (SELECT 1 FROM events e WHERE e.code = alert_events.event_code)`);
      await addAudit(actor, `retenção: apagou ${r.rowCount} evento(s) com mais de ${pol.days} dia(s)`, t.id, 'system', t.id);
    }
    results.push({ tenant: t.id, days: pol.days, deleted: r.rowCount ?? 0, skipped: false });
  }
  return results;
}

/** Agenda a purga: roda pouco depois do boot e depois a cada PURGE_INTERVAL_MS. */
export function startRetentionScheduler() {
  setTimeout(() => { purgeOldEvents().catch((e) => console.error('[retention] falha na purga inicial:', e.message)); }, 60_000);
  setInterval(() => { purgeOldEvents().catch((e) => console.error('[retention] falha na purga periódica:', e.message)); }, PURGE_INTERVAL_MS);
}
