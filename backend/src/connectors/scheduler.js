// ─────────────────────────────────────────────────────────────
// Scheduler de connectors — polling com checkpoint persistido,
// status para a API/frontend.
// ─────────────────────────────────────────────────────────────
import { sql } from '../db.js';
import { ingestNormalized } from '../ingest.js';
import { normalizeWazuh } from '../normalize.js';
import { wazuhConnector } from './wazuh.js';
import { fortisiemConnector } from './fortisiem.js';
import { loadConnectorConfigs, buildPoller, CONNECTOR_TYPES } from './dynamic.js';

// connectors globais (via variável de ambiente) — mantidos por compatibilidade
const envConnectors = [wazuhConnector, fortisiemConnector];
// connectors dinâmicos (por cliente, vindos do banco)
let dynamicPollers = [];
const lastPoll = new Map();

async function refreshDynamic() {
  const cfgs = await loadConnectorConfigs(true);
  dynamicPollers = [];
  for (const c of cfgs) {
    try {
      const poller = await buildPoller(c);
      if (poller) dynamicPollers.push(poller);
    } catch (e) {
      console.error(`[scheduler] erro ao construir poller ${c.code}: ${e.message}`);
    }
  }
}

/** Todos os pollers "reais" (env + dinâmicos), com chave estável de estado. */
function allPollers() {
  return [
    ...envConnectors.filter((c) => c.configured()).map((c) => ({ ...c, key: c.name })),
    ...dynamicPollers,
  ];
}

async function getState(name) {
  const r = await sql('SELECT * FROM connector_state WHERE name = $1', [name]);
  return r.rows[0] ?? null;
}

async function setState(name, patch) {
  const cur = await getState(name);
  if (!cur) {
    await sql(
      `INSERT INTO connector_state (name, status, last_ok, last_error, collected, last_ts)
       VALUES ($1,$2,$3,$4,$5,$6)`,
      [name, patch.status ?? 'inicializando', patch.lastOk ?? null, patch.lastError ?? null, patch.collected ?? 0, patch.lastTs ? new Date(patch.lastTs).toISOString() : null],
    );
    return;
  }
  await sql(
    `UPDATE connector_state SET
       status = COALESCE($2, status),
       last_ok = COALESCE($3, last_ok),
       last_error = COALESCE($4, last_error),
       collected = COALESCE($5, collected),
       last_ts = COALESCE($6, last_ts)
     WHERE name = $1`,
    [
      name,
      patch.status ?? null,
      patch.lastOk ? new Date(patch.lastOk).toISOString() : null,
      patch.lastError !== undefined ? patch.lastError : null,
      patch.collected !== undefined ? (cur.collected + patch.collected) : null,
      patch.lastTs ? new Date(patch.lastTs).toISOString() : null,
    ],
  );
}

async function pollConnector(c) {
  const key = c.key ?? c.name;
  const st = await getState(key);
  const sinceTs = st?.last_ts ? Date.parse(st.last_ts) : 0;
  try {
    const { collected, maxTs } = await c.poll({
      sinceTs,
      emit: (ev, extId) => ingestNormalized(ev, extId, c.tenant, c.env ?? null).catch((e) =>
        console.error(`[ingest] falha ao persistir evento: ${e.message}`),
      ),
    });
    await setState(key, {
      status: 'coletando',
      lastOk: Date.now(),
      lastError: '',
      collected,
      lastTs: maxTs > sinceTs ? maxTs : undefined,
    });
    if (collected > 0) console.log(`[${c.displayName ?? key}] ${collected} evento(s) novo(s) → ${c.tenant}`);
  } catch (err) {
    await setState(key, { status: 'erro', lastError: err.message });
    console.error(`[${c.displayName ?? key}] ${err.message}`);
  }
}

export function startScheduler() {
  (async () => {
    await refreshDynamic().catch((e) => console.error('[scheduler] carga inicial: ' + e.message));

    setInterval(async () => {
      for (const c of allPollers()) {
        const key = c.key ?? c.name;
        const last = lastPoll.get(key) ?? 0;
        if (Date.now() - last >= (c.pollSeconds ?? 20) * 1000) {
          lastPoll.set(key, Date.now());
          await pollConnector(c);
        }
      }
    }, 1000);

    setInterval(() => void refreshDynamic().catch((e) => console.error('[scheduler] refresh: ' + e.message)), 30_000);

    const names = allPollers().map((c) => c.displayName ?? c.key ?? c.name);
    if (names.length) console.log('[scheduler] connectors reais:', names.join(', '));
  })();
}

// ── status para API ──────────────────────────────────────────
export async function connectorStatus() {
  await refreshDynamic().catch(() => {});
  const rows = await sql('SELECT * FROM connector_state ORDER BY name');
  const eps = await sql(
    `SELECT source, count(*)::int AS n FROM events
      WHERE ts > now() - interval '60 seconds' GROUP BY source`,
  );
  const epsBySource = {};
  for (const r of eps.rows) epsBySource[r.source] = r.n;

  const byKey = Object.fromEntries(rows.rows.map((r) => [r.name, r]));
  const st = (key, fallback) => ({
    status: byKey[key]?.status ?? fallback,
    lastOk: byKey[key]?.last_ok ? Date.parse(byKey[key].last_ok) : null,
    lastError: byKey[key]?.last_error || null,
    collected: byKey[key]?.collected ?? 0,
    lastTs: byKey[key]?.last_ts ? Date.parse(byKey[key].last_ts) : null,
  });

  const list = [];

  // connectors via variável de ambiente
  for (const c of envConnectors) {
    if (!c.configured()) continue;
    list.push({ key: c.name, name: c.name, type: c.mode?.() ?? c.name, tenant: c.tenant, configured: true, push: false, ...st(c.name, 'inicializando') });
  }
  // connectors dinâmicos (banco)
  for (const c of dynamicPollers) {
    list.push({ key: c.key, name: c.displayName, type: c.type, tenant: c.tenant, configured: true, push: false, ...st(c.key, 'inicializando') });
  }
  // webhooks (push — não fazem polling)
  const webhooks = (await loadConnectorConfigs(true)).filter((c) => c.type === 'webhook');
  for (const w of webhooks) {
    list.push({ key: w.code, name: w.name, type: 'webhook', tenant: w.tenant, configured: true, push: true, status: 'push', lastOk: null, lastError: null, collected: byKey[w.code]?.collected ?? 0, lastTs: null });
  }

  return { epsBySource, connectors: list };
}
