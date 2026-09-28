// ─────────────────────────────────────────────────────────────
// Connector Wazuh
// Modos:
//   1) Wazuh Indexer (OpenSearch) — recomendado: busca em
//      wazuh-alerts-4.x-* com cursor de timestamp.
//   2) Wazuh Manager API (4.8+) — autenticação JWT + GET /events.
// ─────────────────────────────────────────────────────────────
import { normalizeWazuh } from '../normalize.js';
import https from 'https';

const env = process.env;
const rejectUnauthorized = env.WAZUH_SKIP_SSL_VERIFY !== 'true' && env.WAZUH_SKIP_SSL_VERIFY !== '1';

function basicAuth(user, pass) {
  return 'Basic ' + Buffer.from(`${user}:${pass}`).toString('base64');
}

// Agente HTTPS que ignora validação de certificado quando necessário
function getHttpsAgent() {
  if (!rejectUnauthorized) {
    return new https.Agent({ rejectUnauthorized: false });
  }
  return undefined;
}

async function pollIndexer({ sinceTs, emit }) {
  const base = env.WAZUH_INDEXER_URL.replace(/\/$/, '');
  const pattern = env.WAZUH_INDEX_PATTERN || 'wazuh-alerts-4.x-*';
  const headers = { 'Content-Type': 'application/json' };
  if (env.WAZUH_INDEXER_USER) {
    headers.Authorization = basicAuth(env.WAZUH_INDEXER_USER, env.WAZUH_INDEXER_PASS || '');
  }

  // Sem cursor: pega a janela mais recente; com cursor: avança a partir dele.
  const hasCursor = sinceTs > 86_400_000; // > 1970-01-02
  const body = {
    size: 250,
    sort: [{ timestamp: hasCursor ? 'asc' : 'desc' }],
    track_total_hits: true,
    query: {
      bool: {
        filter: hasCursor
          ? [{ range: { timestamp: { gt: new Date(sinceTs).toISOString() } } }]
          : [{ range: { timestamp: { gte: new Date(Date.now() - 15 * 60_000).toISOString() } } }],
      },
    },
  };

  const agent = getHttpsAgent();
  const res = await fetch(`${base}/${pattern}/_search`, {
    method: 'POST',
    headers,
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(15_000),
    ...(agent ? { agent } : {}),
  });
  if (!res.ok) throw new Error(`Wazuh Indexer respondeu HTTP ${res.status}`);
  const json = await res.json();

  let maxTs = sinceTs;
  for (const hit of json.hits?.hits ?? []) {
    const ev = normalizeWazuh(hit._source ?? {});
    emit(ev, `wazuh:${hit._index}:${hit._id}`);
    if (ev.ts > maxTs) maxTs = ev.ts;
  }
  return { collected: json.hits?.hits?.length ?? 0, maxTs };
}

async function pollManager({ sinceTs, emit }) {
  const base = env.WAZUH_MANAGER_URL.replace(/\/$/, '');
  const agent = getHttpsAgent();
  const auth = await fetch(`${base}/security/user/authenticate`, {
    method: 'POST',
    headers: { Authorization: basicAuth(env.WAZUH_API_USER, env.WAZUH_API_PASS || '') },
    signal: AbortSignal.timeout(10_000),
    ...(agent ? { agent } : {}),
  });
  if (!auth.ok) throw new Error(`Wazuh API: autenticação falhou (HTTP ${auth.status})`);
  const { data } = await auth.json();
  const token = data?.token;
  if (!token) throw new Error('Wazuh API: token não retornado');

  const res = await fetch(`${base}/events?limit=100`, {
    headers: { Authorization: `Bearer ${token}` },
    signal: AbortSignal.timeout(15_000),
    ...(agent ? { agent } : {}),
  });
  if (res.status === 404) {
    throw new Error(
      'GET /events não existe neste Manager (requer Wazuh 4.8+). Use o modo Wazuh Indexer (WAZUH_INDEXER_URL).',
    );
  }
  if (!res.ok) throw new Error(`Wazuh API respondeu HTTP ${res.status}`);
  const json = await res.json();

  let maxTs = sinceTs;
  for (const item of json.data?.affected_items ?? []) {
    const ev = normalizeWazuh(item);
    if (ev.ts <= sinceTs) continue;
    emit(ev, `wazuh:api:${item.timestamp}:${item.rule?.id}:${item.agent?.id}`);
    if (ev.ts > maxTs) maxTs = ev.ts;
  }
  return { collected: json.data?.affected_items?.length ?? 0, maxTs };
}

export const wazuhConnector = {
  name: 'Wazuh',
  pollSeconds: Number(env.WAZUH_POLL_SECONDS) || 20,
  tenant: env.WAZUH_TENANT || null,
  configured: () => Boolean(env.WAZUH_INDEXER_URL || env.WAZUH_MANAGER_URL),
  mode: () => (env.WAZUH_INDEXER_URL ? 'indexer' : env.WAZUH_MANAGER_URL ? 'manager-api' : null),
  poll: (ctx) => (env.WAZUH_INDEXER_URL ? pollIndexer(ctx) : pollManager(ctx)),
};
