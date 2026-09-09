// ─────────────────────────────────────────────────────────────
// Connectors dinâmicos (por cliente) — configurados no banco e
// gerenciados pela tela de Integrações. Cada instância alimenta
// um tenant específico.
//
// Tipos:
//   wazuh_indexer  → Wazuh Indexer / OpenSearch (poll _search)
//   wazuh_manager  → Wazuh Manager API 4.8+ (JWT + GET /events)
//   fortisiem      → FortiSIEM Phoenix REST (login + eventos)
//   webhook        → push: a fonte POSTa em /api/v1/ingest (sem poll)
// ─────────────────────────────────────────────────────────────
import { sql } from '../db.js';
import { normalizeWazuh, normalizeFortisiem } from '../normalize.js';

export const PASS_MASK = '••••••••';

export const CONNECTOR_TYPES = {
  wazuh_indexer: {
    label: 'Wazuh Indexer / OpenSearch',
    push: false,
    fields: [
      { key: 'url', label: 'URL do Indexer', placeholder: 'https://wazuh-indexer:9200', type: 'text' },
      { key: 'user', label: 'Usuário', placeholder: 'admin', type: 'text' },
      { key: 'pass', label: 'Senha', placeholder: '••••', type: 'password' },
      { key: 'indexPattern', label: 'Índice de alertas', placeholder: 'wazuh-alerts-4.x-*', type: 'text' },
      { key: 'skipSSLVerify', label: 'Ignorar verificação SSL (certificado autoassinado)', placeholder: '', type: 'checkbox' },
    ],
  },
  wazuh_manager: {
    label: 'Wazuh Manager API (4.8+)',
    push: false,
    fields: [
      { key: 'url', label: 'URL da API', placeholder: 'https://wazuh-manager:55000', type: 'text' },
      { key: 'user', label: 'Usuário da API', placeholder: 'api-user', type: 'text' },
      { key: 'pass', label: 'Senha', placeholder: '••••', type: 'password' },
      { key: 'skipSSLVerify', label: 'Ignorar verificação SSL (certificado autoassinado)', placeholder: '', type: 'checkbox' },
    ],
  },
  fortisiem: {
    label: 'FortiSIEM (Phoenix REST)',
    push: false,
    fields: [
      { key: 'url', label: 'URL do Supervisor', placeholder: 'https://fortisiem:443', type: 'text' },
      { key: 'user', label: 'Usuário', placeholder: 'admin', type: 'text' },
      { key: 'pass', label: 'Senha', placeholder: '••••', type: 'password' },
      { key: 'org', label: 'Organização (opcional)', placeholder: 'super', type: 'text' },
    ],
  },
  webhook: {
    label: 'Webhook / Push (ingest)',
    push: true,
    fields: [],
  },
};

const basicAuth = (u, p) => 'Basic ' + Buffer.from(`${u}:${p}`).toString('base64');

export async function loadConnectorConfigs(enabledOnly = true) {
  const r = await sql(
    `SELECT c.*, t.name AS tenant_name
       FROM connector_configs c LEFT JOIN tenants t ON t.id = c.tenant
      ${enabledOnly ? 'WHERE c.enabled' : ''}
      ORDER BY c.created`);
  return r.rows;
}

export function maskSettings(settings) {
  const out = { ...(settings ?? {}) };
  if (out.pass) out.pass = PASS_MASK;
  if (out.password) out.password = PASS_MASK;
  return out;
}

/** Resolve a senha real: mantém a existente se vier mascarada no update. */
export function resolvePass(incoming, existing) {
  if (incoming === undefined) return existing ?? '';
  if (incoming === PASS_MASK) return existing ?? '';
  return incoming;
}

// ── builders de poll por tipo ────────────────────────────────
async function pollWazuhIndexer(s) {
  const rejectUnauthorized = !(s.skipSSLVerify === true || s.skipSSLVerify === 'true' || s.skipSSLVerify === '1');
  const { request, Agent } = await import('undici');
  const dispatcher = !rejectUnauthorized ? new Agent({ connect: { rejectUnauthorized: false } }) : undefined;
  
  return async ({ sinceTs, emit }) => {
    const url = (s.url || '').replace(/\/$/, '');
    const pattern = s.indexPattern || 'wazuh-alerts-4.x-*';
    const headers = { 'Content-Type': 'application/json' };
    if (s.user) headers.Authorization = basicAuth(s.user, s.pass || '');
    const hasCursor = sinceTs > 86_400_000;
    const body = {
      size: 250,
      sort: [{ timestamp: hasCursor ? 'asc' : 'desc' }],
      track_total_hits: true,
      query: {
        bool: {
          filter: [{
            range: {
              timestamp: hasCursor
                ? { gt: new Date(sinceTs).toISOString() }
                : { gte: new Date(Date.now() - 15 * 60_000).toISOString() },
            },
          }],
        },
      },
    };
    const res = await request(`${url}/${pattern}/_search`, {
      method: 'POST', 
      headers, 
      body: JSON.stringify(body), 
      signal: AbortSignal.timeout(15_000),
      dispatcher,
    });
    if (res.statusCode !== 200) throw new Error(`Indexer respondeu HTTP ${res.statusCode}`);
    const json = await res.body.json();
    let maxTs = sinceTs;
    for (const hit of json.hits?.hits ?? []) {
      const ev = normalizeWazuh(hit._source ?? {});
      emit(ev, `wazuh:${hit._index}:${hit._id}`);
      if (ev.ts > maxTs) maxTs = ev.ts;
    }
    return { collected: json.hits?.hits?.length ?? 0, maxTs };
  };
}

async function wazuhManagerToken(s, dispatcher) {
  const base = (s.url || '').replace(/\/$/, '');
  const { request } = await import('undici');
  const auth = await request(`${base}/security/user/authenticate`, {
    method: 'POST',
    headers: { Authorization: basicAuth(s.user, s.pass || '') },
    signal: AbortSignal.timeout(10_000),
    dispatcher,
  });
  if (auth.statusCode !== 200) throw new Error(`Manager API: autenticação falhou (HTTP ${auth.statusCode})`);
  const { data } = await auth.body.json();
  if (!data?.token) throw new Error('Manager API: token não retornado');
  return { base, token: data.token };
}

async function pollWazuhManager(s) {
  const rejectUnauthorized = !(s.skipSSLVerify === true || s.skipSSLVerify === 'true' || s.skipSSLVerify === '1');
  const { request, Agent } = await import('undici');
  const dispatcher = !rejectUnauthorized ? new Agent({ connect: { rejectUnauthorized: false } }) : undefined;
  
  return async ({ sinceTs, emit }) => {
    const { base, token } = await wazuhManagerToken(s, dispatcher);
    const res = await request(`${base}/events?limit=100`, {
      headers: { Authorization: `Bearer ${token}` }, 
      signal: AbortSignal.timeout(15_000),
      dispatcher,
    });
    if (res.statusCode === 404) throw new Error('GET /events indisponível (requer Wazuh 4.8+)');
    if (res.statusCode !== 200) throw new Error(`Manager API respondeu HTTP ${res.statusCode}`);
    const json = await res.body.json();
    let maxTs = sinceTs;
    for (const item of json.data?.affected_items ?? []) {
      const ev = normalizeWazuh(item);
      if (ev.ts <= sinceTs) continue;
      emit(ev, `wazuh:api:${item.timestamp}:${item.rule?.id}:${item.agent?.id}`);
      if (ev.ts > maxTs) maxTs = ev.ts;
    }
    return { collected: json.data?.affected_items?.length ?? 0, maxTs };
  };
}

function pollFortisiem(s) {
  return async ({ sinceTs, emit }) => {
    const base = (s.url || '').replace(/\/$/, '');
    const loginBody =
      `<request><user-id>${s.user}</user-id><password>${s.pass || ''}</password>` +
      (s.org ? `<org-name>${s.org}</org-name>` : '') + `</request>`;
    const login = await fetch(`${base}/phoenix/rest/login`, {
      method: 'POST', headers: { 'Content-Type': 'text/xml' }, body: loginBody,
      signal: AbortSignal.timeout(10_000),
    });
    if (!login.ok) throw new Error(`FortiSIEM login falhou (HTTP ${login.status})`);
    const text = await login.text();
    const token = text.match(/<token>([^<]+)<\/token>/)?.[1] ?? null;

    const qs = new URLSearchParams({
      startTime: new Date(sinceTs > 86_400_000 ? sinceTs : Date.now() - 15 * 60_000).toISOString(),
      endTime: new Date().toISOString(),
      maxRecords: '250',
    });
    for (const path of ['/phoenix/rest/query/event', '/phoenix/rest/event/list', '/phoenix/rest/events']) {
      try {
        const res = await fetch(`${base}${path}?${qs}`, {
          headers: token ? { Authorization: `Bearer ${token}` } : {},
          signal: AbortSignal.timeout(15_000),
        });
        if (res.status === 404) continue;
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const json = await res.json();
        const records = json.records ?? json.events ?? json.data ?? [];
        let maxTs = sinceTs;
        for (const rec of records) {
          const ev = normalizeFortisiem(rec);
          emit(ev, `fortisiem:${rec.id ?? rec.eventId ?? JSON.stringify(rec).slice(0, 64)}`);
          if (ev.ts > maxTs) maxTs = ev.ts;
        }
        return { collected: records.length, maxTs };
      } catch (err) {
        if (String(err.message).includes('HTTP')) throw err;
      }
    }
    throw new Error('Nenhum endpoint de eventos compatível nesta versão (use push via /api/v1/ingest)');
  };
}

/**
 * Constrói um poller a partir de uma linha de connector_configs.
 * Retorna null para tipos push (webhook), que não fazem polling.
 */
export async function buildPoller(cfg) {
  const s = cfg.settings ?? {};
  const meta = CONNECTOR_TYPES[cfg.type];
  if (!meta || meta.push) return null;
  let poll;
  if (cfg.type === 'wazuh_indexer') {
    poll = await pollWazuhIndexer(s);
  } else if (cfg.type === 'wazuh_manager') {
    poll = await pollWazuhManager(s);
  } else if (cfg.type === 'fortisiem') {
    poll = pollFortisiem(s);
  } else {
    poll = null;
  }
  if (!poll) return null;
  return {
    key: cfg.code,
    code: cfg.code,
    displayName: cfg.name,
    type: cfg.type,
    tenant: cfg.tenant,
    env: cfg.env ?? null,
    pollSeconds: cfg.poll_seconds || 20,
    configured: () => Boolean(s.url),
    poll,
  };
}
export async function testConnector(type, settings) {
  const s = settings ?? {};
  const rejectUnauthorized = !(s.skipSSLVerify === true || s.skipSSLVerify === 'true' || s.skipSSLVerify === '1');
  
  try {
    if (type === 'wazuh_indexer') {
      if (!s.url) return { ok: false, message: 'Informe a URL do Indexer.' };
      const url = s.url.replace(/\/$/, '');
      console.log(`[Wazuh Test] Testing connection to ${url}`);
      console.log(`[Wazuh Test] skipSSLVerify: ${s.skipSSLVerify}, rejectUnauthorized: ${rejectUnauthorized}`);
      
      const headers = {};
      if (s.user) {
        headers.Authorization = basicAuth(s.user, s.pass || '');
        console.log(`[Wazuh Test] Using basic auth with user: ${s.user}`);
      }
      
      // Usar undici diretamente para controle total do TLS
      const { request } = await import('undici');
      const dispatcher = !rejectUnauthorized 
        ? new (await import('undici')).Agent({ connect: { rejectUnauthorized: false } })
        : undefined;
      
      try {
        const res = await request(url, { 
          method: 'GET',
          headers,
          signal: AbortSignal.timeout(8_000),
          dispatcher 
        });
        console.log(`[Wazuh Test] Response status: ${res.statusCode}`);
        
        if (res.statusCode !== 200) {
          const errorText = await res.body.text();
          console.error(`[Wazuh Test] Error response body: ${errorText}`);
          return { ok: false, message: `Indexer respondeu HTTP ${res.statusCode}: ${errorText}` };
        }
        
        const data = await res.body.json();
        console.log(`[Wazuh Test] Success! Cluster: ${data.cluster_name || 'N/A'}, Status: ${data.status || 'N/A'}`);
        return { ok: true, message: `Conectado ao Indexer com sucesso. Cluster: ${data.cluster_name || 'N/A'}, Status: ${data.status || 'N/A'}` };
      } catch (fetchErr) {
        console.error(`[Wazuh Test] Fetch error: ${fetchErr.message}`, fetchErr);
        throw fetchErr;
      }
    }
    
    if (type === 'wazuh_manager') {
      if (!s.url || !s.user) return { ok: false, message: 'Informe URL e usuário.' };
      const httpsModule = await import('https');
      const httpsAgent = !rejectUnauthorized ? new httpsModule.Agent({ rejectUnauthorized: false }) : null;
      await wazuhManagerToken(s, httpsAgent);
      return { ok: true, message: 'Autenticado na Manager API.' };
    }
    
    if (type === 'fortisiem') {
      if (!s.url || !s.user) return { ok: false, message: 'Informe URL e usuário.' };
      const base = s.url.replace(/\/$/, '');
      const body = `<request><user-id>${s.user}</user-id><password>${s.pass || ''}</password></request>`;
      const res = await fetch(`${base}/phoenix/rest/login`, {
        method: 'POST', headers: { 'Content-Type': 'text/xml' }, body,
        signal: AbortSignal.timeout(8_000),
      });
      if (!res.ok) return { ok: false, message: `FortiSIEM login falhou (HTTP ${res.status}).` };
      return { ok: true, message: 'Login no FortiSIEM OK.' };
    }
    
    if (type === 'webhook') {
      return { ok: true, message: 'Webhook é push: a fonte deve POSTar em /api/v1/ingest.' };
    }
    
    return { ok: false, message: 'Tipo de connector desconhecido.' };
  } catch (err) {
    console.error(`[Wazuh Test] Connection error: ${err.message}`);
    console.error(`[Wazuh Test] Error code: ${err.code || 'N/A'}`);
    console.error(`[Wazuh Test] Error type: ${err.type || 'N/A'}`);
    return { ok: false, message: `Falha ao conectar: ${err.message}` };
  }
}
