// ─────────────────────────────────────────────────────────────
// Connector FortiSIEM (Phoenix REST API)
//
// O REST da FortiSIEM varia bastante entre versões. Este connector:
//   1) autentica via POST /phoenix/rest/login (usuário/senha/org);
//   2) tenta endpoints conhecidos de consulta de eventos;
//   3) se nenhum existir na versão instalada, reporta erro claro —
//      a integração recomendada é o push:
//        POST /api/v1/ingest  (header X-Api-Key)
//      configurável como destino nas regras de notificação da
//      FortiSIEM (JSON com srcIpAddr, destIpAddr, user,
//      eventType, eventSeverity…).
// ─────────────────────────────────────────────────────────────
import { normalizeFortisiem } from '../normalize.js';

const env = process.env;

const EVENT_ENDPOINTS = [
  '/phoenix/rest/query/event',
  '/phoenix/rest/event/list',
  '/phoenix/rest/events',
];

async function login(base) {
  const body =
    `<request><user-id>${env.FORTISIEM_USER}</user-id>` +
    `<password>${env.FORTISIEM_PASS || ''}</password>` +
    (env.FORTISIEM_ORG ? `<org-name>${env.FORTISIEM_ORG}</org-name>` : '') +
    `</request>`;
  const res = await fetch(`${base}/phoenix/rest/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'text/xml' },
    body,
    signal: AbortSignal.timeout(10_000),
  });
  if (!res.ok) throw new Error(`FortiSIEM login falhou (HTTP ${res.status})`);
  const text = await res.text();
  // sessões antigas retornam cookie/token no body ou em header
  const tokenMatch = text.match(/<token>([^<]+)<\/token>/);
  return tokenMatch ? tokenMatch[1] : null;
}

export const fortisiemConnector = {
  name: 'FortiSIEM',
  pollSeconds: Number(env.FORTISIEM_POLL_SECONDS) || 30,
  tenant: env.FORTISIEM_TENANT || null,
  configured: () => Boolean(env.FORTISIEM_URL),
  mode: () => (env.FORTISIEM_URL ? 'phoenix-rest' : null),

  async poll({ sinceTs, emit }) {
    const base = env.FORTISIEM_URL.replace(/\/$/, '');
    const token = await login(base);

    let lastErr = null;
    for (const path of EVENT_ENDPOINTS) {
      try {
        const qs = new URLSearchParams({
          startTime: new Date(sinceTs > 86_400_000 ? sinceTs : Date.now() - 15 * 60_000).toISOString(),
          endTime: new Date().toISOString(),
          maxRecords: '250',
        });
        const res = await fetch(`${base}${path}?${qs}`, {
          headers: token ? { Authorization: `Bearer ${token}` } : {},
          signal: AbortSignal.timeout(15_000),
        });
        if (res.status === 404) {
          lastErr = new Error(`endpoint ${path} não existe (HTTP 404)`);
          continue;
        }
        if (!res.ok) throw new Error(`HTTP ${res.status} em ${path}`);
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
        lastErr = err;
      }
    }
    throw new Error(
      `Nenhum endpoint de eventos compatível nesta versão da FortiSIEM (${lastErr?.message}). ` +
        'Integre via push: POST /api/v1/ingest com X-Api-Key.',
    );
  },
};
