// ─────────────────────────────────────────────────────────────
// SOPIR API · normalização — qualquer fonte → modelo do SOPIR
// ─────────────────────────────────────────────────────────────

// Nível de regra Wazuh → severidade SOPIR
export function sevFromWazuhLevel(level) {
  const n = Number(level) || 0;
  if (n >= 12) return 'critical';
  if (n >= 10) return 'high';
  if (n >= 7) return 'medium';
  if (n >= 4) return 'low';
  return 'info';
}

// Severidade FortiSIEM (0–10) → severidade SOPIR
export function sevFromFortisiem(sev) {
  const n = Number(sev) || 0;
  if (n >= 9) return 'critical';
  if (n >= 7) return 'high';
  if (n >= 4) return 'medium';
  if (n >= 2) return 'low';
  return 'info';
}

const tsOr = (...cands) => {
  for (const c of cands) {
    if (!c) continue;
    const t = typeof c === 'number' ? (c < 1e12 ? c * 1000 : c) : Date.parse(c);
    if (!Number.isNaN(t)) return t;
  }
  return Date.now();
};

/**
 * Documento de alerta do Wazuh Indexer (wazuh-alerts-4.x) → evento SOPIR.
 */
export function normalizeWazuh(doc) {
  const rule = doc.rule ?? {};
  const data = doc.data ?? {};
  return {
    ts: tsOr(doc.timestamp, doc['@timestamp']),
    source: 'Wazuh',
    rule: rule.description || doc.full_log || 'Alerta Wazuh',
    ruleId: String(rule.id ?? ''),
    severity: sevFromWazuhLevel(rule.level),
    srcIp: data.srcip ?? doc.srcip ?? null,
    dstIp: data.dstip ?? doc.dstip ?? null,
    user: data.srcuser ?? data.dstuser ?? null,
    host: doc.agent?.name ?? null,
    agent: doc.agent?.name ?? null,
    description: rule.description ?? '',
    raw: JSON.stringify(doc),
  };
}

/**
 * Registro de evento FortiSIEM (Phoenix) → evento SOPIR.
 * Os nomes de campo variam por versão; aceitamos os mais comuns.
 */
export function normalizeFortisiem(rec) {
  return {
    ts: tsOr(rec.eventTime, rec.reportTime, rec.timePeriod, rec.receiveTime),
    source: 'FortiSIEM',
    rule: rec.eventName || rec.eventType || 'Evento FortiSIEM',
    ruleId: String(rec.eventTypeId ?? rec.eventType ?? ''),
    severity: sevFromFortisiem(rec.eventSeverity ?? rec.severity),
    srcIp: rec.srcIpAddr ?? rec.sourceIP ?? null,
    dstIp: rec.destIpAddr ?? rec.destinationIP ?? null,
    user: rec.user ?? rec.userName ?? null,
    host: rec.hostName ?? rec.reportingDevice ?? null,
    agent: rec.reportingDevice ?? null,
    description: rec.eventName ?? rec.eventType ?? '',
    raw: JSON.stringify(rec),
  };
}

/**
 * Payload genérico do endpoint de ingestão push (POST /api/v1/ingest).
 * Aceita o modelo SOPIR direto ou campos comuns de SIEM/EDR.
 */
export function normalizeGeneric(p) {
  const severity = p.severity
    ?? sevFromWazuhLevel(p.level ?? p.ruleLevel)
    ?? 'info';
  return {
    ts: tsOr(p.ts, p.timestamp, p.time),
    source: p.source || 'Webhook',
    rule: p.rule || p.title || p.name || 'Evento recebido via ingestão',
    ruleId: String(p.ruleId ?? p.rule_id ?? ''),
    severity: ['critical', 'high', 'medium', 'low', 'info'].includes(severity) ? severity : 'info',
    srcIp: p.srcIp ?? p.src_ip ?? p.srcip ?? null,
    dstIp: p.dstIp ?? p.dst_ip ?? p.dstip ?? null,
    user: p.user ?? p.username ?? null,
    host: p.host ?? p.hostname ?? p.agent ?? null,
    agent: p.agent ?? p.host ?? null,
    description: p.desc || p.description || p.rule || '',
    raw: JSON.stringify(p),
  };
}
