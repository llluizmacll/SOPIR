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

// IPv4 simples — usado só pra decidir se um "host" parece IP (não é IOC de domínio)
// ou nome (pode ser um domínio/hostname válido como IOC).
const isIPv4 = (v) => /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(String(v ?? ''));

/**
 * Extrai IP e usuário de texto livre — usado como fallback quando a fonte não
 * estrutura esses campos em atributos próprios (comum em logs de aplicação
 * sem decoder dedicado, ex.: SQL Server: "Login failed for user 'sa'. ...
 * [CLIENT: 10.189.129.212]"). Best-effort: cobre os formatos mais comuns.
 */
function extractFromText(text) {
  const t = String(text ?? '');
  const ip = t.match(/\[client:\s*([\d]{1,3}(?:\.[\d]{1,3}){3})\]/i)?.[1]
    ?? t.match(/\bfrom\s+([\d]{1,3}(?:\.[\d]{1,3}){3})\b/i)?.[1]
    ?? t.match(/\b([\d]{1,3}(?:\.[\d]{1,3}){3})\b/)?.[1]
    ?? null;
  const user = t.match(/\bfor user\s+'([^']+)'/i)?.[1]
    ?? t.match(/\buser\s+'([^']+)'/i)?.[1]
    ?? t.match(/\buser[:=]\s*"?([^\s,;"]+)"?/i)?.[1]
    ?? null;
  return { ip, user };
}

/**
 * Monta a lista de IOCs (além de srcIp/dstIp, tratados à parte) a partir de
 * candidatos [tipo, valor]. Cada normalizador de origem passa o que tiver
 * disponível — campos ausentes são ignorados silenciosamente.
 */
function mkIocs(pairs) {
  const out = [];
  const seen = new Set();
  for (const [type, value] of pairs) {
    if (value === undefined || value === null) continue;
    const v = String(value).trim();
    if (!v || seen.has(`${type}:${v}`)) continue;
    seen.add(`${type}:${v}`);
    out.push({ type, value: v });
  }
  return out;
}

/**
 * Documento de alerta do Wazuh Indexer (wazuh-alerts-4.x) → evento SOPIR.
 */
/**
 * Limpa uma mensagem extraída: tira aspas literais que às vezes envolvem o
 * texto inteiro (comum em campos de log do Windows Event Log) e espaços nas
 * pontas. Retorna null se não sobrar nada útil.
 */
function cleanMessage(text) {
  if (text === null || text === undefined) return null;
  let t = String(text).trim();
  while (t.length > 1 && ((t.startsWith('"') && t.endsWith('"')) || (t.startsWith("'") && t.endsWith("'")))) {
    t = t.slice(1, -1).trim();
  }
  return t || null;
}

export function normalizeWazuh(doc) {
  const rule = doc.rule ?? {};
  const data = doc.data ?? {};
  const syscheck = doc.syscheck ?? {};
  const hashes = data.win?.eventdata?.hashes ?? '';
  const sha256FromHashes = /SHA256=([0-9A-Fa-f]{64})/.exec(hashes)?.[1];
  // texto detalhado original: full_log cobre logs estilo syslog (Linux/apps);
  // eventos vindos do Windows Event Log (ex.: SQL Server rodando em Windows)
  // guardam a mensagem em data.win.system.message ou data.win.eventdata.data
  const rawMessage = doc.full_log || data.win?.system?.message || data.win?.eventdata?.data || '';
  const message = cleanMessage(rawMessage);
  // fallback: extrai IP/usuário do texto puro quando o decoder do Wazuh não
  // estruturou esses campos (comum em logs de app sem parser dedicado, ex.:
  // SQL Server) — sem isso, origem/usuário ficam "—" mesmo a informação
  // estando disponível ali na mensagem original
  const fromText = (!data.srcip || !data.srcuser) ? extractFromText(message) : {};
  return {
    ts: tsOr(doc.timestamp, doc['@timestamp']),
    source: 'Wazuh',
    rule: rule.description || message || 'Alerta Wazuh',
    ruleId: String(rule.id ?? ''),
    severity: sevFromWazuhLevel(rule.level),
    srcIp: data.srcip ?? doc.srcip ?? fromText.ip ?? null,
    dstIp: data.dstip ?? doc.dstip ?? null,
    user: data.srcuser ?? data.dstuser ?? fromText.user ?? null,
    host: doc.agent?.name ?? null,
    agent: doc.agent?.name ?? null,
    hostIp: doc.agent?.ip ?? null,
    description: rule.description ?? '',
    message,
    raw: JSON.stringify(doc),
    iocs: mkIocs([
      ['sha256', syscheck.sha256_after ?? sha256FromHashes],
      ['md5', syscheck.md5_after],
      ['sha1', syscheck.sha1_after],
      ['domain', data.dns?.question?.name],
      ['url', data.url],
    ]),
  };
}

/**
 * Registro de evento FortiSIEM (Phoenix) → evento SOPIR.
 * Os nomes de campo variam por versão; aceitamos os mais comuns.
 */
export function normalizeFortisiem(rec) {
  const rawMsg = rec.rawEventMsg ?? rec.msg ?? '';
  const fromText = (!rec.srcIpAddr && !rec.sourceIP) ? extractFromText(rawMsg) : {};
  return {
    ts: tsOr(rec.eventTime, rec.reportTime, rec.timePeriod, rec.receiveTime),
    source: 'FortiSIEM',
    rule: rec.eventName || rec.eventType || 'Evento FortiSIEM',
    ruleId: String(rec.eventTypeId ?? rec.eventType ?? ''),
    severity: sevFromFortisiem(rec.eventSeverity ?? rec.severity),
    srcIp: rec.srcIpAddr ?? rec.sourceIP ?? fromText.ip ?? null,
    dstIp: rec.destIpAddr ?? rec.destinationIP ?? null,
    user: rec.user ?? rec.userName ?? fromText.user ?? null,
    host: rec.hostName ?? rec.reportingDevice ?? null,
    agent: rec.reportingDevice ?? null,
    description: rec.eventName ?? rec.eventType ?? '',
    message: cleanMessage(rawMsg),
    raw: JSON.stringify(rec),
    iocs: mkIocs([
      ['hash', rec.fileHash],
      ['url', rec.url ?? rec.destinationURL],
      ['domain', !isIPv4(rec.destinationHostName) ? rec.destinationHostName : undefined],
    ]),
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
  const msg = p.message ?? p.msg ?? p.full_log ?? null;
  const fromText = (!p.srcIp && !p.src_ip && !p.srcip) ? extractFromText(msg) : {};
  return {
    ts: tsOr(p.ts, p.timestamp, p.time),
    source: p.source || 'Webhook',
    rule: p.rule || p.title || p.name || 'Evento recebido via ingestão',
    ruleId: String(p.ruleId ?? p.rule_id ?? ''),
    severity: ['critical', 'high', 'medium', 'low', 'info'].includes(severity) ? severity : 'info',
    srcIp: p.srcIp ?? p.src_ip ?? p.srcip ?? fromText.ip ?? null,
    dstIp: p.dstIp ?? p.dst_ip ?? p.dstip ?? null,
    user: p.user ?? p.username ?? fromText.user ?? null,
    host: p.host ?? p.hostname ?? p.agent ?? null,
    agent: p.agent ?? p.host ?? null,
    description: p.desc || p.description || p.rule || '',
    message: cleanMessage(msg),
    raw: JSON.stringify(p),
    iocs: mkIocs([
      ['hash', p.fileHash ?? p.hash ?? p.sha256],
      ['domain', !isIPv4(p.domain) ? p.domain : undefined],
      ['url', p.url],
    ]),
  };
}

// ─────────────────────────────────────────────────────────────
// Normalizadores adicionais — Splunk, QRadar, Microsoft Defender
// e um parser CEF genérico (padrão usado por ArcSight, QRadar via
// syslog, Splunk CEF app e boa parte do mercado de SIEM/EDR — serve
// de rede de segurança pra qualquer ferramenta ainda não mapeada
// explicitamente).
// ─────────────────────────────────────────────────────────────

export function sevFromSplunk(v) {
  if (typeof v === 'string') {
    const s = v.toLowerCase();
    if (s === 'critical') return 'critical';
    if (s === 'high') return 'high';
    if (s === 'medium' || s === 'elevated') return 'medium';
    if (s === 'low') return 'low';
    if (s === 'informational' || s === 'info') return 'info';
  }
  const n = Number(v) || 0;
  if (n >= 9) return 'critical';
  if (n >= 7) return 'high';
  if (n >= 4) return 'medium';
  if (n >= 1) return 'low';
  return 'info';
}

/**
 * Resultado de busca do Splunk (Notable Event do ES, ou evento bruto
 * de qualquer índice) → evento SOPIR. Nomes de campo variam bastante
 * entre apps/CIM; aceitamos os mais comuns (CIM compliant + fallback bruto).
 */
export function normalizeSplunk(rec) {
  const fromText = (!rec.src_ip && !rec.src) ? extractFromText(rec._raw) : {};
  return {
    ts: tsOr(rec._time, rec.time, rec.timestamp),
    source: 'Splunk',
    rule: rec.rule_name || rec.signature || rec.search_name || rec.source_name || 'Evento Splunk',
    ruleId: String(rec.rule_id ?? rec.signature_id ?? rec.event_id ?? ''),
    severity: sevFromSplunk(rec.urgency ?? rec.severity),
    srcIp: rec.src_ip ?? rec.src ?? rec.source_ip ?? fromText.ip ?? null,
    dstIp: rec.dest_ip ?? rec.dest ?? rec.destination_ip ?? null,
    user: rec.user ?? rec.src_user ?? fromText.user ?? null,
    host: rec.dvc ?? rec.host ?? rec.dest ?? null,
    agent: rec.host ?? null,
    description: rec.description ?? rec.signature ?? rec.rule_name ?? '',
    message: cleanMessage(rec._raw),
    raw: JSON.stringify(rec),
    iocs: mkIocs([
      ['hash', rec.file_hash ?? rec.md5 ?? rec.sha256],
      ['domain', !isIPv4(rec.query ?? rec.dest_dns) ? (rec.query ?? rec.dest_dns) : undefined],
      ['url', rec.url],
    ]),
  };
}

// magnitude QRadar: 0–10 (combina relevância, credibilidade e severidade)
export function sevFromQRadarMagnitude(mag) {
  const n = Number(mag) || 0;
  if (n >= 8) return 'critical';
  if (n >= 6) return 'high';
  if (n >= 4) return 'medium';
  if (n >= 1) return 'low';
  return 'info';
}

/**
 * Offense da API do QRadar (/api/siem/offenses) → evento SOPIR.
 * Offenses já são eventos correlacionados pelo QRadar — o equivalente
 * mais próximo do que o SOPIR trata como "evento de origem".
 */
export function normalizeQRadar(rec) {
  return {
    ts: tsOr(rec.last_updated_time, rec.start_time),
    source: 'QRadar',
    rule: rec.description || rec.offense_type_str || `Offense #${rec.id ?? ''}`,
    ruleId: String(rec.offense_type ?? rec.id ?? ''),
    severity: sevFromQRadarMagnitude(rec.magnitude ?? rec.severity),
    srcIp: Array.isArray(rec.offense_source) ? rec.offense_source[0] : (rec.offense_source ?? null),
    dstIp: null,
    user: rec.username_count > 0 ? (rec.assigned_to ?? null) : null,
    host: Array.isArray(rec.log_sources) ? (rec.log_sources[0]?.name ?? null) : null,
    agent: null,
    description: rec.description ?? '',
    raw: JSON.stringify(rec),
  };
}

export function sevFromDefender(v) {
  const s = String(v ?? '').toLowerCase();
  if (s === 'high') return 'critical';
  if (s === 'medium') return 'high';
  if (s === 'low') return 'medium';
  if (s === 'informational') return 'low';
  return 'info';
}

/**
 * Alerta do Microsoft Graph Security API (/security/alerts_v2 — cobre
 * Defender for Endpoint, for Identity, for Cloud Apps, Sentinel) →
 * evento SOPIR.
 */
export function normalizeDefender(rec) {
  const evidence = Array.isArray(rec.evidence) ? rec.evidence : [];
  const fileEv = evidence.find((e) => e.fileDetails);
  const urlEv = evidence.find((e) => typeof e.url === 'string');
  const domainEv = evidence.find((e) => typeof e.domainName === 'string');
  return {
    ts: tsOr(rec.createdDateTime, rec.lastUpdateDateTime),
    source: 'Microsoft Defender',
    rule: rec.title || rec.category || 'Alerta Defender',
    ruleId: String(rec.id ?? ''),
    severity: sevFromDefender(rec.severity),
    srcIp: evidence.find((e) => e.ipAddress)?.ipAddress ?? null,
    dstIp: null,
    user: evidence.find((e) => e.userAccount)?.userAccount?.userPrincipalName ?? null,
    host: evidence.find((e) => e.deviceDnsName)?.deviceDnsName ?? null,
    agent: null,
    description: rec.description ?? rec.title ?? '',
    raw: JSON.stringify(rec),
    iocs: mkIocs([
      ['sha256', fileEv?.fileDetails?.sha256],
      ['sha1', fileEv?.fileDetails?.sha1],
      ['md5', fileEv?.fileDetails?.md5],
      ['url', urlEv?.url],
      ['domain', domainEv?.domainName],
    ]),
  };
}

/**
 * Parser CEF (Common Event Format): CEF:Version|Vendor|Product|Version|
 * SignatureID|Name|Severity|Extension. Extension = pares chave=valor
 * separados por espaço (valores podem conter espaços; '=' escapado como \=).
 */
export function parseCEF(line) {
  const text = String(line ?? '').trim();
  const m = text.match(/CEF:(\d)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(.*)$/);
  if (!m) return null;
  const [, , vendor, product, , sigId, name, sev, ext] = m;
  const extension = {};
  const re = /(\w+)=((?:\\=|\\ |[^\s=])*(?:\s(?!\w+=)\S*)*)/g;
  let em;
  while ((em = re.exec(ext))) {
    extension[em[1]] = em[2].replace(/\\=/g, '=').trim();
  }
  return { vendor, product, sigId, name, sev, extension };
}

export function sevFromCEF(v) {
  const s = String(v ?? '').toLowerCase();
  if (['10', '9', 'critical', 'very-high'].includes(s)) return 'critical';
  if (['8', '7', 'high'].includes(s)) return 'high';
  if (['6', '5', '4', 'medium'].includes(s)) return 'medium';
  if (['3', '2', 'low'].includes(s)) return 'low';
  return 'info';
}

/** Linha CEF crua (string) → evento SOPIR, ou null se não for CEF válido. */
export function normalizeCEF(line) {
  const p = parseCEF(line);
  if (!p) return null;
  const ext = p.extension;
  return {
    ts: tsOr(ext.rt, ext.end, ext.start),
    source: p.vendor && p.product ? `${p.vendor} ${p.product}` : 'CEF',
    rule: p.name || 'Evento CEF',
    ruleId: p.sigId || '',
    severity: sevFromCEF(p.sev),
    srcIp: ext.src ?? null,
    dstIp: ext.dst ?? null,
    user: ext.suser ?? ext.duser ?? null,
    host: ext.dvchost ?? ext.shost ?? ext.dhost ?? null,
    agent: ext.dvc ?? null,
    description: ext.msg ?? p.name ?? '',
    message: String(line) || null,
    raw: JSON.stringify({ cef: String(line) }),
    iocs: mkIocs([
      ['hash', ext.fileHash],
      ['url', ext.request],
      ['domain', !isIPv4(ext.dhost) ? ext.dhost : undefined],
    ]),
  };
}
