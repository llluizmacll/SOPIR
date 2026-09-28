// ─────────────────────────────────────────────────────────────
// SOPIR API · Motor de Correlação por Política
//
// Cada evento normalizado passa pelo motor:
//   evento → janela deslizante → políticas ativas → agrupamento
//          → threshold atingido → alerta (dedup por cooldown)
//
// Diferente do alerta automático por severidade (1 evento = 1
// alerta), aqui o alerta nasce de um PADRÃO: N eventos do mesmo
// grupo dentro da janela, regras distintas em cadeia, destino
// externo etc.
//
// Todas as regras — nativas e customizadas — vivem na tabela
// `correlation_policies`. As nativas são semeadas no boot
// (`ensureBuiltinPolicies`) a partir de `BUILTIN_DEFAULTS` e, a
// partir daí, são linhas normais: podem ser editadas, desativadas
// ou removidas como qualquer regra custom. `restoreBuiltinPolicy`
// e `restoreMissingBuiltins` permitem voltar ao padrão de fábrica.
// ─────────────────────────────────────────────────────────────

import { sql as q, nextCode, addAudit } from './db.js';

// buffer em memória dos eventos recentes (janela de avaliação)
const BUFFER_MAX = 600;
const buffer = [];

// dedup: `${policyId}|${groupKey}` → ts do último disparo
const cooldown = new Map();

// estatísticas por política (em memória — fires/lastFire não persistem)
const stats = new Map();

const isExternal = (ip) =>
  !!ip && !/^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)/.test(ip);

const SEV_RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

// ── definições de fábrica das 6 regras nativas ───────────────
// Formato 100% declarativo — o mesmo usado por regras customizadas.
// `ruleIdIn` / `ruleRegex` casam por OR (id na lista OU regex bate).
// `mode: 'sequence'` exige que TODAS as `conditions` batam em algum
// evento do grupo (ex.: falha de login + sucesso administrativo).
export const BUILTIN_DEFAULTS = [
  {
    code: 'COR-BRUTE', name: 'Brute Force', severity: 'high',
    description: '≥8 falhas de autenticação da mesma origem em 5min',
    windowSec: 300, threshold: 8, groupBy: ['srcIp'], mode: 'count',
    match: { ruleIdIn: ['5716', '5720', '100215'], ruleRegex: '\\bbrute[\\s-]?force\\b|\\bfalha\\b.*\\b(autentica\\w*|login)\\b|\\bauthentication fail' },
  },
  {
    code: 'COR-RANSOM', name: 'Cadeia Ransomware', severity: 'critical',
    description: '≥2 regras distintas de integridade/mass-modification no mesmo host em 10min',
    windowSec: 600, threshold: 2, groupBy: ['host'], mode: 'distinct',
    match: { ruleIdIn: ['5503', '5549', '5551'], ruleRegex: '\\bshadow copy\\b|\\bmass\\w*\\s+modif|\\bmodifica\\w*\\s+em\\s+massa\\b|\\bintegridade\\s+de\\s+arquivo' },
  },
  {
    code: 'COR-C2', name: 'Beaconing C2', severity: 'critical',
    description: '≥5 conexões do mesmo host para um destino externo em 10min',
    windowSec: 600, threshold: 5, groupBy: ['host', 'dstIp'], mode: 'count',
    match: { dstExternal: true },
  },
  {
    code: 'COR-LATERAL', name: 'Movimentação Lateral', severity: 'high',
    description: 'falha de login seguida de login administrativo bem-sucedido da mesma origem (15min)',
    windowSec: 900, threshold: 1, groupBy: ['srcIp'], mode: 'sequence',
    match: { conditions: [
      { ruleIdIn: ['5716', '5720'], ruleRegex: '\\b(login|autentica\\w*|logon)\\b.*\\bfail(ed|ure)?\\b|\\bfail(ed|ure)?\\b.*\\b(login|autentica\\w*|logon)\\b|\\bfalha\\s+de\\s+(login|autentica)' },
      { ruleIdIn: ['5715'], ruleRegex: '\\b(login|autentica\\w*|logon)\\b.*\\bsuccess(ful(ly)?)?\\b|\\bbem[\\s-]sucedido\\b' },
    ] },
  },
  {
    code: 'COR-PRIVESC', name: 'Escalação de Privilégio', severity: 'high',
    description: 'criação de usuário após falhas de autenticação no mesmo host (5min)',
    windowSec: 300, threshold: 1, groupBy: ['host'], mode: 'sequence',
    match: { conditions: [
      { ruleIdIn: ['5901'], ruleRegex: '\\bnovo\\s+usu\\w*\\b|\\buser\\s+created\\b' },
      { ruleIdIn: ['5716', '5720'], ruleRegex: '\\b(login|autentica\\w*|logon)\\b.*\\bfail(ed|ure)?\\b|\\bfail(ed|ure)?\\b.*\\b(login|autentica\\w*|logon)\\b|\\bfalha\\s+de\\s+(login|autentica)' },
    ] },
  },
  {
    code: 'COR-DLP', name: 'Exfiltração DNS', severity: 'high',
    description: '≥10 consultas/eventos de rede do mesmo host para o mesmo destino externo (10min)',
    windowSec: 600, threshold: 10, groupBy: ['host', 'dstIp'], mode: 'count',
    match: { dstExternal: true, ruleIdIn: ['28002', '100240'], ruleRegex: '\\bdns\\s+tunnel\\w*\\b|\\bexfil\\w*\\b|\\bconsulta\\s+dns\\s+(anomal|suspeit)' },
  },
];

const upsertSql = `
  INSERT INTO correlation_policies
    (code,name,description,severity,enabled,window_sec,threshold,group_by,match,mode,mitre,builtin)
  VALUES ($1,$2,$3,$4,true,$5,$6,$7,$8,$9,null,true)
  ON CONFLICT (code) DO %CONFLICT%
`;

async function upsertBuiltin(d, onConflictDoUpdate) {
  const sqlText = upsertSql.replace(
    '%CONFLICT%',
    onConflictDoUpdate
      ? `UPDATE SET name=EXCLUDED.name, description=EXCLUDED.description, severity=EXCLUDED.severity,
           window_sec=EXCLUDED.window_sec, threshold=EXCLUDED.threshold, group_by=EXCLUDED.group_by,
           match=EXCLUDED.match, mode=EXCLUDED.mode, mitre=null, builtin=true`
      : 'NOTHING',
  );
  await q(sqlText, [d.code, d.name, d.description, d.severity, d.windowSec, d.threshold,
    JSON.stringify(d.groupBy), JSON.stringify(d.match), d.mode]);
}

/** Semeia as regras nativas no banco (idempotente — não sobrescreve edições). Roda no boot. */
export async function ensureBuiltinPolicies() {
  for (const d of BUILTIN_DEFAULTS) await upsertBuiltin(d, false);
}

/** Recria no banco qualquer regra nativa que tenha sido removida. Não mexe nas que ainda existem (mesmo editadas). */
export async function restoreMissingBuiltins(actor, tenant) {
  const r = await q('SELECT code FROM correlation_policies WHERE builtin = true');
  const existing = new Set(r.rows.map((row) => row.code));
  const missing = BUILTIN_DEFAULTS.filter((d) => !existing.has(d.code));
  for (const d of missing) await upsertBuiltin(d, false);
  if (missing.length) {
    await addAudit(actor, 'restaurou regra(s) de correlação padrão ausente(s)', missing.map((d) => d.code).join(', '), 'system', tenant);
    await loadCustomPolicies();
  }
  return missing.map((d) => d.code);
}

/** Restaura UMA regra nativa específica ao estado de fábrica — sobrescreve edições e recria se tiver sido removida. */
export async function restoreBuiltinPolicy(actor, code, tenant) {
  const d = BUILTIN_DEFAULTS.find((x) => x.code === code);
  if (!d) return false;
  await upsertBuiltin(d, true);
  await addAudit(actor, 'restaurou regra de correlação ao padrão de fábrica', code, 'system', tenant);
  await loadCustomPolicies();
  return true;
}

const groupKeyOf = (p, ev) => p.groupBy.map((f) => ev[f] ?? '—').join('|');

// Um grupo só é válido se TODOS os campos de agrupamento tiverem valor real —
// eventos sem srcIp/host/etc (comum em logs de sistema tipo systemd, sem
// contexto de rede) não podem ser agrupados só porque "faltou" o mesmo campo
// nos dois. Sem essa guarda, tudo que não tem srcIp cai no mesmo grupo "—"
// e a correlação mistura eventos completamente sem relação entre si.
const hasRealKey = (p, ev) => p.groupBy.every((f) => ev[f] != null && ev[f] !== '—' && ev[f] !== '');

// ── avaliador declarativo único (nativas e custom passam por aqui) ──
function matchesCriteria(ev, m) {
  if (!m) return true;
  if (m.ruleIdIn?.length || m.ruleRegex) {
    const idOk = m.ruleIdIn?.length ? m.ruleIdIn.includes(String(ev.ruleId)) : false;
    const rxOk = m.ruleRegex ? new RegExp(m.ruleRegex, 'i').test(ev.rule ?? '') : false;
    if (!(idOk || rxOk)) return false;
  }
  if (m.ruleIdContains && !String(ev.ruleId ?? '').includes(m.ruleIdContains)) return false;
  if (m.ruleContains && !String(ev.rule ?? '').toLowerCase().includes(String(m.ruleContains).toLowerCase())) return false;
  if (m.source && ev.source !== m.source) return false;
  if (m.minSeverity && (SEV_RANK[ev.severity] ?? 0) < (SEV_RANK[m.minSeverity] ?? 0)) return false;
  if (m.dstExternal && !isExternal(ev.dstIp)) return false;
  if (m.srcExternal && !isExternal(ev.srcIp)) return false;
  return true;
}

// Converte uma linha do banco (nativa ou custom) em avaliador executável.
function toEvaluator(row) {
  const m = row.match ?? {};
  const groupBy = Array.isArray(row.groupBy) ? row.groupBy : (row.group_by ?? ['host']);
  const threshold = Number(row.threshold) || 3;
  const mode = row.mode || 'count';
  const conditions = Array.isArray(m.conditions) ? m.conditions : null;

  const match = (mode === 'sequence' && conditions)
    ? (ev) => conditions.some((c) => matchesCriteria(ev, c))
    : (ev) => matchesCriteria(ev, m);

  const qualify = (g) => {
    if (mode === 'sequence' && conditions) return conditions.every((c) => g.events.some((e) => matchesCriteria(e, c)));
    if (mode === 'distinct') return new Set(g.events.map((e) => e.ruleId)).size >= threshold;
    return g.events.length >= threshold; // 'count'
  };

  const title = (g) => {
    const key = groupBy.map((f) => `${f}=${g.key[f]}`).join(' ');
    if (mode === 'sequence') return `${row.name}: padrão confirmado em ${key}`;
    return `${row.name}: ${g.events.length} eventos em ${key}`;
  };

  return {
    id: row.code ?? row.id, name: row.name, severity: row.severity,
    windowSec: Number(row.windowSec ?? row.window_sec) || 300,
    threshold, groupBy,
    logic: row.description || `${mode === 'distinct' ? 'regras distintas' : mode === 'sequence' ? 'padrão sequencial' : 'eventos'} ≥ ${threshold} em ${row.windowSec ?? row.window_sec}s`,
    match, qualify, title,
    mode, mitre: row.mitre ?? null, matchDef: m, builtin: !!row.builtin,
  };
}

let policies = []; // avaliadores ativos — carregados do banco (nativas + custom)

export async function loadCustomPolicies() {
  const r = await q('SELECT * FROM correlation_policies ORDER BY builtin DESC, created_at');
  policies = r.rows.map((row) => toEvaluator({
    code: row.code, name: row.name, description: row.description,
    severity: row.severity, windowSec: row.window_sec, threshold: row.threshold,
    groupBy: row.group_by, match: row.match, mode: row.mode, mitre: row.mitre,
    builtin: row.builtin,
  }));
  const ids = new Set(r.rows.map((row) => row.code));
  for (const row of r.rows) {
    const st = stats.get(row.code);
    if (!st) stats.set(row.code, { fires: 0, lastFire: null, enabled: row.enabled !== false });
    else st.enabled = row.enabled !== false; // sincroniza com o banco (ex.: toggle feito em outra instância)
  }
  for (const id of [...stats.keys()]) if (!ids.has(id)) stats.delete(id);
  return policies.length;
}

export async function addCustomPolicy(actor, body, tenant) {
  const code = await nextCode('COR', 'seq_correlation');
  const def = {
    code,
    name: body.name || 'Nova regra',
    description: body.description ?? null,
    severity: body.severity || 'medium',
    enabled: body.enabled !== false,
    window_sec: Number(body.windowSec) || 300,
    threshold: Number(body.threshold) || 3,
    group_by: JSON.stringify(body.groupBy?.length ? body.groupBy : ['host']),
    match: JSON.stringify(body.match ?? {}),
    mode: body.mode || 'count',
    mitre: body.mitre ?? null,
    cooldown_sec: body.cooldownSec ? Number(body.cooldownSec) : null,
    builtin: false,
  };
  await q(
    `INSERT INTO correlation_policies
       (code,name,description,severity,enabled,window_sec,threshold,group_by,match,mode,mitre,cooldown_sec,builtin)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,false)`,
    [def.code, def.name, def.description, def.severity, def.enabled, def.window_sec,
     def.threshold, def.group_by, def.match, def.mode, def.mitre, def.cooldown_sec],
  );
  await addAudit(actor, 'criou regra de correlação', `${def.code} · ${def.name}`, 'system', tenant);
  await loadCustomPolicies();
  return def.code;
}

// Atualiza qualquer regra (nativa ou custom) pelo código. Regras nativas
// editadas continuam marcadas builtin=true (aparecem como "nativa" na UI,
// mas com a lógica alterada) — podem ser restauradas via restoreBuiltinPolicy.
export async function updateCustomPolicy(actor, code, body, tenant) {
  const sets = []; const params = [];
  const add = (col, val) => { if (val !== undefined) { params.push(val); sets.push(`${col} = $${params.length}`); } };
  add('name', body.name); add('description', body.description); add('severity', body.severity);
  add('enabled', body.enabled);
  if (body.windowSec !== undefined) add('window_sec', Number(body.windowSec));
  if (body.threshold !== undefined) add('threshold', Number(body.threshold));
  if (body.groupBy) add('group_by', JSON.stringify(body.groupBy));
  if (body.match) add('match', JSON.stringify(body.match));
  if (body.mode) add('mode', body.mode);
  if (body.mitre !== undefined) add('mitre', body.mitre);
  if (!sets.length) return false;
  params.push(code);
  const r = await q(`UPDATE correlation_policies SET ${sets.join(', ')} WHERE code = $${params.length}`, params);
  if (r.rowCount) {
    await addAudit(actor, 'atualizou regra de correlação', code, 'system', tenant);
    await loadCustomPolicies();
  }
  return r.rowCount > 0;
}

// Remove qualquer regra (nativa ou custom) pelo código. Uma nativa removida
// some da lista até ser recriada via restoreBuiltinPolicy/restoreMissingBuiltins.
export async function deleteCustomPolicy(actor, code, tenant) {
  const r = await q('DELETE FROM correlation_policies WHERE code = $1', [code]);
  if (r.rowCount) {
    await addAudit(actor, 'removeu regra de correlação', code, 'system', tenant);
    stats.delete(code);
    await loadCustomPolicies();
  }
  return r.rowCount > 0;
}

function allPolicies() {
  return policies;
}

/**
 * Avalia um evento normalizado contra todas as políticas ativas.
 * Retorna a lista de disparos: [{ policy, group, events }].
 */
export function correlate(ev, tenant) {
  buffer.push({ ...ev, tenant, _ts: ev.ts || Date.now() });
  if (buffer.length > BUFFER_MAX) buffer.shift();

  const now = Date.now();
  const fired = [];

  for (const p of allPolicies()) {
    const st = stats.get(p.id) ?? { enabled: true, fires: 0, lastFire: null };
    if (!st.enabled || !p.match(ev) || !hasRealKey(p, ev)) continue;

    const windowMs = p.windowSec * 1000;
    const candidates = buffer.filter(
      (e) => e.tenant === tenant && now - e._ts <= windowMs && p.match(e) &&
        p.groupBy.every((f) => (e[f] ?? '—') === (ev[f] ?? '—')),
    );

    const group = { events: candidates, key: Object.fromEntries(p.groupBy.map((f) => [f, ev[f] ?? '—'])) };
    if (!p.qualify(group)) continue;

    const cdKey = `${p.id}|${groupKeyOf(p, ev)}`;
    const last = cooldown.get(cdKey) ?? 0;
    if (now - last < windowMs) continue; // ainda em cooldown
    cooldown.set(cdKey, now);

    st.fires += 1;
    st.lastFire = now;
    fired.push({ policy: p, group });
  }

  // poda cooldowns antigos
  if (cooldown.size > 400) {
    for (const [k, ts] of cooldown) if (now - ts > 30 * 60_000) cooldown.delete(k);
  }
  return fired;
}

export function listPolicies() {
  return allPolicies().map((p) => {
    const st = stats.get(p.id) ?? { enabled: true, fires: 0, lastFire: null };
    return {
      id: p.id, name: p.name, severity: p.severity,
      windowSec: p.windowSec, threshold: p.threshold,
      groupBy: Array.isArray(p.groupBy) ? p.groupBy : [p.groupBy],
      groupByLabel: (Array.isArray(p.groupBy) ? p.groupBy : [p.groupBy]).join(' + '),
      logic: p.logic, mitre: p.mitre ?? null,
      mode: p.mode ?? null, matchDef: p.matchDef ?? null,
      builtin: p.builtin === true,
      enabled: st.enabled, fires: st.fires, lastFire: st.lastFire,
    };
  });
}

export function setPolicyEnabled(id, enabled) {
  const st = stats.get(id);
  if (!st) return null;
  st.enabled = !!enabled;
  q('UPDATE correlation_policies SET enabled = $2 WHERE code = $1', [id, !!enabled]).catch(() => {});
  return listPolicies().find((p) => p.id === id);
}

/**
 * Backtest: executa uma definição de política contra os eventos recentes
 * do buffer (sem criar alertas) e retorna os grupos que teriam disparado.
 */
export function backtest(def) {
  const p = toEvaluator({ ...def, group_by: def.groupBy, window_sec: def.windowSec });
  const now = Date.now();
  const windowMs = p.windowSec * 1000;
  const groups = new Map();

  for (const ev of buffer) {
    if (now - ev._ts > windowMs) continue;
    if (!p.match(ev) || !hasRealKey(p, ev)) continue;
    const key = p.groupBy.map((f) => ev[f] ?? '—').join('|');
    if (!groups.has(key)) {
      groups.set(key, { key: Object.fromEntries(p.groupBy.map((f) => [f, ev[f] ?? '—'])), events: [] });
    }
    groups.get(key).events.push(ev);
  }

  const fired = [];
  for (const g of groups.values()) {
    if (p.qualify(g)) {
      fired.push({ title: p.title(g), count: g.events.length, key: g.key });
    }
  }
  return { policy: p.name, windowSec: p.windowSec, threshold: p.threshold, evaluated: buffer.length, firedCount: fired.length, fired: fired.slice(0, 20) };
}

/** Snapshot do buffer para agregações/risco (eventos recentes). */
export function recentEvents(limit = 600) {
  return buffer.slice(-limit);
}
