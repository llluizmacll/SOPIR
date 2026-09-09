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
// ─────────────────────────────────────────────────────────────

// buffer em memória dos eventos recentes (janela de avaliação)
const BUFFER_MAX = 600;
const buffer = [];

// dedup: `${policyId}|${groupKey}` → ts do último disparo
const cooldown = new Map();

// estatísticas por política (em memória)
const stats = new Map();

const isExternal = (ip) =>
  !!ip && !/^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)/.test(ip);

const has = (ev, ids, rx) => ids.includes(ev.ruleId) || rx.test(ev.rule ?? '');

// ── políticas de correlação ──────────────────────────────────
// `match` filtra eventos candidatos; `qualify` valida o grupo.
export const POLICIES = [
  {
    id: 'COR-BRUTE', name: 'Brute Force', severity: 'high',
    windowSec: 300, threshold: 8, groupBy: ['srcIp'],
    logic: '≥8 falhas de autenticação da mesma origem em 5min',
    match: (ev) => has(ev, ['5716', '5720', '100215'], /brute|falha.*(autentica|login)|authentication fail/i),
    qualify: (g) => g.events.length >= 8,
    title: (g) => `Brute force: ${g.events.length} tentativas de ${g.key.srcIp}`,
  },
  {
    id: 'COR-RANSOM', name: 'Cadeia Ransomware', severity: 'critical',
    windowSec: 600, threshold: 2, groupBy: ['host'],
    logic: '≥2 regras distintas de integridade/mass-modification no mesmo host em 10min',
    match: (ev) => has(ev, ['5503', '5549', '5551'], /shadow copy|mass.*modif|modifica.*massa|integridade/i),
    qualify: (g) => new Set(g.events.map((e) => e.ruleId)).size >= 2,
    title: (g) => `Cadeia de ransomware em ${g.key.host} (${new Set(g.events.map((e) => e.ruleId)).size} técnicas)`,
  },
  {
    id: 'COR-C2', name: 'Beaconing C2', severity: 'critical',
    windowSec: 600, threshold: 5, groupBy: ['host', 'dstIp'],
    logic: '≥5 conexões do mesmo host para um destino externo em 10min',
    match: (ev) => isExternal(ev.dstIp),
    qualify: (g) => g.events.length >= 5,
    title: (g) => `Beaconing C2: ${g.key.host} → ${g.key.dstIp} (${g.events.length} conexões)`,
  },
  {
    id: 'COR-LATERAL', name: 'Movimentação Lateral', severity: 'high',
    windowSec: 900, threshold: 2, groupBy: ['srcIp'],
    logic: 'falha de login seguida de login administrativo bem-sucedido da mesma origem (15min)',
    match: (ev) => has(ev, ['5715', '5716', '5720'], /login admin|falha|authentication/i),
    qualify: (g) => {
      const fail = g.events.some((e) => has(e, ['5716', '5720'], /falha|fail/i));
      const ok = g.events.some((e) => has(e, ['5715'], /bem-sucedido|success/i));
      return fail && ok;
    },
    title: (g) => `Movimentação lateral: login válido após falhas a partir de ${g.key.srcIp}`,
  },
  {
    id: 'COR-PRIVESC', name: 'Escalação de Privilégio', severity: 'high',
    windowSec: 300, threshold: 1, groupBy: ['host'],
    logic: 'criação de usuário após falhas de autenticação no mesmo host (5min)',
    match: (ev) => has(ev, ['5716', '5720', '5901'], /novo usu|user created|falha|fail/i),
    qualify: (g) => {
      const created = g.events.some((e) => has(e, ['5901'], /novo usu|user created/i));
      const fail = g.events.some((e) => has(e, ['5716', '5720'], /falha|fail/i));
      return created && fail;
    },
    title: (g) => `Escalação de privilégio suspeita em ${g.key.host} (usuário criado após falhas)`,
  },
  {
    id: 'COR-DLP', name: 'Exfiltração DNS', severity: 'high',
    windowSec: 600, threshold: 10, groupBy: ['host', 'dstIp'],
    logic: '≥10 consultas/eventos de rede do mesmo host para o mesmo destino externo (10min)',
    match: (ev) => isExternal(ev.dstIp) && has(ev, ['28002', '100240'], /dns|tunnel|exfil|consulta/i),
    qualify: (g) => g.events.length >= 10,
    title: (g) => `Exfiltração DNS: ${g.key.host} → ${g.key.dstIp} (${g.events.length} eventos)`,
  },
];

// inicializa estatísticas
for (const p of POLICIES) stats.set(p.id, { fires: 0, lastFire: null, enabled: true });

const groupKeyOf = (p, ev) => p.groupBy.map((f) => ev[f] ?? '—').join('|');

// ── políticas customizáveis (Detection & Correlation) ────────
// Guardadas no banco (tabela correlation_policies) em formato
// declarativo; convertidas em avaliadores (match/qualify/title) aqui.
import { sql as q, nextCode, addAudit } from './db.js';

const SEV_RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

// Converte uma definição declarativa (do banco) em avaliador.
function toEvaluator(def) {
  const m = def.match ?? {};
  const groupBy = Array.isArray(def.groupBy) ? def.groupBy : (def.group_by ?? ['host']);
  const threshold = Number(def.threshold) || 3;
  const mode = def.mode || 'count';
  const minRank = SEV_RANK[m.minSeverity] ?? 0;

  const match = (ev) => {
    if (m.ruleIdContains && !String(ev.ruleId ?? '').includes(m.ruleIdContains)) return false;
    if (m.ruleContains && !String(ev.rule ?? '').toLowerCase().includes(String(m.ruleContains).toLowerCase())) return false;
    if (m.source && ev.source !== m.source) return false;
    if (m.minSeverity && (SEV_RANK[ev.severity] ?? 0) < minRank) return false;
    if (m.dstExternal && !isExternal(ev.dstIp)) return false;
    if (m.srcExternal && !isExternal(ev.srcIp)) return false;
    return true;
  };

  const qualify = (g) => {
    if (mode === 'distinct') return new Set(g.events.map((e) => e.ruleId)).size >= threshold;
    return g.events.length >= threshold; // 'count'
  };

  const title = (g) => {
    const key = groupBy.map((f) => `${f}=${g.key[f]}`).join(' ');
    return `${def.name}: ${g.events.length} eventos em ${key}`;
  };

  return {
    id: def.code ?? def.id, name: def.name, severity: def.severity,
    windowSec: Number(def.windowSec ?? def.window_sec) || 300,
    threshold, groupBy, logic: def.description || `${mode === 'distinct' ? 'regras distintas' : 'eventos'} ≥ ${threshold} em ${def.windowSec ?? def.window_sec}s`,
    match, qualify, title,
    mode, mitre: def.mitre ?? null, matchDef: m, builtin: false,
  };
}

let customPolicies = []; // avaliadores ativos (custom)

export async function loadCustomPolicies() {
  const r = await q('SELECT * FROM correlation_policies ORDER BY created_at');
  customPolicies = r.rows.map((row) => toEvaluator({
    code: row.code, name: row.name, description: row.description,
    severity: row.severity, windowSec: row.window_sec, threshold: row.threshold,
    groupBy: row.group_by, match: row.match, mode: row.mode, mitre: row.mitre,
  }));
  for (const p of customPolicies) {
    if (!stats.has(p.id)) stats.set(p.id, { fires: 0, lastFire: null, enabled: true });
  }
  return customPolicies.length;
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

export async function deleteCustomPolicy(actor, code, tenant) {
  const r = await q('DELETE FROM correlation_policies WHERE code = $1', [code]);
  if (r.rowCount) {
    await addAudit(actor, 'removeu regra de correlação', code, 'system', tenant);
    stats.delete(code);
    await loadCustomPolicies();
  }
  return r.rowCount > 0;
}

/** Lista todas as políticas (embutidas + custom) em formato serializável. */
function allPolicies() {
  return [...POLICIES, ...customPolicies];
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
    if (!st.enabled || !p.match(ev)) continue;

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
      builtin: p.builtin !== false,
      enabled: st.enabled, fires: st.fires, lastFire: st.lastFire,
    };
  });
}

export function setPolicyEnabled(id, enabled) {
  const st = stats.get(id);
  if (!st) return null;
  st.enabled = !!enabled;
  // persiste o estado para políticas customizadas
  const isCustom = customPolicies.some((p) => p.id === id);
  if (isCustom) {
    q('UPDATE correlation_policies SET enabled = $2 WHERE code = $1', [id, !!enabled]).catch(() => {});
  }
  return listPolicies().find((p) => p.id === id);
}

/**
 * Backtest: executa uma definição de política contra os eventos recentes
 * do buffer (sem criar alertas) e retorna os grupos que teriam disparado.
 */
export function backtest(def) {
  const p = toEvaluator(def);
  const now = Date.now();
  const windowMs = p.windowSec * 1000;
  const groups = new Map();

  for (const ev of buffer) {
    if (now - ev._ts > windowMs) continue;
    if (!p.match(ev)) continue;
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
