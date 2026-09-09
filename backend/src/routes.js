// ─────────────────────────────────────────────────────────────
// SOPIR API · rotas REST (respostas em camelCase, id = código)
// ─────────────────────────────────────────────────────────────
import { Router } from 'express';
import { sql, nextCode, addAudit, computeHash } from './db.js';
import { computeIncidentSla, getSlaMetrics, getSlaPolicy, sevToPriority, DEFAULT_SLA } from './sla.js';
import { CASE_STAGES, CASE_SLA_MIN, CASE_TEMPLATES, stageDurations, getCaseMetrics, backfillCases } from './casemgmt.js';
import { ingestNormalized, getIngestStats } from './ingest.js';
import { normalizeGeneric } from './normalize.js';
import { connectorStatus } from './connectors/scheduler.js';
import { PLAYBOOKS, startRun, approveRun, rejectRun } from './playbook-engine.js';
import { expandGraph } from './graph.js';
import { requireAuth, requirePerm, effectiveTenant, canPerms } from './auth.js';
import {
  listPolicies, setPolicyEnabled, addCustomPolicy, updateCustomPolicy,
  deleteCustomPolicy, backtest,
} from './correlator.js';
import { computeRiskScores, aggregateEvents } from './risk.js';

const r = Router();
const wrap = (fn) => (req, res) => fn(req, res).catch((err) => {
  console.error('[api] ' + err.message);
  res.status(500).json({ error: err.message });
});

// Escopo de tenant: Customer fica preso ao tenant do token; staff usa ?tenant=.
const tenantOf = (req) => {
  const t = effectiveTenant(req);
  return t === 'all' ? null : t;
};
const actorOf = (req) => req.auth?.name ?? 'sistema';

// ── serializers (linha DB → modelo SOPIR do frontend) ────────
const evRow = (x) => ({
  id: x.code, ts: Date.parse(x.ts), tenant: x.tenant, env: x.env ?? null, source: x.source,
  rule: x.rule, ruleId: x.rule_id ?? '', severity: x.severity,
  srcIp: x.src_ip ?? '—', dstIp: x.dst_ip ?? '—', user: x.app_user ?? '—',
  host: x.host ?? '—', agent: x.agent ?? '—', desc: x.description ?? '',
  raw: typeof x.raw === 'string' ? x.raw : JSON.stringify(x.raw ?? {}),
});
const alRow = (x) => ({
  id: x.code, tenant: x.tenant, env: x.env ?? null, title: x.title, severity: x.severity, status: x.status,
  source: x.source ?? '—', rule: x.rule ?? '', ruleId: x.rule_id ?? '',
  srcIp: x.src_ip ?? '—', dstIp: x.dst_ip ?? '—', user: x.app_user ?? '—',
  host: x.host ?? '—', ts: Date.parse(x.ts), desc: x.description ?? '',
  assignee: x.assignee ?? undefined, classification: x.classification ?? undefined,
  incidentId: x.incident_code ?? undefined,
});
const vuRow = (x) => ({
  id: x.code, cve: x.cve, tenant: x.tenant, env: x.env ?? null, title: x.title,
  cvss: Number(x.cvss), severity: x.severity, asset: x.asset ?? '—',
  status: x.status, found: Date.parse(x.found_ts), fix: x.fix ?? '',
});
const asRow = (x) => ({
  id: x.code, tenant: x.tenant, env: x.env ?? null, name: x.name, type: x.type, ip: x.ip,
  os: x.os, crit: x.crit, status: x.status, owner: x.owner,
});
const runRow = (x) => ({
  id: x.code, pbId: x.pb_id, pbName: x.pb_name, step: x.step,
  status: x.status, ts: Date.parse(x.ts), tenant: x.tenant ?? 'all', actor: x.actor,
});
const auRow = (x) => ({
  id: 'AU-' + x.id, ts: Date.parse(x.ts), actor: x.actor,
  action: x.action, target: x.target ?? '', kind: x.kind,
  tenant: x.tenant ?? null, ip: x.ip ?? null, ua: x.ua ?? null, sid: x.sid ?? null,
  outcome: x.outcome ?? 'ok', before: x.before ?? null, after: x.after ?? null,
  control: x.control ?? null, hash: x.hash ?? null, prevHash: x.prev_hash ?? null, tsMs: Number(x.ts_ms ?? Date.parse(x.ts)),
});

async function fullIncident(x) {
  const [tasks, tl, iocs, als] = await Promise.all([
    sql('SELECT id, text, done FROM incident_tasks WHERE inc_code=$1 ORDER BY id', [x.code]),
    sql('SELECT ts, text, kind, author FROM incident_timeline WHERE inc_code=$1 ORDER BY ts', [x.code]),
    sql('SELECT ioc FROM incident_iocs WHERE inc_code=$1', [x.code]),
    sql('SELECT alert_code FROM incident_alerts WHERE inc_code=$1', [x.code]),
  ]);
  const sla = await computeIncidentSla(x).catch(() => null);
  return {
    id: x.code, tenant: x.tenant, env: x.env ?? null, title: x.title,
    severity: x.severity, priority: x.priority ?? sevToPriority(x.severity), status: x.status,
    assignee: x.assignee ?? '—', ts: Date.parse(x.ts), slaH: x.sla_h,
    firstResponseAt: x.first_response_at ? Date.parse(x.first_response_at) : null,
    resolvedAt: x.resolved_at ? Date.parse(x.resolved_at) : null,
    sla,
    asset: x.asset ?? undefined, caseId: x.case_code ?? undefined,
    iocs: iocs.rows.map((i) => i.ioc),
    tasks: tasks.rows.map((t) => ({ id: String(t.id), text: t.text, done: t.done })),
    timeline: tl.rows.map((t) => ({ ts: Date.parse(t.ts), text: t.text, kind: t.kind, author: t.author ?? undefined })),
    alertIds: als.rows.map((a) => a.alert_code),
  };
}

async function fullCase(x) {
  const [refs, comments, tasks, timeline] = await Promise.all([
    sql('SELECT kind, value FROM case_refs WHERE case_code=$1 ORDER BY id', [x.code]),
    sql('SELECT ts, author, text FROM case_comments WHERE case_code=$1 ORDER BY ts', [x.code]),
    sql('SELECT id, text, done FROM case_tasks WHERE case_code=$1 ORDER BY id', [x.code]),
    sql('SELECT ts, text, kind, author FROM case_timeline WHERE case_code=$1 ORDER BY ts', [x.code]),
  ]);
  const by = (k) => refs.rows.filter((q) => q.kind === k).map((q) => q.value);
  const openedMs = x.opened_at ? Date.parse(x.opened_at) : Date.parse(x.ts);
  const slaMin = CASE_SLA_MIN[x.severity] ?? CASE_SLA_MIN.medium;
  const endMs = x.closed_at ? Date.parse(x.closed_at) : Date.now();
  const isClosed = x.status === 'closed' || x.stage === 'Encerrado';
  const elapsed = endMs - openedMs;
  const durations = await stageDurations(x.code, x.stage, openedMs).catch(() => null);
  return {
    id: x.code, tenant: x.tenant, title: x.title, severity: x.severity,
    priority: x.priority ?? null, stage: x.stage, status: x.status ?? 'active',
    assignee: x.assignee ?? '—', ts: Date.parse(x.ts),
    openedAt: openedMs, closedAt: x.closed_at ? Date.parse(x.closed_at) : null,
    slaMin, slaBreached: !isClosed && elapsed > slaMin * 60_000,
    stageDurations: durations,
    alertIds: by('alert'), incidentIds: by('incident'), assetNames: by('asset'),
    iocs: by('ioc'), evidence: by('evidence'),
    tasks: tasks.rows.map((t) => ({ id: String(t.id), text: t.text, done: t.done })),
    timeline: timeline.rows.map((t) => ({ ts: Date.parse(t.ts), text: t.text, kind: t.kind, author: t.author ?? undefined })),
    comments: comments.rows.map((c) => ({ ts: Date.parse(c.ts), author: c.author ?? '—', text: c.text })),
  };
}

// ── health / bootstrap ───────────────────────────────────────
r.get('/health', (req, res) => res.json({ ok: true, service: 'sopir-api', version: '0.3.0', uptime: process.uptime() }));

// ── ingestão push (webhook / FortiSIEM notify) — protegida por API-key, não JWT ──
r.post('/ingest', wrap(async (req, res) => {
  const key = process.env.SOPIR_INGEST_KEY;
  if (key && req.header('X-Api-Key') !== key) {
    return res.status(401).json({ error: 'X-Api-Key inválida' });
  }
  const list = Array.isArray(req.body) ? req.body : req.body?.events ?? [req.body];
  let accepted = 0;
  for (const p of list) {
    if (!p || typeof p !== 'object') continue;
    const ev = normalizeGeneric(p);
    const tenant = p.tenant || 'vetra';
    const env = p.env ?? null;
    const extId = p.extId ?? p.id ?? null;
    const code = await ingestNormalized(ev, extId, tenant, env);
    if (code) accepted += 1;
  }
  res.json({ accepted });
}));

// ── gate de autenticação: todas as rotas abaixo exigem JWT válido ──
r.use(requireAuth);

// ── RBAC: permissão exigida por método + rota (espelha o frontend) ──
const PERM_RULES = [
  { m: ['POST', 'PATCH', 'DELETE'], rx: /^\/alerts/, perm: 'alerts.update' },
  { m: ['POST', 'PATCH', 'DELETE'], rx: /^\/incidents/, perm: 'incidents.update' },
  { m: ['POST', 'PATCH', 'DELETE'], rx: /^\/cases/, perm: 'cases.update' },
  { m: ['PATCH', 'POST', 'DELETE'], rx: /^\/vulnerabilities/, perm: 'vulns.update' },
  { m: ['PATCH', 'POST', 'DELETE'], rx: /^\/assets/, perm: 'assets.update' },
  { m: ['POST'], rx: /^\/playbooks\/[^/]+\/run/, perm: 'response.execute' },
  { m: ['POST'], rx: /^\/runs\/[^/]+\/(approve|reject)/, perm: 'response.approve' },
  { m: ['PATCH', 'POST', 'PUT', 'DELETE'], rx: /^\/correlations(?!\/backtest)/, perm: 'correlations.update' },
  { m: ['POST'], rx: /^\/reports/, perm: 'reports.export' },
  { m: ['PUT', 'POST', 'PATCH', 'DELETE'], rx: /^\/sla\/policies/, perm: 'sla.update' },
];
r.use((req, res, next) => {
  const rule = PERM_RULES.find((x) => x.m.includes(req.method) && x.rx.test(req.path));
  if (rule && !canPerms(req.auth.perms, rule.perm)) {
    return res.status(403).json({ error: `permissão negada: requer ${rule.perm}` });
  }
  return next();
});

// ── ISOLAMENTO: recurso direto (PATCH/DELETE por ID) precisa pertencer ao tenant ──
// Listagens (GET) já são filtradas por tenant; aqui fechamos a porta do acesso
// direto a um código específico de outro cliente.
const OWNER_TABLES = {
  incidents: 'code', cases: 'code', alerts: 'code',
  vulnerabilities: 'code', assets: 'name', playbook_runs: 'code',
};
r.use(async (req, res, next) => {
  try {
    if (req.method === 'GET') return next();
    const m = req.path.match(/^\/(incidents|cases|alerts|vulnerabilities|assets|playbook_runs)\/([^/]+)/);
    if (!m) return next();
    const t = tenantOf(req);
    if (!t) return next(); // escopo MSSP (staff global) — segue sem restrição
    const col = OWNER_TABLES[m[1]];
    const own = await sql(`SELECT tenant FROM ${m[1]} WHERE ${col} = $1`, [decodeURIComponent(m[2])]);
    if (own.rowCount && own.rows[0].tenant !== t) {
      await addAudit(actorOf(req), 'tentativa de acesso entre tenants bloqueada', `${m[1]}/${m[2]} (tenant: ${t})`, 'auth', t, { outcome: 'denied' }).catch(() => {});
      return res.status(403).json({ error: 'recurso pertence a outro tenant — acesso negado' });
    }
    return next();
  } catch (err) {
    return next(err);
  }
});

r.get('/bootstrap', wrap(async (req, res) => {
  const t = tenantOf(req);
  const where = t ? ' WHERE tenant = $1' : '';
  const params = t ? [t] : [];

  const [events, alerts, incidents, cases, vulns, assets, runs, audit, tenants, orgs, envs, connectors] = await Promise.all([
    sql(`SELECT * FROM events${where} ORDER BY ts DESC LIMIT 300`, params),
    sql(`SELECT * FROM alerts${where} ORDER BY ts DESC LIMIT 200`, params),
    sql(`SELECT * FROM incidents${where} ORDER BY ts DESC LIMIT 50`, params),
    sql(`SELECT * FROM cases${where} ORDER BY ts DESC LIMIT 50`, params),
    sql(`SELECT * FROM vulnerabilities${where} ORDER BY cvss DESC LIMIT 100`, params),
    sql(`SELECT * FROM assets${where} ORDER BY crit DESC`, params),
    sql(`SELECT * FROM playbook_runs${where} ORDER BY ts DESC LIMIT 20`, params),
    sql('SELECT * FROM audit ORDER BY ts DESC LIMIT 60'),
    sql('SELECT * FROM tenants ORDER BY id'),
    sql('SELECT * FROM orgs ORDER BY id'),
    sql(`SELECT * FROM environments${where} ORDER BY tenant, created`, params),
    connectorStatus(),
  ]);

  const envRow = (x) => ({ id: x.code, tenant: x.tenant, name: x.name, kind: x.kind });
  res.json({
    tenants: tenants.rows.map((x) => ({ id: x.id, name: x.name, short: x.short, orgId: x.org_id ?? null, brandColor: x.brand_color ?? null })),
    orgs: orgs.rows.map((x) => ({ id: x.id, name: x.name, short: x.short })),
    environments: envs.rows.map(envRow),
    events: events.rows.map(evRow),
    alerts: alerts.rows.map(alRow),
    incidents: await Promise.all(incidents.rows.map(fullIncident)),
    cases: await Promise.all(cases.rows.map(fullCase)),
    vulns: vulns.rows.map(vuRow),
    assets: assets.rows.map(asRow),
    runs: runs.rows.map(runRow),
    audit: audit.rows.map(auRow),
    eps: connectors.epsBySource,
    connectors: connectors.connectors,
  });
}));

// ── eventos ──────────────────────────────────────────────────
r.get('/events', wrap(async (req, res) => {
  const { q, severity, source, tenant, env, from, to, limit = 200, offset = 0 } = req.query;
  const clauses = [];
  const params = [];
  const push = (clause, ...vals) => { clauses.push(clause.replace('?', `$${params.push(...vals)}`)); };
  if (tenant && tenant !== 'all') push('tenant = ?', tenant);
  if (env && env !== 'all') push('env = ?', env);
  if (severity && severity !== 'all') push('severity = ?', severity);
  if (source && source !== 'all') push('source = ?', source);
  if (from) push('ts >= to_timestamp(?::numeric / 1000)', from);
  if (to) push('ts <= to_timestamp(?::numeric / 1000)', to);
  if (q) {
    const like = `%${q}%`;
    params.push(like, like, like, like, like);
    const n = params.length;
    clauses.push(`(rule ILIKE $${n - 4} OR host ILIKE $${n - 3} OR src_ip ILIKE $${n - 2} OR app_user ILIKE $${n - 1} OR rule_id ILIKE $${n})`);
  }
  const where = clauses.length ? ' WHERE ' + clauses.join(' AND ') : '';
  const rows = await sql(
    `SELECT * FROM events${where} ORDER BY ts DESC LIMIT $${params.push(Number(limit))} OFFSET $${params.push(Number(offset))}`,
    params,
  );
  res.json(rows.rows.map(evRow));
}));

r.get('/events/:id/related', wrap(async (req, res) => {
  const ev = await sql('SELECT * FROM events WHERE code = $1', [req.params.id]);
  if (!ev.rowCount) return res.status(404).json({ error: 'evento não encontrado' });
  const base = ev.rows[0];
  const rel = await sql(
    `SELECT * FROM events
      WHERE code <> $1 AND (host = $2 OR src_ip = $3 OR app_user = $4)
        AND host IS NOT NULL
      ORDER BY ts DESC LIMIT 8`,
    [base.code, base.host, base.src_ip, base.app_user],
  );
  res.json(rel.rows.map(evRow));
}));

// ── alertas ──────────────────────────────────────────────────
r.get('/alerts', wrap(async (req, res) => {
  const t = tenantOf(req);
  const rows = await sql(
    `SELECT * FROM alerts${t ? ' WHERE tenant = $1' : ''} ORDER BY ts DESC LIMIT 300`,
    t ? [t] : [],
  );
  res.json(rows.rows.map(alRow));
}));

r.post('/alerts', wrap(async (req, res) => {
  const { eventId } = req.body ?? {};
  const ev = await sql('SELECT * FROM events WHERE code = $1', [eventId]);
  if (!ev.rowCount) return res.status(404).json({ error: 'evento não encontrado' });
  const e = ev.rows[0];
  const code = await nextCode('ALT', 'seq_alerts');
  await sql(
    `INSERT INTO alerts (code, tenant, title, severity, status, source, rule, rule_id,
       src_ip, dst_ip, app_user, host, ts, description)
     VALUES ($1,$2,$3,$4,'novo',$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
    [code, e.tenant, e.rule, e.severity, e.source, e.rule, e.rule_id,
     e.src_ip, e.dst_ip, e.app_user, e.host, e.ts, e.description],
  );
  await addAudit(req.header('X-Sopir-User') || 'analista', 'criou alerta a partir de evento', `${code} ← ${eventId}`, 'triage', e.tenant);
  res.json({ id: code });
}));

// ── supressão de alertas (event management) ──────────────────
r.get('/alerts/suppression', wrap(async (req, res) => {
  const rows = await sql('SELECT * FROM suppression_rules ORDER BY created_at DESC');
  res.json(rows.rows.map((r) => ({
    id: r.id, ruleId: r.rule_id ?? null, host: r.host ?? null, srcIp: r.src_ip ?? null,
    reason: r.reason ?? '', tenant: r.tenant ?? null, enabled: r.enabled,
    expiresAt: Date.parse(r.expires_at), createdAt: Date.parse(r.created_at),
  })));
}));

r.post('/alerts/suppression', wrap(async (req, res) => {
  const { ruleId, host, srcIp, reason = '', tenant = null, durationMin = 60 } = req.body ?? {};
  if (!ruleId && !host && !srcIp) return res.status(400).json({ error: 'informe ao menos um critério (regra, host ou IP)' });
  const expires = new Date(Date.now() + Number(durationMin) * 60_000).toISOString();
  const r = await sql(
    `INSERT INTO suppression_rules (rule_id, host, src_ip, reason, tenant, expires_at)
     VALUES ($1,$2,$3,$4,$5,$6) RETURNING id`,
    [ruleId ?? null, host ?? null, srcIp ?? null, reason, tenant, expires]);
  await addAudit(req.header('X-Sopir-User') || 'analista', 'criou regra de supressão',
    [ruleId, host, srcIp].filter(Boolean).join(' · ') + ` (${durationMin}min)`, 'triage', tenant);
  res.json({ id: r.rows[0].id });
}));

r.delete('/alerts/suppression/:id', wrap(async (req, res) => {
  await sql('DELETE FROM suppression_rules WHERE id = $1', [req.params.id]);
  await addAudit(req.header('X-Sopir-User') || 'analista', 'removeu regra de supressão', '#' + req.params.id, 'triage', null);
  res.json({ ok: true });
}));

r.patch('/alerts/suppression/:id', wrap(async (req, res) => {
  const { enabled } = req.body ?? {};
  await sql('UPDATE suppression_rules SET enabled = $2 WHERE id = $1', [req.params.id, !!enabled]);
  res.json({ ok: true });
}));

// ── centro de ingestão (pipeline visível + teste) ────────────
r.get('/ingest/stats', requirePerm('correlations.read'), wrap(async (req, res) => {
  const [recent, perSource, stats] = await Promise.all([
    sql('SELECT * FROM events ORDER BY ts DESC LIMIT 20'),
    sql(`SELECT source, count(*)::int AS n FROM events WHERE ts > now() - interval '60 seconds' GROUP BY source`),
    Promise.resolve(getIngestStats()),
  ]);
  const epsBySource = {};
  for (const r of perSource.rows) epsBySource[r.source] = r.n;
  res.json({ recent: recent.rows.map(evRow), epsBySource, pipeline: stats });
}));

r.post('/ingest/test', requirePerm('correlations.update'), wrap(async (req, res) => {
  const { event } = req.body ?? {};
  if (!event) return res.status(400).json({ error: 'informe o evento' });
  const ev = normalizeGeneric(event);
  const tenant = event.tenant || 'vetra';
  const extId = `test:${Date.now()}:${Math.random().toString(36).slice(2, 8)}`;
  const out = await ingestNormalized(ev, extId, tenant, event.env ?? null);
  res.json({
    accepted: Boolean(out),
    code: out?.code ?? null,
    severity: ev.severity,
    alertCreated: out?.alertCreated ?? null,
    correlationsFired: out?.correlationsFired ?? 0,
    note: !out ? 'evento duplicado (dedup)' : (out.alertCreated ? 'alerta automático gerado' : 'evento crítico/baixo sem alerta (supressão ou severidade)'),
  });
}));

r.patch('/alerts/:id', wrap(async (req, res) => {
  const { status, assignee, classification, incidentId } = req.body ?? {};
  const before = await sql('SELECT status, assignee, classification, incident_code FROM alerts WHERE code=$1', [req.params.id]);
  const sets = [];
  const params = [];
  const add = (col, val) => { if (val !== undefined) { params.push(val); sets.push(`${col} = $${params.length}`); } };
  add('status', status); add('assignee', assignee); add('classification', classification); add('incident_code', incidentId);
  if (!sets.length) return res.json({ ok: true });
  params.push(req.params.id);
  await sql(`UPDATE alerts SET ${sets.join(', ')} WHERE code = $${params.length}`, params);
  const actor = req.header('X-Sopir-User') || 'analista';
  const b = before.rows[0] ?? {};
  const changes = [];
  if (status && status !== b.status) changes.push(`status ${b.status ?? '—'} → ${status}`);
  if (assignee && assignee !== b.assignee) changes.push(`responsável → ${assignee}`);
  if (classification && classification !== b.classification) changes.push(`classificação → ${classification}`);
  if (incidentId && incidentId !== b.incident_code) changes.push(`incidente → ${incidentId}`);
  await addAudit(actor, 'atualizou alerta' + (changes.length ? ` (${changes.join('; ')})` : ''), req.params.id, 'triage', null,
    { before: b, after: { status, assignee, classification, incident_code: incidentId } }).catch(() => {});
  res.json({ ok: true });
}));

r.post('/alerts/:id/escalate', wrap(async (req, res) => {
  const { title, severity } = req.body ?? {};
  const a = await sql('SELECT * FROM alerts WHERE code = $1', [req.params.id]);
  if (!a.rowCount) return res.status(404).json({ error: 'alerta não encontrado' });
  const alert = a.rows[0];
  const sev = severity || alert.severity;
  const pol = await getSlaPolicy(alert.tenant, sev);
  const slaH = Math.max(1, Math.round(pol.resolution_min / 60));
  const incCode = await nextCode('INC', 'seq_incidents').catch(() => null);
  const code = incCode || 'INC-' + Date.now();
  await sql(
    `INSERT INTO incidents (code, tenant, title, severity, priority, status, assignee, ts, sla_h, asset)
     VALUES ($1,$2,$3,$4,$5,'aberto',$6, now(), $7, $8)`,
    [code, alert.tenant, title || alert.title, sev, sevToPriority(sev),
     req.header('X-Sopir-User') || 'analista', slaH, alert.host],
  );
  await sql('INSERT INTO incident_alerts (inc_code, alert_code) VALUES ($1,$2) ON CONFLICT DO NOTHING', [code, alert.code]);
  await sql(
    'INSERT INTO incident_timeline (inc_code, ts, text, kind) VALUES ($1, now(), $2, $3)',
    [code, `Incidente criado a partir do alerta ${alert.code}`, 'system'],
  );
  await sql('UPDATE alerts SET status=$2, incident_code=$3 WHERE code=$1', [alert.code, 'escalado', code]);
  await addAudit(req.header('X-Sopir-User') || 'analista', 'escalou alerta para incidente', `${alert.code} → ${code}`, 'triage', alert.tenant);
  res.json({ incidentId: code });
}));

// ── incidentes ───────────────────────────────────────────────
r.get('/incidents', wrap(async (req, res) => {
  const t = tenantOf(req);
  const rows = await sql(`SELECT * FROM incidents${t ? ' WHERE tenant = $1' : ''} ORDER BY ts DESC`, t ? [t] : []);
  res.json(await Promise.all(rows.rows.map(fullIncident)));
}));

r.post('/incidents', wrap(async (req, res) => {
  const { title, severity = 'high', priority, desc, asset } = req.body ?? {};
  if (!title) return res.status(400).json({ error: 'title obrigatório' });
  const tenant = tenantOf(req) || 'vetra';
  const pol = await getSlaPolicy(tenant, severity);
  const slaH = Math.max(1, Math.round(pol.resolution_min / 60));
  const code = await nextCode('INC', 'seq_incidents').catch(() => 'INC-' + Date.now());
  const actor = req.header('X-Sopir-User') || 'analista';
  await sql(
    `INSERT INTO incidents (code, tenant, title, severity, priority, status, assignee, ts, sla_h, asset)
     VALUES ($1,$2,$3,$4,$5,'aberto',$6, now(), $7, $8)`,
    [code, tenant, title, severity, priority || sevToPriority(severity), actor, slaH, asset ?? null],
  );
  if (desc) {
    await sql('INSERT INTO incident_timeline (inc_code, ts, text, kind, author) VALUES ($1, now(), $2, $3, $4)',
      [code, desc, 'user', actor]);
  }
  await sql('INSERT INTO incident_timeline (inc_code, ts, text, kind) VALUES ($1, now(), $2, $3)',
    [code, 'Incidente aberto manualmente', 'system']);
  await addAudit(actor, 'abriu incidente manualmente', code, 'triage', tenantOf(req));
  res.json({ id: code });
}));

r.patch('/incidents/:id', wrap(async (req, res) => {
  const { status, severity, priority, assignee, note, log } = req.body ?? {};
  const actor = req.header('X-Sopir-User') || 'analista';
  const before = await sql(
    'SELECT status, severity, assignee, priority, first_response_at, resolved_at, tenant FROM incidents WHERE code=$1',
    [req.params.id]);
  const b = before.rows[0] ?? {};
  const sets = [];
  const params = [];
  const add = (col, val) => { if (val !== undefined) { params.push(val); sets.push(`${col} = $${params.length}`); } };
  add('status', status); add('severity', severity); add('priority', priority); add('assignee', assignee);
  if (severity) {
    // SLA de resolução vem da política do tenant (horas, compatibilidade)
    const pol = await getSlaPolicy(b.tenant ?? 'vetra', severity);
    add('sla_h', Math.max(1, Math.round(pol.resolution_min / 60)));
  }
  // carimbo de primeira resposta: primeiro movimento de status saindo de 'aberto'
  if (status && status !== 'aberto' && b.status === 'aberto' && !b.first_response_at) {
    add('first_response_at', new Date().toISOString());
  }
  // carimbo de resolução; reabertura limpa o carimbo
  if (status && ['resolvido', 'fechado'].includes(status) && !b.resolved_at) {
    add('resolved_at', new Date().toISOString());
  } else if (status && !['resolvido', 'fechado'].includes(status) && b.resolved_at) {
    sets.push('resolved_at = NULL');
  }
  if (sets.length) {
    params.push(req.params.id);
    await sql(`UPDATE incidents SET ${sets.join(', ')} WHERE code = $${params.length}`, params);
  }
  const text = note || log;
  if (text) {
    await sql('INSERT INTO incident_timeline (inc_code, ts, text, kind, author) VALUES ($1, now(), $2, $3, $4)',
      [req.params.id, text, 'user', actor]);
  }
  if (log) await addAudit(actor, log, req.params.id, 'triage', null,
    { before: b, after: { status, severity, assignee } }).catch(() => {});
  res.json({ ok: true });
}));

r.patch('/incidents/:id/tasks/:taskId', wrap(async (req, res) => {
  const { done } = req.body ?? {};
  await sql('UPDATE incident_tasks SET done = $1 WHERE id = $2 AND inc_code = $3',
    [Boolean(done), req.params.taskId, req.params.id]);
  res.json({ ok: true });
}));

r.post('/incidents/:id/case', wrap(async (req, res) => {
  const inc = await sql('SELECT * FROM incidents WHERE code = $1', [req.params.id]);
  if (!inc.rowCount) return res.status(404).json({ error: 'incidente não encontrado' });
  const i = inc.rows[0];
  const code = await nextCode('CASE', 'seq_cases').catch(() => 'CASE-' + Date.now());
  const actor = req.header('X-Sopir-User') || 'analista';
  await sql(
    `INSERT INTO cases (code, tenant, title, severity, stage, assignee, ts)
     VALUES ($1,$2,$3,$4,'Triagem',$5, now())`,
    [code, i.tenant, i.title, i.severity, i.assignee],
  );
  await sql('INSERT INTO case_refs (case_code, kind, value) VALUES ($1,$2,$3)', [code, 'incident', i.code]);
  if (i.asset) await sql('INSERT INTO case_refs (case_code, kind, value) VALUES ($1,$2,$3)', [code, 'asset', i.asset]);
  await sql('UPDATE incidents SET case_code = $2 WHERE code = $1', [i.code, code]);
  await addAudit(actor, 'abriu case a partir do incidente', `${i.code} → ${code}`, 'triage', i.tenant);
  res.json({ caseId: code });
}));

// ── SLA: políticas & conformidade (Incident Management) ─────
r.get('/sla/policies', requirePerm('sla.read'), wrap(async (req, res) => {
  const t = tenantOf(req) || 'vetra';
  const rows = await sql('SELECT * FROM sla_policies WHERE tenant = $1 ORDER BY severity', [t]);
  const map = Object.fromEntries(rows.rows.map((p) => [p.severity, p]));
  res.json(Object.keys(DEFAULT_SLA).map((sev) => ({
    tenant: t, severity: sev,
    responseMin: map[sev]?.response_min ?? DEFAULT_SLA[sev].response,
    resolutionMin: map[sev]?.resolution_min ?? DEFAULT_SLA[sev].resolution,
  })));
}));

r.put('/sla/policies', requirePerm('sla.update'), wrap(async (req, res) => {
  const { tenant, severity, responseMin, resolutionMin } = req.body ?? {};
  if (!tenant || !severity || !DEFAULT_SLA[severity]) return res.status(400).json({ error: 'tenant e severity válidos são obrigatórios' });
  const rm = Number(responseMin), sm = Number(resolutionMin);
  if (!rm || !sm || rm < 1 || sm < 1) return res.status(400).json({ error: 'valores em minutos devem ser ≥ 1' });
  await sql(
    `INSERT INTO sla_policies (tenant, severity, response_min, resolution_min)
     VALUES ($1,$2,$3,$4)
     ON CONFLICT (tenant, severity) DO UPDATE SET response_min=$3, resolution_min=$4`,
    [tenant, severity, rm, sm]);
  await addAudit(req.header('X-Sopir-User') || 'analista',
    `atualizou política de SLA (${severity}: resposta ${rm}min / resolução ${sm}min)`, tenant, 'system', tenant);
  res.json({ ok: true });
}));

r.get('/sla/metrics', requirePerm('sla.read'), wrap(async (req, res) => {
  res.json(await getSlaMetrics(tenantOf(req)));
}));

// ── cases ────────────────────────────────────────────────────
r.get('/cases', wrap(async (req, res) => {
  const t = tenantOf(req);
  const rows = await sql(`SELECT * FROM cases${t ? ' WHERE tenant = $1' : ''} ORDER BY ts DESC`, t ? [t] : []);
  res.json(await Promise.all(rows.rows.map(fullCase)));
}));

r.get('/cases/templates', (req, res) => {
  res.json(CASE_TEMPLATES.map(({ id, name, severity, tasks }) => ({ id, name, severity, tasks })));
});

r.get('/cases/metrics', requirePerm('cases.read'), wrap(async (req, res) => {
  res.json(await getCaseMetrics(tenantOf(req)));
}));

r.post('/cases', wrap(async (req, res) => {
  const { title, severity, priority, templateId } = req.body ?? {};
  if (!title) return res.status(400).json({ error: 'title obrigatório' });
  const code = await nextCode('CASE', 'seq_cases').catch(() => 'CASE-' + Date.now());
  const actor = req.header('X-Sopir-User') || 'analista';
  const tenant = tenantOf(req) || 'vetra';
  const tpl = CASE_TEMPLATES.find((t) => t.id === templateId);
  const sev = severity || tpl?.severity || 'medium';
  await sql(
    `INSERT INTO cases (code, tenant, title, severity, priority, stage, status, assignee, ts, opened_at)
     VALUES ($1,$2,$3,$4,$5,'Triagem','active',$6, now(), now())`,
    [code, tenant, title, sev, priority || sevToPriority(sev), actor],
  );
  // tarefas iniciais a partir do template
  if (tpl) {
    for (const t of tpl.tasks) {
      await sql('INSERT INTO case_tasks (case_code, text) VALUES ($1,$2)', [code, t]);
    }
  }
  await sql('INSERT INTO case_timeline (case_code, ts, text, kind, author) VALUES ($1, now(), $2, $3, $4)',
    [code, `Case aberto${tpl ? ` (template: ${tpl.name})` : ''}`, 'system', actor]);
  await addAudit(actor, 'criou case' + (tpl ? ` via template ${tpl.name}` : ''), code, 'triage', tenant);
  res.json({ id: code });
}));

r.get('/cases/:id', wrap(async (req, res) => {
  const row = await sql('SELECT * FROM cases WHERE code=$1', [req.params.id]);
  if (!row.rowCount) return res.status(404).json({ error: 'case não encontrado' });
  res.json(await fullCase(row.rows[0]));
}));

r.patch('/cases/:id', wrap(async (req, res) => {
  const { stage, advance, status, severity, priority, assignee, reopen } = req.body ?? {};
  const actor = req.header('X-Sopir-User') || 'analista';
  const cur = await sql('SELECT stage, status FROM cases WHERE code=$1', [req.params.id]);
  if (!cur.rowCount) return res.status(404).json({ error: 'case não encontrado' });
  const before = cur.rows[0];

  let target = stage;
  if (advance) {
    target = CASE_STAGES[Math.min(CASE_STAGES.indexOf(before.stage) + 1, CASE_STAGES.length - 1)];
  }

  const sets = []; const params = [];
  const add = (col, val) => { if (val !== undefined) { params.push(val); sets.push(`${col} = $${params.length}`); } };

  if (target && target !== before.stage) {
    add('stage', target);
    await sql('INSERT INTO case_timeline (case_code, ts, text, kind, author) VALUES ($1, now(), $2, $3, $4)',
      [req.params.id, `Stage: ${target}`, 'stage', actor]);
    // fechar automaticamente ao chegar em Encerrado
    if (target === 'Encerrado') {
      add('status', 'closed'); add('closed_at', new Date().toISOString());
      await sql('INSERT INTO case_timeline (case_code, ts, text, kind, author) VALUES ($1, now(), $2, $3, $4)',
        [req.params.id, 'Case encerrado', 'system', actor]);
    }
  }
  if (reopen) { add('status', 'active'); add('closed_at', null); }
  if (status) add('status', status);
  if (severity) add('severity', severity);
  if (priority) add('priority', priority);
  if (assignee) add('assignee', assignee);

  if (sets.length) {
    params.push(req.params.id);
    await sql(`UPDATE cases SET ${sets.join(', ')} WHERE code = $${params.length}`, params);
  }
  const changes = [];
  if (target && target !== before.stage) changes.push(`etapa → ${target}`);
  if (status) changes.push(`status → ${status}`);
  if (severity) changes.push(`severidade → ${severity}`);
  if (priority) changes.push(`prioridade → ${priority}`);
  if (assignee) changes.push(`responsável → ${assignee}`);
  if (reopen) changes.push('reaberto');
  if (changes.length) {
    await addAudit(actor, 'atualizou case (' + changes.join('; ') + ')', req.params.id, 'triage', null);
  }
  res.json({ ok: true });
}));

// ── tarefas do case ─────────────────────────────────────────
r.post('/cases/:id/tasks', wrap(async (req, res) => {
  const { text } = req.body ?? {};
  if (!text) return res.status(400).json({ error: 'text obrigatório' });
  const r = await sql('INSERT INTO case_tasks (case_code, text) VALUES ($1,$2) RETURNING id', [req.params.id, text]);
  res.json({ id: String(r.rows[0].id) });
}));

r.patch('/cases/:id/tasks/:tid', wrap(async (req, res) => {
  const { done } = req.body ?? {};
  await sql('UPDATE case_tasks SET done=$1 WHERE id=$2 AND case_code=$3', [Boolean(done), req.params.tid, req.params.id]);
  res.json({ ok: true });
}));

r.delete('/cases/:id/tasks/:tid', wrap(async (req, res) => {
  await sql('DELETE FROM case_tasks WHERE id=$1 AND case_code=$2', [req.params.tid, req.params.id]);
  res.json({ ok: true });
}));

// ── relações do case (vincular/desvincular) ─────────────────
r.post('/cases/:id/relations', wrap(async (req, res) => {
  const { kind, value } = req.body ?? {};
  const KINDS = ['alert', 'incident', 'asset', 'ioc', 'evidence'];
  if (!KINDS.includes(kind) || !value) return res.status(400).json({ error: 'kind inválido ou value ausente' });
  await sql('INSERT INTO case_refs (case_code, kind, value) VALUES ($1,$2,$3)', [req.params.id, kind, value]);
  await sql('INSERT INTO case_timeline (case_code, ts, text, kind, author) VALUES ($1, now(), $2, $3, $4)',
    [req.params.id, `Vinculou ${kind}: ${value}`, 'relation', req.header('X-Sopir-User') || 'analista']);
  res.json({ ok: true });
}));

r.delete('/cases/:id/relations', wrap(async (req, res) => {
  const { kind, value } = req.body ?? {};
  await sql('DELETE FROM case_refs WHERE case_code=$1 AND kind=$2 AND value=$3', [req.params.id, kind, value]);
  res.json({ ok: true });
}));

r.post('/cases/:id/comments', wrap(async (req, res) => {
  const { text, author } = req.body ?? {};
  if (!text) return res.status(400).json({ error: 'text obrigatório' });
  await sql('INSERT INTO case_comments (case_code, ts, author, text) VALUES ($1, now(), $2, $3)',
    [req.params.id, author || req.header('X-Sopir-User') || 'analista', text]);
  res.json({ ok: true });
}));

// ── vulnerabilidades ─────────────────────────────────────────
r.get('/vulnerabilities', wrap(async (req, res) => {
  const t = tenantOf(req);
  const rows = await sql(`SELECT * FROM vulnerabilities${t ? ' WHERE tenant = $1' : ''} ORDER BY cvss DESC`, t ? [t] : []);
  res.json(rows.rows.map(vuRow));
}));

r.patch('/vulnerabilities/:id', wrap(async (req, res) => {
  const { status } = req.body ?? {};
  if (!status) return res.json({ ok: true });
  const before = await sql('SELECT status FROM vulnerabilities WHERE code=$1', [req.params.id]);
  const prev = before.rows[0]?.status ?? null;
  await sql('UPDATE vulnerabilities SET status = $2 WHERE code = $1', [req.params.id, status]);
  const actor = req.header('X-Sopir-User') || 'analista';
  await addAudit(actor, `alterou status de vulnerabilidade ${prev ?? '—'} → ${status}`, req.params.id, 'triage', null,
    { before: { status: prev }, after: { status } }).catch(() => {});
  res.json({ ok: true });
}));

// ── ativos ───────────────────────────────────────────────────
r.get('/assets', wrap(async (req, res) => {
  const t = tenantOf(req);
  const rows = await sql(`SELECT * FROM assets${t ? ' WHERE tenant = $1' : ''} ORDER BY crit DESC`, t ? [t] : []);
  res.json(rows.rows.map(asRow));
}));

r.patch('/assets/:name/status', wrap(async (req, res) => {
  const { status } = req.body ?? {};
  if (!['online', 'offline', 'isolado'].includes(status)) return res.status(400).json({ error: 'status inválido' });
  const before = await sql('SELECT status FROM assets WHERE name=$1', [req.params.name]);
  const prev = before.rows[0]?.status ?? null;
  await sql('UPDATE assets SET status = $2 WHERE name = $1', [req.params.name, status]);
  const actor = req.header('X-Sopir-User') || 'analista';
  await addAudit(actor, status === 'isolado' ? `isolou ativo da rede (${prev ?? '—'} → isolado)` : `alterou status do ativo ${prev ?? '—'} → ${status}`, req.params.name, 'response', null,
    { before: { status: prev }, after: { status } }).catch(() => {});
  res.json({ ok: true });
}));

// ── playbooks / response engine ──────────────────────────────
r.get('/playbooks', (req, res) => res.json(PLAYBOOKS));

r.get('/runs', wrap(async (req, res) => {
  const t = tenantOf(req);
  const rows = await sql(`SELECT * FROM playbook_runs${t ? ' WHERE tenant = $1' : ''} ORDER BY ts DESC LIMIT 30`, t ? [t] : []);
  res.json(rows.rows.map(runRow));
}));

r.post('/playbooks/:id/run', wrap(async (req, res) => {
  const actor = req.body?.actor || req.header('X-Sopir-User') || 'analista';
  const tenant = tenantOf(req) || 'vetra';
  const code = await startRun(req.params.id, actor, tenant);
  res.json({ id: code });
}));

r.post('/runs/:id/approve', wrap(async (req, res) => {
  const actor = req.body?.actor || req.header('X-Sopir-User') || 'analista';
  await approveRun(req.params.id, actor);
  res.json({ ok: true });
}));

r.post('/runs/:id/reject', wrap(async (req, res) => {
  const actor = req.body?.actor || req.header('X-Sopir-User') || 'analista';
  await rejectRun(req.params.id, actor);
  res.json({ ok: true });
}));

// ── auditoria & conectores ───────────────────────────────────
r.get('/audit', requirePerm('audit.read'), wrap(async (req, res) => {
  const { actor, kind, tenant, outcome, control, q, from, to } = req.query;
  const where = []; const params = [];
  if (actor) { params.push(`%${actor}%`); where.push(`actor ILIKE $${params.length}`); }
  if (kind) { params.push(kind); where.push(`kind = $${params.length}`); }
  if (tenant) { params.push(tenant); where.push(`tenant = $${params.length}`); }
  if (outcome) { params.push(outcome); where.push(`outcome = $${params.length}`); }
  if (control) { params.push(control); where.push(`control = $${params.length}`); }
  if (q) {
    params.push(`%${q}%`, `%${q}%`, `%${q}%`);
    const n = params.length;
    where.push(`(action ILIKE $${n - 2} OR target ILIKE $${n - 1} OR actor ILIKE $${n})`);
  }
  if (from) { params.push(Number(from)); where.push(`ts_ms >= $${params.length}`); }
  if (to) { params.push(Number(to)); where.push(`ts_ms <= $${params.length}`); }
  const w = where.length ? ' WHERE ' + where.join(' AND ') : '';
  const rows = await sql(`SELECT * FROM audit${w} ORDER BY ts_ms DESC LIMIT 400`, params);
  res.json(rows.rows.map(auRow));
}));

// Verifica a integridade da cadeia de hashes da trilha de auditoria.
r.get('/audit/verify', requirePerm('audit.read'), wrap(async (req, res) => {
  const rows = await sql('SELECT id, ts_ms, actor, action, target, kind, prev_hash, hash FROM audit ORDER BY id');
  let lastHash = null; let verified = 0; let legacy = 0; let firstBad = null;
  for (const r of rows.rows) {
    if (!r.hash) { legacy += 1; continue; }
    const isFirst = lastHash === null;
    // primeira linha selada aceita GENESIS ou uma âncora de retenção
    const prevOk = isFirst
      ? (r.prev_hash === 'GENESIS' || /âncora/i.test(r.action))
      : r.prev_hash === lastHash;
    const recomputed = computeHash(r.prev_hash, Number(r.ts_ms), r.actor, r.action, r.target ?? '', r.kind);
    if (!prevOk || recomputed !== r.hash) { firstBad = 'AU-' + r.id; break; }
    lastHash = r.hash; verified += 1;
  }
  res.json({ ok: firstBad === null, total: rows.rows.length, verified, legacy, firstBad, tip: lastHash });
}));

// Painel de conformidade: cobertura de controles, volume diário e sinais de risco.
r.get('/audit/compliance', requirePerm('audit.read'), wrap(async (req, res) => {
  const [controls, perDay, failed1h, denied24, afterHours, rejections7d] = await Promise.all([
    sql(`SELECT control, count(*)::int AS n FROM audit WHERE control IS NOT NULL GROUP BY control ORDER BY control`),
    sql(`SELECT (ts_ms / 86400000)::bigint AS day, count(*)::int AS n FROM audit
          WHERE ts_ms > $1 GROUP BY 1 ORDER BY 1`, [Date.now() - 14 * 86400000]),
    sql(`SELECT count(*)::int AS n FROM audit WHERE kind='auth' AND outcome='denied' AND ts_ms > $1`, [Date.now() - 3600000]),
    sql(`SELECT count(*)::int AS n FROM audit WHERE action ILIKE '%entre tenants%' AND ts_ms > $1`, [Date.now() - 86400000]),
    sql(`SELECT count(*)::int AS n FROM audit WHERE kind IN ('triage','response','auth') AND actor <> 'sistema'
           AND ts_ms > $1 AND EXTRACT(hour FROM to_timestamp(ts_ms / 1000.0)) BETWEEN 0 AND 5`, [Date.now() - 86400000]),
    sql(`SELECT count(*)::int AS n FROM audit WHERE action ILIKE '%rejeitou%' AND ts_ms > $1`, [Date.now() - 7 * 86400000]),
  ]);
  // volume dos últimos 14 dias (índice 0 = hoje)
  const nowDay = Math.floor(Date.now() / 86400000);
  const days = new Array(14).fill(0);
  for (const r of perDay.rows) {
    const idx = nowDay - Number(r.day);
    if (idx >= 0 && idx < 14) days[13 - idx] = r.n;
  }
  res.json({
    controls: controls.rows,
    perDay: days,
    signals: [
      { id: 'failed-logins', label: 'Logins negados (última hora)', count: failed1h.rows[0].n, severity: failed1h.rows[0].n > 3 ? 'high' : failed1h.rows[0].n > 0 ? 'medium' : 'low' },
      { id: 'cross-tenant', label: 'Acessos entre tenants bloqueados (24h)', count: denied24.rows[0].n, severity: denied24.rows[0].n > 0 ? 'high' : 'low' },
      { id: 'after-hours', label: 'Ações administrativas fora do horário (24h)', count: afterHours.rows[0].n, severity: afterHours.rows[0].n > 2 ? 'medium' : 'low' },
      { id: 'rejections', label: 'Ações de resposta rejeitadas (7d)', count: rejections7d.rows[0].n, severity: rejections7d.rows[0].n > 0 ? 'medium' : 'low' },
    ],
  });
}));

r.get('/connectors', wrap(async (req, res) => {
  const st = await connectorStatus();
  res.json(st);
}));

// ── motor de correlação por política ─────────────────────────
r.get('/correlations', requirePerm('correlations.read'), (req, res) => {
  res.json(listPolicies());
});

r.patch('/correlations/:id', wrap(async (req, res) => {
  const updated = setPolicyEnabled(req.params.id, req.body?.enabled);
  if (!updated) return res.status(404).json({ error: 'política não encontrada' });
  await addAudit(actorOf(req), `${req.body?.enabled ? 'ativou' : 'desativou'} política de correlação`, req.params.id, 'system', tenantOf(req));
  res.json(updated);
}));

// ── regras customizáveis (Detection & Correlation) ──────────
r.post('/correlations', requirePerm('correlations.update'), wrap(async (req, res) => {
  const code = await addCustomPolicy(actorOf(req), req.body ?? {}, tenantOf(req));
  res.status(201).json({ code });
}));

r.put('/correlations/:id', requirePerm('correlations.update'), wrap(async (req, res) => {
  const ok = await updateCustomPolicy(actorOf(req), req.params.id, req.body ?? {}, tenantOf(req));
  if (!ok) return res.status(404).json({ error: 'regra não encontrada (somente customizadas são editáveis)' });
  res.json({ ok: true });
}));

r.delete('/correlations/:id', requirePerm('correlations.update'), wrap(async (req, res) => {
  const ok = await deleteCustomPolicy(actorOf(req), req.params.id, tenantOf(req));
  if (!ok) return res.status(404).json({ error: 'regra não encontrada (somente customizadas são removíveis)' });
  res.json({ ok: true });
}));

// backtest: roda uma definição de regra contra os eventos recentes
r.post('/correlations/backtest', requirePerm('correlations.read'), (req, res) => {
  res.json(backtest(req.body ?? {}));
});

// ── risco por entidade & agrupamento ────────────────────────
r.get('/risk/scores', requirePerm('correlations.read'), wrap(async (req, res) => {
  const type = req.query.type || 'host';
  res.json(await computeRiskScores(type, tenantOf(req)));
}));

r.get('/events/aggregate', requirePerm('correlations.read'), wrap(async (req, res) => {
  const by = req.query.by || 'host';
  const hours = Number(req.query.hours) || 24;
  res.json(await aggregateEvents(by, tenantOf(req), hours));
}));

// ── Investigation Graph ─────────────────────────────────────
r.get('/graph/expand', requirePerm('investigations.read'), wrap(async (req, res) => {
  const { type, value } = req.query;
  if (!type || !value) return res.status(400).json({ error: 'type e value são obrigatórios' });
  const t = tenantOf(req);
  const g = await expandGraph(type, value, t);
  res.json(g);
}));

r.get('/investigations', requirePerm('investigations.read'), wrap(async (req, res) => {
  const t = tenantOf(req);
  const where = t ? ' WHERE tenant = $1' : '';
  const params = t ? [t] : [];
  const r2 = await sql(`SELECT * FROM investigations${where} ORDER BY ts DESC LIMIT 50`, params);
  res.json(r2.rows.map((x) => ({
    id: x.code, tenant: x.tenant ?? 'all', name: x.name, rootType: x.root_type ?? '',
    rootValue: x.root_value ?? '', graph: x.graph, status: x.status,
    ts: Date.parse(x.ts), owner: x.owner ?? '—',
  })));
}));

r.post('/investigations', requirePerm('investigations.update'), wrap(async (req, res) => {
  const { name, rootType, rootValue, graph, tenant } = req.body ?? {};
  if (!name || !graph) return res.status(400).json({ error: 'name e graph são obrigatórios' });
  const code = await nextCode('INV', 'seq_investigations');
  const t = tenant || tenantOf(req) || 'vetra';
  await sql(
    `INSERT INTO investigations (code, tenant, name, root_type, root_value, graph, status, owner)
     VALUES ($1,$2,$3,$4,$5,$6,'aberta',$7)`,
    [code, t, name, rootType ?? null, rootValue ?? null, JSON.stringify(graph), actorOf(req)],
  );
  await addAudit(actorOf(req), 'salvou investigação', `${code} · ${name}`, 'triage', t);
  res.json({ id: code });
}));

r.patch('/investigations/:id', requirePerm('investigations.update'), wrap(async (req, res) => {
  const { graph, status } = req.body ?? {};
  if (graph) await sql(`UPDATE investigations SET graph = $2 WHERE code = $1`, [req.params.id, JSON.stringify(graph)]);
  if (status) await sql(`UPDATE investigations SET status = $2 WHERE code = $1`, [req.params.id, status]);
  res.json({ ok: true });
}));

export default r;
