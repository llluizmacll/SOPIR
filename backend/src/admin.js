// ─────────────────────────────────────────────────────────────
// SOPIR API · Administração — usuários, perfis de acesso (RBAC)
// e clientes (tenants). Tudo protegido por permissões admin.*.
// ─────────────────────────────────────────────────────────────
import { Router } from 'express';
import crypto from 'crypto';
import bcrypt from 'bcryptjs';
import { sql, addAudit, nextCode } from './db.js';
import { requirePerm, roleExists, invalidateRoleCache, PERM_CATALOG, ROLE_PERMS } from './auth.js';
import {
  loadConnectorConfigs, maskSettings, resolvePass, testConnector, CONNECTOR_TYPES,
} from './connectors/dynamic.js';
import {
  getSettings, patchSettings, fetchDiscovery, listProviders, assertPasswordPolicy,
} from './identity.js';

const r = Router();
const wrap = (fn) => (req, res, next) => fn(req, res, next).catch(next);
const actorOf = (req) => req.auth?.name ?? 'sistema';

// ═══════════════════ USUÁRIOS ═══════════════════
r.get('/users', requirePerm('admin.users'), wrap(async (req, res) => {
  const rows = await sql(
    `SELECT u.username, u.name, u.role, u.tenant, u.active, u.last_login,
            u.mfa_enabled, t.name AS tenant_name
       FROM users u LEFT JOIN tenants t ON t.id = u.tenant
      ORDER BY u.name`);
  res.json(rows.rows.map((u) => ({
    username: u.username, name: u.name, role: u.role,
    tenant: u.tenant, tenantName: u.tenant_name ?? null,
    active: u.active, lastLogin: u.last_login ? Date.parse(u.last_login) : null,
    mfaEnabled: !!u.mfa_enabled,
  })));
}));

r.post('/users', requirePerm('admin.users'), wrap(async (req, res) => {
  const { username, name, password, role, tenant = null, active = true } = req.body ?? {};
  if (!username || !name || !password || !role) {
    return res.status(400).json({ error: 'username, nome, senha e perfil são obrigatórios' });
  }
  const pwErr = assertPasswordPolicy(password, await getSettings());
  if (pwErr) return res.status(400).json({ error: pwErr });
  if (!(await roleExists(role))) return res.status(400).json({ error: `perfil não encontrado: ${role}` });
  if (role === 'Customer' && !tenant) return res.status(400).json({ error: 'perfil Customer exige um cliente (tenant)' });
  if (tenant) {
    const t = await sql('SELECT 1 FROM tenants WHERE id = $1', [tenant]);
    if (!t.rowCount) return res.status(400).json({ error: `cliente não encontrado: ${tenant}` });
  }
  const uname = String(username).toLowerCase().trim();
  const dup = await sql('SELECT 1 FROM users WHERE username = $1', [uname]);
  if (dup.rowCount) return res.status(409).json({ error: `usuário já existe: ${uname}` });

  await sql(
    `INSERT INTO users (username, name, role, tenant, pass_hash, active)
     VALUES ($1,$2,$3,$4,$5,$6)`,
    [uname, name, role, tenant, bcrypt.hashSync(String(password), 10), !!active]);
  await addAudit(actorOf(req), 'criou usuário', `${uname} (${role})`, 'auth', tenant);
  res.status(201).json({ ok: true, username: uname });
}));

// ── Reset de MFA (admin) ─────────────────────────────────────
r.post('/users/:username/reset-mfa', requirePerm('admin.users'), wrap(async (req, res) => {
  const { username } = req.params;
  const cur = await sql('SELECT 1 FROM users WHERE username = $1', [username]);
  if (!cur.rowCount) return res.status(404).json({ error: 'usuário não encontrado' });
  await sql('UPDATE users SET mfa_enabled = false, mfa_secret = NULL WHERE username = $1', [username]);
  await sql('DELETE FROM recovery_codes WHERE username = $1', [username]);
  await sql(
    `INSERT INTO audit (actor, action, target, kind) VALUES ($1, 'resetou MFA do usuário', $2, 'auth')`,
    [actorOf(req), username]);
  res.json({ ok: true });
}));

r.patch('/users/:username', requirePerm('admin.users'), wrap(async (req, res) => {
  const { username } = req.params;
  const { name, role, tenant, active } = req.body ?? {};
  const cur = await sql('SELECT * FROM users WHERE username = $1', [username]);
  if (!cur.rowCount) return res.status(404).json({ error: 'usuário não encontrado' });
  const u = cur.rows[0];

  if (role && role !== u.role) {
    if (!(await roleExists(role))) return res.status(400).json({ error: `perfil não encontrado: ${role}` });
    if (role === 'Customer' && !(tenant ?? u.tenant)) return res.status(400).json({ error: 'perfil Customer exige um cliente' });
  }
  await sql(
    `UPDATE users SET
       name   = COALESCE($2, name),
       role   = COALESCE($3, role),
       tenant = $4,
       active = COALESCE($5, active)
     WHERE username = $1`,
    [username, name ?? null, role ?? null, tenant === undefined ? u.tenant : tenant, active ?? null]);

  const what = [];
  if (role && role !== u.role) what.push(`perfil → ${role}`);
  if (active === false && u.active) what.push('suspenso');
  if (active === true && !u.active) what.push('reativado');
  if (tenant !== undefined && tenant !== u.tenant) what.push(`cliente → ${tenant ?? 'MSSP'}`);
  await addAudit(actorOf(req), 'atualizou usuário' + (what.length ? ` (${what.join(', ')})` : ''), username, 'auth', u.tenant);
  res.json({ ok: true });
}));

r.post('/users/:username/password', requirePerm('admin.users'), wrap(async (req, res) => {
  const { password } = req.body ?? {};
  if (!password || String(password).length < 4) return res.status(400).json({ error: 'senha deve ter ao menos 4 caracteres' });
  const cur = await sql('SELECT 1 FROM users WHERE username = $1', [req.params.username]);
  if (!cur.rowCount) return res.status(404).json({ error: 'usuário não encontrado' });
  await sql('UPDATE users SET pass_hash = $2 WHERE username = $1', [req.params.username, bcrypt.hashSync(String(password), 10)]);
  await addAudit(actorOf(req), 'redefiniu senha de usuário', req.params.username, 'auth', null);
  res.json({ ok: true });
}));

r.delete('/users/:username', requirePerm('admin.users'), wrap(async (req, res) => {
  if (req.params.username === req.auth.username) {
    return res.status(400).json({ error: 'você não pode excluir a própria conta' });
  }
  const cur = await sql('SELECT 1 FROM users WHERE username = $1', [req.params.username]);
  if (!cur.rowCount) return res.status(404).json({ error: 'usuário não encontrado' });
  await sql('DELETE FROM users WHERE username = $1', [req.params.username]);
  await addAudit(actorOf(req), 'excluiu usuário', req.params.username, 'auth', null);
  res.json({ ok: true });
}));

// ═══════════════════ PERFIS DE ACESSO ═══════════════════
const BUILTIN_DESC = {
  Admin: 'Acesso total à plataforma, incluindo administração.',
  'SOC Manager': 'Gestão completa da operação do SOC.',
  'SOC Analyst': 'Triagem de alertas, incidentes e cases.',
  'Security Engineer': 'Vulnerabilidades, remediação e ativos.',
  Customer: 'Portal do cliente — somente o próprio ambiente.',
};

r.get('/roles', requirePerm('admin.roles'), wrap(async (req, res) => {
  const counts = await sql('SELECT role, count(*)::int AS n FROM users GROUP BY role');
  const countOf = (role) => counts.rows.find((c) => c.role === role)?.n ?? 0;

  const db = await sql('SELECT * FROM roles ORDER BY name');
  const dbMap = new Map(db.rows.map((c) => [c.name, c]));

  // embutidos: permissões do DB (se editadas) prevalecem sobre o mapa estático
  const builtin = Object.entries(ROLE_PERMS).map(([name, staticPerms]) => {
    const row = dbMap.get(name);
    return {
      name, display: row?.display ?? name,
      description: row?.description || BUILTIN_DESC[name] || '',
      permissions: row?.permissions?.length ? row.permissions : staticPerms,
      builtin: true, users: countOf(name),
    };
  });

  const custom = db.rows.filter((c) => !ROLE_PERMS[c.name]).map((c) => ({
    name: c.name, display: c.display, description: c.description ?? '',
    permissions: c.permissions ?? [], builtin: false, users: countOf(c.name),
  }));

  res.json([...builtin, ...custom]);
}));

r.get('/roles/permissions', requirePerm('admin.roles'), (req, res) => {
  res.json(PERM_CATALOG.map((m) => ({ module: m.module, perms: m.perms.map(([id, label]) => ({ id, label })) })));
});

r.post('/roles', requirePerm('admin.roles'), wrap(async (req, res) => {
  const { name, display, description = '', permissions = [] } = req.body ?? {};
  if (!name || !display) return res.status(400).json({ error: 'identificador e nome de exibição são obrigatórios' });
  const slug = String(name).trim().toLowerCase().replace(/\s+/g, '-').replace(/[^a-z0-9-_]/g, '');
  if (!slug) return res.status(400).json({ error: 'identificador inválido' });
  if (ROLE_PERMS[slug] || ROLE_PERMS[display]) return res.status(409).json({ error: 'já existe um perfil embutido com esse nome' });
  const dup = await sql('SELECT 1 FROM roles WHERE name = $1', [slug]);
  if (dup.rowCount) return res.status(409).json({ error: `perfil já existe: ${slug}` });
  if (!Array.isArray(permissions) || !permissions.length) return res.status(400).json({ error: 'selecione ao menos uma permissão' });

  await sql(
    'INSERT INTO roles (name, display, description, permissions, builtin) VALUES ($1,$2,$3,$4,false)',
    [slug, display, description, JSON.stringify(permissions)]);
  invalidateRoleCache();
  await addAudit(actorOf(req), 'criou perfil de acesso', `${slug} (${permissions.length} permissões)`, 'auth', null);
  res.status(201).json({ ok: true, name: slug });
}));

r.patch('/roles/:name', requirePerm('admin.roles'), wrap(async (req, res) => {
  const { name } = req.params;
  const { display, description, permissions } = req.body ?? {};
  if (ROLE_PERMS[name]) {
    // embutido: só permite ajustar permissões (exceto Admin, que é total)
    if (name === 'Admin') return res.status(400).json({ error: 'o perfil Admin não pode ser modificado' });
    if (!Array.isArray(permissions) || !permissions.length) {
      return res.status(400).json({ error: 'selecione ao menos uma permissão' });
    }
    await sql(
      `INSERT INTO roles (name, display, description, permissions, builtin)
       VALUES ($1, $1, $2, $3, true)
       ON CONFLICT (name) DO UPDATE SET permissions = $3`,
      [name, BUILTIN_DESC[name] ?? '', JSON.stringify(permissions)]);
    invalidateRoleCache();
    await addAudit(actorOf(req), 'atualizou permissões do perfil embutido', name, 'auth', null);
    return res.json({ ok: true });
  }
  const cur = await sql('SELECT 1 FROM roles WHERE name = $1', [name]);
  if (!cur.rowCount) return res.status(404).json({ error: 'perfil não encontrado' });
  await sql(
    `UPDATE roles SET display = COALESCE($2, display), description = COALESCE($3, description),
       permissions = COALESCE($4, permissions) WHERE name = $1`,
    [name, display ?? null, description ?? null, permissions ? JSON.stringify(permissions) : null]);
  invalidateRoleCache();
  await addAudit(actorOf(req), 'atualizou perfil de acesso', name, 'auth', null);
  res.json({ ok: true });
}));

r.delete('/roles/:name', requirePerm('admin.roles'), wrap(async (req, res) => {
  const { name } = req.params;
  if (ROLE_PERMS[name]) return res.status(400).json({ error: 'perfis embutidos não podem ser excluídos' });
  const used = await sql('SELECT count(*)::int AS n FROM users WHERE role = $1', [name]);
  if (used.rows[0].n > 0) return res.status(409).json({ error: `perfil em uso por ${used.rows[0].n} usuário(s)` });
  const cur = await sql('DELETE FROM roles WHERE name = $1 RETURNING 1', [name]);
  if (!cur.rowCount) return res.status(404).json({ error: 'perfil não encontrado' });
  invalidateRoleCache();
  await addAudit(actorOf(req), 'excluiu perfil de acesso', name, 'auth', null);
  res.json({ ok: true });
}));

// ═══════════════════ CLIENTES (TENANTS) ═══════════════════
const tenantRow = async (t) => {
  const [a, al, i, u, v, cn, ev] = await Promise.all([
    sql('SELECT count(*)::int AS n FROM assets WHERE tenant=$1', [t.id]),
    sql('SELECT count(*)::int AS n FROM alerts WHERE tenant=$1', [t.id]),
    sql('SELECT count(*)::int AS n FROM incidents WHERE tenant=$1', [t.id]),
    sql('SELECT count(*)::int AS n FROM users WHERE tenant=$1', [t.id]),
    sql('SELECT count(*)::int AS n FROM vulnerabilities WHERE tenant=$1', [t.id]),
    sql('SELECT count(*)::int AS n FROM connector_configs WHERE tenant=$1', [t.id]),
    sql('SELECT code, name, kind FROM environments WHERE tenant=$1 ORDER BY created', [t.id]),
  ]);
  const org = t.org_id ? await sql('SELECT name FROM orgs WHERE id=$1', [t.org_id]) : null;
  return {
    id: t.id, name: t.name, short: t.short, contact: t.contact ?? null,
    orgId: t.org_id ?? null, orgName: org?.rows[0]?.name ?? null,
    brandColor: t.brand_color ?? null, tagline: t.tagline ?? null,
    quotas: { maxUsers: t.max_users ?? null, maxAssets: t.max_assets ?? null, maxConnectors: t.max_connectors ?? null },
    created: t.created ? Date.parse(t.created) : null,
    assets: a.rows[0].n, alerts: al.rows[0].n, incidents: i.rows[0].n,
    users: u.rows[0].n, vulns: v.rows[0].n, connectors: cn.rows[0].n,
    environments: ev.rows.map((e) => ({ id: e.code, name: e.name, kind: e.kind })),
    active: t.active !== false,
  };
};

r.get('/tenants', requirePerm('admin.tenants'), wrap(async (req, res) => {
  const rows = await sql('SELECT * FROM tenants ORDER BY name');
  res.json(await Promise.all(rows.rows.map(tenantRow)));
}));

r.post('/tenants', requirePerm('admin.tenants'), wrap(async (req, res) => {
  const { id, name, short, contact = null, orgId = null, brandColor = null, tagline = null, maxUsers = null, maxAssets = null, maxConnectors = null } = req.body ?? {};
  if (!id || !name || !short) return res.status(400).json({ error: 'id, nome e sigla são obrigatórios' });
  const slug = String(id).trim().toLowerCase().replace(/[^a-z0-9-_]/g, '');
  if (!slug) return res.status(400).json({ error: 'id inválido — use letras minúsculas, números e hífen' });
  const dup = await sql('SELECT 1 FROM tenants WHERE id = $1', [slug]);
  if (dup.rowCount) return res.status(409).json({ error: `cliente já existe: ${slug}` });
  await sql(
    `INSERT INTO tenants (id, name, short, contact, org_id, brand_color, tagline, max_users, max_assets, max_connectors)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
    [slug, name, String(short).slice(0, 4).toUpperCase(), contact, orgId, brandColor, tagline, maxUsers, maxAssets, maxConnectors]);
  await addAudit(actorOf(req), 'cadastrou cliente (tenant)', `${name} [${slug}]`, 'system', slug);
  res.status(201).json({ ok: true, id: slug });
}));

r.patch('/tenants/:id', requirePerm('admin.tenants'), wrap(async (req, res) => {
  const { name, short, contact, orgId, brandColor, tagline, maxUsers, maxAssets, maxConnectors } = req.body ?? {};
  const cur = await sql('SELECT 1 FROM tenants WHERE id = $1', [req.params.id]);
  if (!cur.rowCount) return res.status(404).json({ error: 'cliente não encontrado' });
  await sql(
    `UPDATE tenants SET name = COALESCE($2, name), short = COALESCE($3, short), contact = $4,
       org_id = $5, brand_color = $6, tagline = $7, max_users = $8, max_assets = $9, max_connectors = $10
     WHERE id = $1`,
    [req.params.id, name ?? null, short ? String(short).slice(0, 4).toUpperCase() : null,
     contact === undefined ? null : contact, orgId === undefined ? null : orgId,
     brandColor === undefined ? null : brandColor, tagline === undefined ? null : tagline,
     maxUsers === undefined ? null : maxUsers, maxAssets === undefined ? null : maxAssets,
     maxConnectors === undefined ? null : maxConnectors]);
  await addAudit(actorOf(req), 'atualizou cliente', req.params.id, 'system', req.params.id);
  res.json({ ok: true });
}));

r.delete('/tenants/:id', requirePerm('admin.tenants'), wrap(async (req, res) => {
  const { id } = req.params;
  
  // Impedir exclusão do tenant padrão
  if (id === 'default' || id === 'mssp') {
    return res.status(400).json({ error: 'não é permitido excluir o tenant padrão' });
  }
  
  // Excluir todos os dados relacionados em cascata
  await sql('BEGIN');
  try {
    // Excluir conectores
    await sql('DELETE FROM connector_configs WHERE tenant=$1', [id]);
    // Excluir eventos
    await sql('DELETE FROM events WHERE tenant=$1', [id]);
    // Excluir casos
    await sql('DELETE FROM cases WHERE tenant=$1', [id]);
    // Excluir incidentes
    await sql('DELETE FROM incidents WHERE tenant=$1', [id]);
    // Excluir alertas
    await sql('DELETE FROM alerts WHERE tenant=$1', [id]);
    // Excluir vulnerabilidades
    await sql('DELETE FROM vulnerabilities WHERE tenant=$1', [id]);
    // Excluir ativos
    await sql('DELETE FROM assets WHERE tenant=$1', [id]);
    // Excluir usuários
    await sql('DELETE FROM users WHERE tenant=$1', [id]);
    // Excluir ambientes
    await sql('DELETE FROM environments WHERE tenant=$1', [id]);
    // Excluir o tenant
    await sql('DELETE FROM tenants WHERE id = $1 RETURNING 1', [id]);
    await addAudit(actorOf(req), 'removeu cliente (tenant) com todos os dados', id, 'system', null);
    await sql('COMMIT');
    res.json({ ok: true });
  } catch (err) {
    await sql('ROLLBACK');
    throw err;
  }
}));

// ── Ativar/Desativar Tenant ─────────────────────────────────────
r.patch('/tenants/:id/status', requirePerm('admin.tenants'), wrap(async (req, res) => {
  const { id } = req.params;
  const { active } = req.body ?? {};
  
  if (typeof active !== 'boolean') {
    return res.status(400).json({ error: 'campo "active" (boolean) é obrigatório' });
  }
  
  // Impedir desativação do tenant padrão
  if ((id === 'default' || id === 'mssp') && !active) {
    return res.status(400).json({ error: 'não é permitido desativar o tenant padrão' });
  }
  
  const cur = await sql('SELECT * FROM tenants WHERE id = $1', [id]);
  if (!cur.rowCount) return res.status(404).json({ error: 'cliente não encontrado' });
  
  await sql('UPDATE tenants SET active = $2 WHERE id = $1', [id, active]);
  await addAudit(
    actorOf(req),
    active ? 'reativou cliente (tenant)' : 'desativou cliente (tenant)',
    id,
    'system',
    id
  );
  res.json({ ok: true });
}));

// ═══════════════ ORGANIZAÇÕES ═══════════════
r.get('/orgs', requirePerm('admin.tenants'), wrap(async (req, res) => {
  const orgs = await sql('SELECT * FROM orgs ORDER BY name');
  const out = [];
  for (const o of orgs.rows) {
    const t = await sql('SELECT id, name, short FROM tenants WHERE org_id=$1 ORDER BY name', [o.id]);
    out.push({ id: o.id, name: o.name, short: o.short, tenants: t.rows.map((x) => ({ id: x.id, name: x.name, short: x.short })) });
  }
  res.json(out);
}));

r.post('/orgs', requirePerm('admin.tenants'), wrap(async (req, res) => {
  const { name, short } = req.body ?? {};
  if (!name) return res.status(400).json({ error: 'nome é obrigatório' });
  const id = await nextCode('ORG', 'seq_orgs');
  await sql('INSERT INTO orgs (id, name, short) VALUES ($1,$2,$3)',
    [id, name, String(short || name.slice(0, 3)).slice(0, 4).toUpperCase()]);
  await addAudit(actorOf(req), 'criou organização', name, 'system', null);
  res.status(201).json({ ok: true, id });
}));

r.delete('/orgs/:id', requirePerm('admin.tenants'), wrap(async (req, res) => {
  const used = await sql('SELECT count(*)::int AS n FROM tenants WHERE org_id=$1', [req.params.id]);
  if (used.rows[0].n > 0) {
    return res.status(409).json({ error: `organização possui ${used.rows[0].n} cliente(s) — mova-os antes` });
  }
  const cur = await sql('DELETE FROM orgs WHERE id=$1 RETURNING 1', [req.params.id]);
  if (!cur.rowCount) return res.status(404).json({ error: 'organização não encontrada' });
  await addAudit(actorOf(req), 'removeu organização', req.params.id, 'system', null);
  res.json({ ok: true });
}));

// ═══════════════ AMBIENTES ═══════════════
r.get('/tenants/:id/environments', requirePerm('admin.tenants'), wrap(async (req, res) => {
  const rows = await sql('SELECT * FROM environments WHERE tenant=$1 ORDER BY created', [req.params.id]);
  res.json(rows.rows.map((e) => ({ id: e.code, tenant: e.tenant, name: e.name, kind: e.kind, created: e.created ? Date.parse(e.created) : null })));
}));

r.post('/tenants/:id/environments', requirePerm('admin.tenants'), wrap(async (req, res) => {
  const { name, kind = 'producao' } = req.body ?? {};
  if (!name) return res.status(400).json({ error: 'nome é obrigatório' });
  const t = await sql('SELECT 1 FROM tenants WHERE id=$1', [req.params.id]);
  if (!t.rowCount) return res.status(404).json({ error: 'cliente não encontrado' });
  const code = await nextCode('ENV', 'seq_envs');
  await sql('INSERT INTO environments (code, tenant, name, kind) VALUES ($1,$2,$3,$4)',
    [code, req.params.id, name, kind]);
  await addAudit(actorOf(req), 'criou ambiente', `${name} → ${req.params.id}`, 'system', req.params.id);
  res.status(201).json({ ok: true, id: code });
}));

r.delete('/environments/:code', requirePerm('admin.tenants'), wrap(async (req, res) => {
  const cur = await sql('DELETE FROM environments WHERE code=$1 RETURNING tenant, name', [req.params.code]);
  if (!cur.rowCount) return res.status(404).json({ error: 'ambiente não encontrado' });
  await addAudit(actorOf(req), 'removeu ambiente', `${cur.rows[0].name} [${req.params.code}]`, 'system', cur.rows[0].tenant);
  res.json({ ok: true });
}));

// ═══════════════ ONBOARDING (cliente completo) ═══════════════
r.post('/onboard', requirePerm('admin.tenants'), wrap(async (req, res) => {
  const { name, short, contact, orgId, brandColor, maxUsers, maxAssets, createPortalUser, portalPassword } = req.body ?? {};
  if (!name) return res.status(400).json({ error: 'nome é obrigatório' });
  const slug = String(name).trim().toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '').replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 24) || 'cliente';
  let id = slug;
  let n = 2;
  while ((await sql('SELECT 1 FROM tenants WHERE id=$1', [id])).rowCount) id = `${slug}-${n++}`;

  await sql(
    `INSERT INTO tenants (id, name, short, contact, org_id, brand_color, max_users, max_assets)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
    [id, name, String(short || name.slice(0, 3)).slice(0, 4).toUpperCase(), contact ?? null, orgId ?? null, brandColor ?? null, maxUsers ?? null, maxAssets ?? null]);

  // ambiente padrão Produção
  const envCode = await nextCode('ENV', 'seq_envs');
  await sql('INSERT INTO environments (code, tenant, name, kind) VALUES ($1,$2,$3,$4)', [envCode, id, 'Produção', 'producao']);

  // usuário do portal (opcional)
  let portalUser = null;
  if (createPortalUser && portalPassword) {
    const assert = assertPasswordPolicy(portalPassword, await getSettings());
    if (assert) return res.status(400).json({ error: assert });
    portalUser = `portal.${id}`;
    await sql(
      'INSERT INTO users (username, name, role, tenant, pass_hash, active) VALUES ($1,$2,$3,$4,$5,true)',
      [portalUser, `Portal — ${name}`, 'Customer', id, bcrypt.hashSync(portalPassword, 10)]);
  }

  await addAudit(actorOf(req), 'realizou onboarding de cliente', `${name} [${id}]`, 'system', id);
  res.status(201).json({ ok: true, id, environment: envCode, portalUser });
}));

// ═══════════════ MATRIZ DE ISOLAMENTO ═══════════════
r.get('/isolation', requirePerm('admin.tenants'), wrap(async (req, res) => {
  const tenants = await sql('SELECT id, name FROM tenants ORDER BY name');
  const tables = [
    ['events', 'Eventos'], ['alerts', 'Alertas'], ['incidents', 'Incidentes'], ['cases', 'Cases'],
    ['vulnerabilities', 'Vulnerabilidades'], ['assets', 'Ativos'], ['users', 'Usuários'],
    ['connector_configs', 'Connectors'], ['environments', 'Ambientes'],
  ];
  const matrix = [];
  for (const t of tenants.rows) {
    const row = { tenant: t.id, tenantName: t.name, cells: [] };
    for (const [tbl, label] of tables) {
      const r = await sql(`SELECT count(*)::int AS n FROM ${tbl} WHERE tenant=$1`, [t.id]).catch(() => ({ rows: [{ n: 0 }] }));
      row.cells.push({ table: tbl, label, count: r.rows[0]?.n ?? 0 });
    }
    matrix.push(row);
  }
  res.json(matrix);
}));

// ═══════════════ CONNECTORS (INTEGRAÇÕES POR CLIENTE) ═══════════════
const cfgRow = (c) => ({
  code: c.code, name: c.name, type: c.type,
  tenant: c.tenant, tenantName: c.tenant_name ?? null, env: c.env ?? null,
  settings: maskSettings(c.settings), enabled: c.enabled,
  pollSeconds: c.poll_seconds, push: Boolean(CONNECTOR_TYPES[c.type]?.push),
});

r.get('/connectors/types', requirePerm('connectors.read'), (req, res) => {
  res.json(Object.entries(CONNECTOR_TYPES).map(([id, t]) => ({ id, label: t.label, push: t.push, fields: t.fields })));
});

r.get('/connectors', requirePerm('connectors.read'), wrap(async (req, res) => {
  const rows = await loadConnectorConfigs(false);
  res.json(rows.map(cfgRow));
}));

r.post('/connectors', requirePerm('connectors.update'), wrap(async (req, res) => {
  const { name, type, tenant, env = null, settings = {}, enabled = true, pollSeconds = 20 } = req.body ?? {};
  if (!name || !type || !tenant) return res.status(400).json({ error: 'nome, tipo e cliente são obrigatórios' });
  if (!CONNECTOR_TYPES[type]) return res.status(400).json({ error: `tipo inválido: ${type}` });
  const t = await sql('SELECT 1 FROM tenants WHERE id = $1', [tenant]);
  if (!t.rowCount) return res.status(400).json({ error: `cliente não encontrado: ${tenant}` });

  const code = await nextCode('CON', 'seq_connectors');
  await sql(
    `INSERT INTO connector_configs (code, name, type, tenant, env, settings, enabled, poll_seconds)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
    [code, name, type, tenant, env, JSON.stringify(settings ?? {}), !!enabled, Number(pollSeconds) || 20]);
  await addAudit(actorOf(req), 'criou connector', `${name} [${type}] → ${tenant}${env ? ` / ${env}` : ''}`, 'system', tenant);
  res.status(201).json({ ok: true, code });
}));

r.patch('/connectors/:code', requirePerm('connectors.update'), wrap(async (req, res) => {
  const { code } = req.params;
  const { name, tenant, env, settings, enabled, pollSeconds } = req.body ?? {};
  const cur = await sql('SELECT * FROM connector_configs WHERE code = $1', [code]);
  if (!cur.rowCount) return res.status(404).json({ error: 'connector não encontrado' });
  const c = cur.rows[0];

  let mergedSettings = c.settings ?? {};
  if (settings && typeof settings === 'object') {
    mergedSettings = { ...mergedSettings, ...settings };
    // senha mascarada no formulário → mantém a senha atual
    mergedSettings.pass = resolvePass(settings.pass, (c.settings ?? {}).pass);
  }

  await sql(
    `UPDATE connector_configs SET
       name = COALESCE($2, name),
       tenant = COALESCE($3, tenant),
       env = COALESCE($4, env),
       settings = $5,
       enabled = COALESCE($6, enabled),
       poll_seconds = COALESCE($7, poll_seconds)
     WHERE code = $1`,
    [code, name ?? null, tenant ?? null, env === undefined ? null : env, JSON.stringify(mergedSettings),
     enabled === undefined ? null : !!enabled, pollSeconds === undefined ? null : Number(pollSeconds) || 20]);
  await addAudit(actorOf(req), 'atualizou connector', code, 'system', tenant ?? c.tenant);
  res.json({ ok: true });
}));

r.delete('/connectors/:code', requirePerm('connectors.update'), wrap(async (req, res) => {
  const { code } = req.params;
  const cur = await sql('DELETE FROM connector_configs WHERE code = $1 RETURNING tenant, name', [code]);
  if (!cur.rowCount) return res.status(404).json({ error: 'connector não encontrado' });
  await addAudit(actorOf(req), 'removeu connector', `${cur.rows[0].name} [${code}]`, 'system', cur.rows[0].tenant);
  res.json({ ok: true });
}));

// testa uma conexão (sem salvar) — body: { type, settings }
r.post('/connectors/test', requirePerm('connectors.update'), wrap(async (req, res) => {
  const { type, settings } = req.body ?? {};
  if (!type) return res.status(400).json({ error: 'informe o tipo' });
  const result = await testConnector(type, settings ?? {});
  res.json(result);
}));

// testa um connector já salvo
r.post('/connectors/:code/test', requirePerm('connectors.update'), wrap(async (req, res) => {
  const { code } = req.params;
  const cur = await sql('SELECT * FROM connector_configs WHERE code = $1', [code]);
  if (!cur.rowCount) return res.status(404).json({ error: 'connector não encontrado' });
  const c = cur.rows[0];
  const result = await testConnector(c.type, c.settings ?? {});
  res.json(result);
}));

// ═══════════════ IDENTIDADE (SSO + POLÍTICAS) ═══════════════
r.get('/identity/settings', requirePerm('identity.read'), wrap(async (req, res) => {
  res.json(await getSettings());
}));

r.patch('/identity/settings', requirePerm('identity.manage'), wrap(async (req, res) => {
  const out = await patchSettings(req.body ?? {});
  await addAudit(actorOf(req), 'atualizou políticas de segurança', 'security_settings', 'auth', null);
  res.json(out);
}));

r.get('/identity/providers', requirePerm('identity.read'), wrap(async (req, res) => {
  res.json(await listProviders(false));
}));

r.post('/identity/providers', requirePerm('identity.manage'), wrap(async (req, res) => {
  const { name, issuer, clientId, clientSecret, autoProvision = true, defaultRole = 'SOC Analyst', enabled = true } = req.body ?? {};
  if (!name || !issuer || !clientId) return res.status(400).json({ error: 'nome, issuer e client_id são obrigatórios' });
  if (!(await roleExists(defaultRole))) return res.status(400).json({ error: `perfil não encontrado: ${defaultRole}` });
  const code = 'idp-' + crypto.randomBytes(4).toString('hex');
  await sql(
    `INSERT INTO identity_providers (code, name, type, issuer, client_id, client_secret, auto_provision, default_role, enabled)
     VALUES ($1,$2,'oidc',$3,$4,$5,$6,$7,$8)`,
    [code, name, issuer, clientId, clientSecret ?? null, !!autoProvision, defaultRole, !!enabled]);
  await addAudit(actorOf(req), 'criou provedor de identidade (SSO)', `${name} [${code}]`, 'auth', null);
  res.status(201).json({ ok: true, code });
}));

r.patch('/identity/providers/:code', requirePerm('identity.manage'), wrap(async (req, res) => {
  const { code } = req.params;
  const { name, issuer, clientId, clientSecret, autoProvision, defaultRole, enabled } = req.body ?? {};
  const cur = await sql('SELECT * FROM identity_providers WHERE code = $1', [code]);
  if (!cur.rowCount) return res.status(404).json({ error: 'provedor não encontrado' });
  const p = cur.rows[0];
  const secret = clientSecret === undefined || clientSecret === '' || /^\*+$/.test(String(clientSecret))
    ? p.client_secret
    : clientSecret;
  await sql(
    `UPDATE identity_providers SET
       name = COALESCE($2, name), issuer = COALESCE($3, issuer),
       client_id = COALESCE($4, client_id), client_secret = $5,
       auto_provision = COALESCE($6, auto_provision),
       default_role = COALESCE($7, default_role),
       enabled = COALESCE($8, enabled)
     WHERE code = $1`,
    [code, name ?? null, issuer ?? null, clientId ?? null, secret,
     autoProvision === undefined ? null : !!autoProvision, defaultRole ?? null,
     enabled === undefined ? null : !!enabled]);
  await addAudit(actorOf(req), 'atualizou provedor de identidade', code, 'auth', null);
  res.json({ ok: true });
}));

r.delete('/identity/providers/:code', requirePerm('identity.manage'), wrap(async (req, res) => {
  const cur = await sql('DELETE FROM identity_providers WHERE code = $1 RETURNING name', [req.params.code]);
  if (!cur.rowCount) return res.status(404).json({ error: 'provedor não encontrado' });
  await addAudit(actorOf(req), 'removeu provedor de identidade', cur.rows[0].name, 'auth', null);
  res.json({ ok: true });
}));

// valida o discovery (.well-known) antes de salvar/usar
r.post('/identity/providers/test', requirePerm('identity.manage'), wrap(async (req, res) => {
  const { issuer } = req.body ?? {};
  if (!issuer) return res.status(400).json({ error: 'informe o issuer' });
  try {
    const doc = await fetchDiscovery(issuer);
    res.json({
      ok: true,
      message: 'Discovery válido — provedor OIDC acessível',
      endpoints: {
        authorization: doc.authorization_endpoint,
        token: doc.token_endpoint,
        userinfo: doc.userinfo_endpoint ?? null,
        jwks: doc.jwks_uri ?? null,
      },
    });
  } catch (err) {
    res.json({ ok: false, message: err.message });
  }
}));

export default r;
