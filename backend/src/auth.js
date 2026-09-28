// ─────────────────────────────────────────────────────────────
// SOPIR API · Autenticação JWT + MFA + Sessões + SSO (OIDC)
//
// · login bcrypt → (MFA?) → JWT com claim de sessão (sid)
// · sessões persistidas: listagem, revogação, expiração por política
// · MFA TOTP com códigos de recuperação (uso único)
// · recuperação de senha por token (30min, uso único)
// · SSO/OIDC: discovery, authorization code, auto-provisionamento
// · RBAC dinâmico (embutido + perfis customizados no banco)
// ─────────────────────────────────────────────────────────────
import { Router } from 'express';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { sql, addAudit, auditCtx } from './db.js';
import { generateSecret, otpauthUri, verifyTotp, generateRecoveryCodes } from './totp.js';
import {
  getSettings, assertPasswordPolicy,
  createSession, findSession, touchSession, revokeSession, revokeOtherSessions, listSessions,
  storeRecoveryCodes, consumeRecoveryCode,
  createPasswordReset, consumePasswordReset,
  fetchDiscovery, exchangeCode, fetchUserInfo, getProvider, listProviders,
} from './identity.js';

export const JWT_SECRET = process.env.JWT_SECRET || 'sopir-dev-secret-troque-em-producao';
const FRONTEND_URL = (process.env.FRONTEND_URL || 'http://localhost:8080').replace(/\/$/, '');
const RESET_DEV = String(process.env.SOPIR_RESET_DEV ?? 'true') === 'true';

// ── papéis embutidos ─────────────────────────────────────────
export const ROLE_PERMS = {
  Admin: ['*'],
  'SOC Manager': [
    'alerts.*', 'incidents.*', 'cases.*', 'assets.*', 'vulns.read',
    'correlations.read', 'correlations.update',
    'investigations.read', 'investigations.update',
    'connectors.read', 'connectors.update',
    'identity.read',
    'response.execute', 'response.approve', 'reports.export', 'audit.read',
    'sla.read', 'sla.update', 'portal.read',
  ],
  'SOC Analyst': [
    'alerts.read', 'alerts.update', 'incidents.read', 'incidents.update',
    'cases.read', 'cases.update', 'assets.read',
    'correlations.read', 'investigations.read', 'investigations.update',
    'connectors.read', 'sla.read', 'portal.read',
  ],
  'Security Engineer': ['vulns.*', 'remediation.execute', 'assets.read', 'assets.update', 'investigations.read'],
  Customer: ['portal.read'],
};

// ── catálogo de permissões (alimenta a UI de perfis) ─────────
export const PERM_CATALOG = [
  { module: 'Alertas', perms: [['alerts.read', 'Visualizar alertas'], ['alerts.update', 'Triagem & atualização']] },
  { module: 'Incidentes', perms: [['incidents.read', 'Visualizar incidentes'], ['incidents.update', 'Gerir ciclo de vida']] },
  { module: 'Cases', perms: [['cases.read', 'Visualizar cases'], ['cases.update', 'Gerir cases']] },
  { module: 'Ativos', perms: [['assets.read', 'Visualizar inventário'], ['assets.update', 'Isolar / liberar ativos']] },
  { module: 'Vulnerabilidades', perms: [['vulns.read', 'Visualizar findings'], ['vulns.update', 'Remediação & aceite de risco']] },
  { module: 'Correlação', perms: [['correlations.read', 'Ver políticas'], ['correlations.update', 'Ativar / desativar políticas']] },
  { module: 'Investigação', perms: [['investigations.read', 'Montar grafo'], ['investigations.update', 'Salvar investigações']] },
  { module: 'Resposta (SOAR)', perms: [['response.execute', 'Executar playbooks'], ['response.approve', 'Aprovar ações']] },
  { module: 'Remediação', perms: [['remediation.execute', 'Executar remediações']] },
  { module: 'Relatórios', perms: [['reports.export', 'Exportar relatórios']] },
  { module: 'Auditoria', perms: [['audit.read', 'Ler trilha de auditoria']] },
  { module: 'Portal do Cliente', perms: [['portal.read', 'Visão executiva do cliente']] },
  { module: 'Integrações', perms: [['connectors.read', 'Ver connectors & saúde'], ['connectors.update', 'Configurar connectors por cliente']] },
  { module: 'SLA & Performance', perms: [['sla.read', 'Ver políticas & conformidade SLA'], ['sla.update', 'Editar políticas de SLA']] },
  { module: 'Identidade', perms: [['identity.read', 'Ver provedores SSO & políticas'], ['identity.manage', 'Gerir SSO, MFA e políticas']] },
  { module: 'Administração', perms: [['admin.users', 'Gerir usuários'], ['admin.roles', 'Gerir perfis de acesso'], ['admin.tenants', 'Gerir clientes (tenants)']] },
];

export function canPerms(perms, perm) {
  return (perms ?? []).some((p) => p === '*' || p === perm || (p.endsWith('.*') && perm.startsWith(p.slice(0, -1))));
}

/** Alias de compatibilidade (apenas o mapa estático). */
export function can(role, perm) {
  return canPerms(ROLE_PERMS[role] ?? [], perm);
}

// ── resolução de permissões (embutido → custom, com cache) ───
const roleCache = { map: new Map(), at: 0 };
const CACHE_TTL = 20_000;

export function invalidateRoleCache() {
  roleCache.map.clear();
  roleCache.at = 0;
}

export async function roleExists(role) {
  if (ROLE_PERMS[role]) return true;
  const r = await sql('SELECT 1 FROM roles WHERE name = $1', [role]);
  return r.rowCount > 0;
}

export async function resolvePerms(role) {
  const fresh = Date.now() - roleCache.at < CACHE_TTL;
  if (fresh && roleCache.map.has(role)) return roleCache.map.get(role);
  const r = await sql('SELECT permissions FROM roles WHERE name = $1', [role]);
  const perms = r.rows[0]?.permissions?.length ? r.rows[0].permissions : (ROLE_PERMS[role] ?? []);
  if (!fresh) { roleCache.map.clear(); roleCache.at = Date.now(); }
  roleCache.map.set(role, perms);
  return perms;
}

// ── middlewares ──────────────────────────────────────────────
export async function requireAuth(req, res, next) {
  const header = req.headers.authorization ?? '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'token não informado' });
  try {
    const claims = jwt.verify(token, JWT_SECRET);
    if (claims.mfa) return res.status(401).json({ error: 'verificação MFA pendente' });

    // sessão: tokens emitidos com sid precisam de sessão válida
    if (claims.sid) {
      const sess = await findSession(claims.sid);
      if (!sess || sess.revoked_at || Date.parse(sess.expires_at) < Date.now()) {
        return res.status(401).json({ error: 'sessão encerrada' });
      }
      void touchSession(claims.sid).catch(() => {});
    }

    const perms = await resolvePerms(claims.role);
    req.auth = {
      username: claims.sub, name: claims.name, role: claims.role,
      tenant: claims.tenant ?? null, perms, sid: claims.sid ?? null,
    };
    // vincula a sessão ao contexto de auditoria desta request
    const ctx = auditCtx.getStore();
    if (ctx) ctx.sid = claims.sid ?? null;
    return next();
  } catch {
    return res.status(401).json({ error: 'token inválido ou expirado' });
  }
}

export function requirePerm(perm) {
  return (req, res, next) => {
    if (!req.auth) return res.status(401).json({ error: 'não autenticado' });
    if (!canPerms(req.auth.perms, perm)) {
      return res.status(403).json({ error: `permissão negada: requer ${perm}` });
    }
    return next();
  };
}

export function effectiveTenant(req) {
  if (req.auth?.tenant) return req.auth.tenant;
  return req.query.tenant || 'all';
}

// ── helpers de emissão ───────────────────────────────────────
async function loadUser(username) {
  const r = await sql('SELECT * FROM users WHERE username = $1', [String(username).toLowerCase().trim()]);
  return r.rows[0] ?? null;
}

async function issueFull(user, req) {
  const settings = await getSettings();
  const ttl = Number(settings.session_ttl_hours) || 12;
  const sess = await createSession(user.username, ttl, req?.ip, req?.headers?.['user-agent']);
  const permissions = await resolvePerms(user.role);
  const token = jwt.sign(
    { sub: user.username, name: user.name, role: user.role, tenant: user.tenant, sid: sess.sid },
    JWT_SECRET,
    { expiresIn: `${ttl}h` },
  );
  await sql('UPDATE users SET last_login = now() WHERE username = $1', [user.username]);
  return {
    token,
    user: { username: user.username, name: user.name, role: user.role, tenant: user.tenant, permissions, mfaEnabled: !!user.mfa_enabled },
  };
}

const signMfaToken = (user) =>
  jwt.sign({ sub: user.username, name: user.name, role: user.role, tenant: user.tenant, mfa: 1 }, JWT_SECRET, { expiresIn: '5m' });

/** Resolve o usuário a partir de Bearer (req.auth) ou de um mfaToken no body. */
async function resolveActor(req) {
  if (req.auth) return loadUser(req.auth.username);
  const t = req.body?.mfaToken;
  if (!t) return null;
  try {
    const claims = jwt.verify(t, JWT_SECRET);
    if (!claims.mfa) return null;
    return loadUser(claims.sub);
  } catch {
    return null;
  }
}

// ── rotas de autenticação ────────────────────────────────────
export const authRouter = Router();

authRouter.post('/login', async (req, res) => {
  const { username, password } = req.body ?? {};
  if (!username || !password) return res.status(400).json({ error: 'usuário e senha obrigatórios' });

  const user = await loadUser(username);
  if (!user || !bcrypt.compareSync(String(password), user.pass_hash)) {
    await addAudit(String(username), 'login falhou (credenciais inválidas)', String(username), 'auth', null, { outcome: 'denied' }).catch(() => {});
    return res.status(401).json({ error: 'usuário ou senha inválidos' });
  }
  if (user.active === false) {
    await addAudit(user.name, 'login negado (usuário suspenso)', user.username, 'auth', user.tenant, { outcome: 'denied' }).catch(() => {});
    return res.status(403).json({ error: 'usuário suspenso — contate o administrador' });
  }
  if (!(await roleExists(user.role))) {
    return res.status(403).json({ error: 'perfil de acesso não encontrado' });
  }

  const settings = await getSettings();
  const short = { username: user.username, name: user.name, role: user.role, mfaEnabled: !!user.mfa_enabled };

  // MFA habilitado → segundo fator obrigatório
  if (user.mfa_enabled) {
    return res.json({ mfaRequired: true, mfaToken: signMfaToken(user), user: short });
  }
  // política: papéis que exigem MFA → matrícula obrigatória antes de entrar
  if ((settings.mfa_required_roles ?? []).includes(user.role)) {
    return res.json({ mustEnroll: true, mfaToken: signMfaToken(user), user: short });
  }

  const out = await issueFull(user, req);
  await addAudit(user.name, 'login bem-sucedido (JWT emitido)', user.username, 'auth', user.tenant).catch(() => {});
  res.json(out);
});

authRouter.get('/me', requireAuth, (req, res) => {
  res.json({ user: { ...req.auth, permissions: req.auth.perms } });
});

// ── MFA ──────────────────────────────────────────────────────
authRouter.post('/mfa/setup', requireAuthOrMfa, wrap(async (req, res) => {
  const user = await resolveActor(req);
  if (!user) return res.status(401).json({ error: 'não autenticado' });
  const secret = generateSecret();
  await sql('UPDATE users SET mfa_secret = $2 WHERE username = $1', [user.username, secret]);
  res.json({ secret, otpauth: otpauthUri(secret, user.username) });
}));

authRouter.post('/mfa/enable', requireAuthOrMfa, wrap(async (req, res) => {
  const user = await resolveActor(req);
  if (!user) return res.status(401).json({ error: 'não autenticado' });
  if (!user.mfa_secret) return res.status(400).json({ error: 'inicie a configuração (setup) antes' });
  if (!verifyTotp(user.mfa_secret, req.body?.code)) return res.status(400).json({ error: 'código inválido' });

  await sql('UPDATE users SET mfa_enabled = true WHERE username = $1', [user.username]);
  const codes = generateRecoveryCodes();
  await storeRecoveryCodes(user.username, codes);
  await addAudit(user.name, 'ativou MFA (TOTP)', user.username, 'auth', user.tenant).catch(() => {});

  if (req.body?.mfaToken) {
    // matrícula durante o login → já emite a sessão completa
    const fresh = await loadUser(user.username);
    const out = await issueFull(fresh, req);
    await addAudit(user.name, 'login MFA verificado (matrícula)', user.username, 'auth', user.tenant).catch(() => {});
    return res.json({ ok: true, recoveryCodes: codes, ...out });
  }
  res.json({ ok: true, recoveryCodes: codes });
}));

authRouter.post('/mfa/disable', requireAuth, wrap(async (req, res) => {
  const user = await loadUser(req.auth.username);
  if (!user?.mfa_enabled) return res.status(400).json({ error: 'MFA não está ativo' });
  if (!verifyTotp(user.mfa_secret, req.body?.code)) return res.status(400).json({ error: 'código inválido' });
  await sql('UPDATE users SET mfa_enabled = false, mfa_secret = NULL WHERE username = $1', [user.username]);
  await sql('DELETE FROM recovery_codes WHERE username = $1', [user.username]);
  await addAudit(user.name, 'desativou MFA', user.username, 'auth', user.tenant).catch(() => {});
  res.json({ ok: true });
}));

authRouter.post('/mfa/verify', wrap(async (req, res) => {
  const { mfaToken, code } = req.body ?? {};
  let claims;
  try { claims = jwt.verify(mfaToken, JWT_SECRET); } catch { return res.status(401).json({ error: 'token MFA inválido ou expirado' }); }
  if (!claims.mfa) return res.status(401).json({ error: 'token MFA inválido' });

  const user = await loadUser(claims.sub);
  if (!user || !user.mfa_enabled) return res.status(400).json({ error: 'MFA não configurado' });

  const okTotp = verifyTotp(user.mfa_secret, code);
  const okRecovery = !okTotp && await consumeRecoveryCode(user.username, code);
  if (!okTotp && !okRecovery) return res.status(401).json({ error: 'código inválido' });

  const out = await issueFull(user, req);
  await addAudit(user.name, okRecovery ? 'login com código de recuperação' : 'login MFA verificado', user.username, 'auth', user.tenant).catch(() => {});
  res.json(out);
}));

authRouter.post('/mfa/reset', requireAuth, requirePerm('admin.users'), wrap(async (req, res) => {
  const { username } = req.body ?? {};
  const user = await loadUser(username);
  if (!user) return res.status(404).json({ error: 'usuário não encontrado' });
  await sql('UPDATE users SET mfa_enabled = false, mfa_secret = NULL WHERE username = $1', [user.username]);
  await sql('DELETE FROM recovery_codes WHERE username = $1', [user.username]);
  await addAudit(req.auth.name, 'resetou MFA de usuário', user.username, 'auth', user.tenant).catch(() => {});
  res.json({ ok: true });
}));

authRouter.get('/recovery-codes/regen', requireAuth, wrap(async (req, res) => {
  const user = await loadUser(req.auth.username);
  if (!user?.mfa_enabled) return res.status(400).json({ error: 'ative o MFA antes de gerar códigos' });
  const codes = generateRecoveryCodes();
  await storeRecoveryCodes(user.username, codes);
  await addAudit(user.name, 'regerou códigos de recuperação', user.username, 'auth', user.tenant).catch(() => {});
  res.json({ codes });
}));

// ── sessões ──────────────────────────────────────────────────
authRouter.get('/sessions', requireAuth, wrap(async (req, res) => {
  const sessions = await listSessions(req.auth.username);
  res.json(sessions.map((sn) => ({ ...sn, current: sn.id === req.auth.sid })));
}));

authRouter.delete('/sessions/:sid', requireAuth, wrap(async (req, res) => {
  const ok = await revokeSession(req.params.sid, req.auth.username);
  if (!ok) return res.status(404).json({ error: 'sessão não encontrada' });
  await addAudit(req.auth.name, 'encerrou sessão', req.params.sid.slice(0, 8) + '…', 'auth', req.auth.tenant).catch(() => {});
  res.json({ ok: true });
}));

authRouter.post('/sessions/revoke-others', requireAuth, wrap(async (req, res) => {
  const n = await revokeOtherSessions(req.auth.username, req.auth.sid);
  await addAudit(req.auth.name, `encerrou ${n} outra(s) sessão(ões)`, req.auth.username, 'auth', req.auth.tenant).catch(() => {});
  res.json({ ok: true, revoked: n });
}));

// ── recuperação de senha ─────────────────────────────────────
authRouter.post('/forgot', wrap(async (req, res) => {
  const { username } = req.body ?? {};
  const user = await loadUser(username ?? '');
  // anti-enumeração: resposta sempre igual
  if (user && user.active !== false) {
    const { token } = await createPasswordReset(user.username);
    console.log(`[auth] token de recuperação para ${user.username}: ${token}`);
    await addAudit(user.name, 'solicitou recuperação de senha', user.username, 'auth', user.tenant).catch(() => {});
    if (RESET_DEV) return res.json({ ok: true, devToken: token });
  }
  res.json({ ok: true });
}));

authRouter.post('/reset', wrap(async (req, res) => {
  const { token, password } = req.body ?? {};
  const username = await consumePasswordReset(token);
  if (!username) return res.status(400).json({ error: 'token inválido ou expirado' });
  const settings = await getSettings();
  const policyErr = assertPasswordPolicy(password, settings);
  if (policyErr) return res.status(400).json({ error: policyErr });
  await sql('UPDATE users SET pass_hash = $2 WHERE username = $1', [username, bcrypt.hashSync(String(password), 10)]);
  await revokeOtherSessions(username, ''); // derruba todas as sessões
  await addAudit(username, 'redefiniu senha via token de recuperação', username, 'auth', null).catch(() => {});
  res.json({ ok: true });
}));

// ── SSO / OIDC ───────────────────────────────────────────────
authRouter.get('/sso/providers', wrap(async (req, res) => {
  const settings = await getSettings();
  if (!settings.sso_enabled) return res.json([]);
  const providers = await listProviders(true);
  res.json(providers.map((p) => ({ code: p.code, name: p.name, type: p.type })));
}));

authRouter.get('/sso/:code/start', wrap(async (req, res) => {
  const provider = await getProvider(req.params.code);
  if (!provider || !provider.enabled) return res.redirect(`${FRONTEND_URL}/#sso_error=provedor+indisponível`);
  const doc = await fetchDiscovery(provider.issuer);
  const state = jwt.sign({ p: provider.code }, JWT_SECRET, { expiresIn: '10m' });
  const redirectUri = `${FRONTEND_URL}/api/v1/auth/sso/${provider.code}/callback`;
  const url = new URL(doc.authorization_endpoint);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', provider.client_id);
  url.searchParams.set('redirect_uri', redirectUri);
  url.searchParams.set('scope', 'openid profile email');
  url.searchParams.set('state', state);
  res.redirect(url.toString());
}));

authRouter.get('/sso/:code/callback', wrap(async (req, res) => {
  const fail = (msg) => res.redirect(`${FRONTEND_URL}/#sso_error=${encodeURIComponent(msg)}`);
  try {
    const claims = jwt.verify(req.query.state ?? '', JWT_SECRET);
    if (claims.p !== req.params.code) return fail('estado inválido');
  } catch {
    return fail('estado expirado');
  }

  const provider = await getProvider(req.params.code);
  if (!provider || !provider.enabled) return fail('provedor indisponível');

  const doc = await fetchDiscovery(provider.issuer);
  const redirectUri = `${FRONTEND_URL}/api/v1/auth/sso/${provider.code}/callback`;
  const tokens = await exchangeCode(doc, provider, req.query.code, redirectUri);

  let info = tokens.id_token ? jwt.decode(tokens.id_token) : null;
  if (!info?.email && !info?.preferred_username) {
    info = { ...(info ?? {}), ...(await fetchUserInfo(doc, tokens.access_token) ?? {}) };
  }
  const uname = String(info?.preferred_username || info?.email || '').toLowerCase().trim();
  if (!uname) return fail('provedor não retornou identificador de usuário');

  let user = await loadUser(uname);
  if (!user) {
    if (!provider.auto_provision) return fail('usuário não provisionado — contate o administrador');
    await sql(
      `INSERT INTO users (username, name, role, tenant, pass_hash, active)
       VALUES ($1,$2,$3,NULL,$4,true)`,
      [uname, info?.name || uname, provider.default_role, bcrypt.hashSync(crypto.randomBytes(24).toString('hex'), 10)]);
    await addAudit('sistema', 'provisionou usuário via SSO', `${uname} [${provider.name}]`, 'auth', null).catch(() => {});
    user = await loadUser(uname);
  }
  if (user.active === false) return fail('usuário suspenso');

  const out = await issueFull(user, req);
  await addAudit(user.name, `login via SSO (${provider.name})`, user.username, 'auth', user.tenant).catch(() => {});
  res.redirect(`${FRONTEND_URL}/#sso=${encodeURIComponent(out.token)}`);
}));

// ── utilidades internas ──────────────────────────────────────
/** Aceita Bearer OU mfaToken (fluxo de matrícula MFA durante o login). */
async function requireAuthOrMfa(req, res, next) {
  if (req.headers.authorization?.startsWith('Bearer ')) return requireAuth(req, res, next);
  if (req.body?.mfaToken) return next();
  return res.status(401).json({ error: 'não autenticado' });
}

function wrap(fn) {
  return (req, res) => Promise.resolve(fn(req, res)).catch((err) => {
    console.error('[auth] ' + (err.stack || err.message));
    res.status(500).json({ error: err.message });
  });
}
