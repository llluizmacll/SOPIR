// ─────────────────────────────────────────────────────────────
// SOPIR API · Identity — sessões, recuperação, políticas e OIDC
// ─────────────────────────────────────────────────────────────
import crypto from 'crypto';
import { sql } from './db.js';
import { sha256hex, generateRecoveryCodes } from './totp.js';

// ── políticas de segurança (tabela security_settings) ────────
const DEFAULTS = {
  session_ttl_hours: 12,
  min_password_length: 8,
  mfa_required_roles: [],
  sso_enabled: true,
  sso_auto_provision: true,
};

export async function getSettings() {
  const rows = await sql('SELECT key, value FROM security_settings');
  const out = { ...DEFAULTS };
  for (const r of rows.rows) out[r.key] = r.value;
  return out;
}

export async function patchSettings(patch) {
  for (const [key, value] of Object.entries(patch ?? {})) {
    if (!(key in DEFAULTS)) continue;
    await sql(
      `INSERT INTO security_settings (key, value) VALUES ($1,$2)
       ON CONFLICT (key) DO UPDATE SET value = $2`,
      [key, JSON.stringify(value)]);
  }
  return getSettings();
}

export function assertPasswordPolicy(pw, settings) {
  const min = settings?.min_password_length ?? DEFAULTS.min_password_length;
  if (!pw || String(pw).length < min) {
    return `senha deve ter ao menos ${min} caracteres`;
  }
  return null;
}

// ── sessões ──────────────────────────────────────────────────
export async function createSession(username, ttlHours, ip, ua) {
  const sid = crypto.randomUUID();
  const expires = new Date(Date.now() + ttlHours * 3_600_000);
  await sql(
    `INSERT INTO sessions (sid, username, ip, ua, expires_at)
     VALUES ($1,$2,$3,$4,$5)`,
    [sid, username, ip ?? null, ua ? String(ua).slice(0, 300) : null, expires]);
  // limpa sessões antigas/revogadas (higiene)
  sql(`DELETE FROM sessions WHERE expires_at < now() - interval '7 days' OR (revoked_at IS NOT NULL AND revoked_at < now() - interval '7 days')`).catch(() => {});
  return { sid, expiresAt: expires };
}

export async function findSession(sid) {
  const r = await sql('SELECT * FROM sessions WHERE sid = $1', [sid]);
  return r.rows[0] ?? null;
}

/** Atualiza last_seen com throttle (1x a cada 5 min por sessão). */
export async function touchSession(sid) {
  await sql(
    `UPDATE sessions SET last_seen = now()
      WHERE sid = $1 AND (last_seen IS NULL OR last_seen < now() - interval '5 minutes')`,
    [sid]);
}

export async function revokeSession(sid, username) {
  const q = username
    ? 'UPDATE sessions SET revoked_at = now() WHERE sid = $1 AND username = $2 RETURNING 1'
    : 'UPDATE sessions SET revoked_at = now() WHERE sid = $1 RETURNING 1';
  const p = username ? [sid, username] : [sid];
  const r = await sql(q, p);
  return r.rowCount > 0;
}

export async function revokeOtherSessions(username, keepSid) {
  const r = await sql(
    `UPDATE sessions SET revoked_at = now()
      WHERE username = $1 AND revoked_at IS NULL AND sid <> $2`,
    [username, keepSid ?? '']);
  return r.rowCount;
}

export async function listSessions(username) {
  const r = await sql(
    `SELECT sid, ip, ua, created_at, expires_at, last_seen, revoked_at
       FROM sessions WHERE username = $1
      ORDER BY created_at DESC LIMIT 25`,
    [username]);
  return r.rows.map((s) => ({
    id: s.sid, ip: s.ip, ua: s.ua,
    created: Date.parse(s.created_at), expires: Date.parse(s.expires_at),
    lastSeen: s.last_seen ? Date.parse(s.last_seen) : null,
    revoked: s.revoked_at ? Date.parse(s.revoked_at) : null,
  }));
}

// ── códigos de recuperação (MFA fallback, uso único) ─────────
export async function storeRecoveryCodes(username, codes) {
  await sql('DELETE FROM recovery_codes WHERE username = $1', [username]);
  for (const c of codes) {
    await sql('INSERT INTO recovery_codes (username, code_hash) VALUES ($1,$2)', [username, sha256hex(c)]);
  }
}

/** Consome um código de recuperação; retorna true se válido. */
export async function consumeRecoveryCode(username, code) {
  const norm = String(code ?? '').trim().toLowerCase();
  if (!norm) return false;
  const r = await sql(
    `UPDATE recovery_codes SET used_at = now()
      WHERE username = $1 AND code_hash = $2 AND used_at IS NULL
      RETURNING id`,
    [username, sha256hex(norm)]);
  return r.rowCount > 0;
}

// ── recuperação de senha (token de uso único, 30 min) ────────
export async function createPasswordReset(username) {
  const token = crypto.randomBytes(32).toString('base64url');
  const expires = new Date(Date.now() + 30 * 60_000);
  await sql(
    `INSERT INTO password_resets (token_hash, username, expires_at) VALUES ($1,$2,$3)`,
    [sha256hex(token), username, expires]);
  return { token, expiresAt: expires };
}

/** Valida e consome o token; retorna o username ou null. */
export async function consumePasswordReset(token) {
  if (!token) return null;
  const r = await sql(
    `UPDATE password_resets SET used_at = now()
      WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now()
      RETURNING username`,
    [sha256hex(token)]);
  return r.rows[0]?.username ?? null;
}

// ── OIDC (SSO) ───────────────────────────────────────────────
const oidcCache = new Map(); // issuer → { at, doc }

export async function fetchDiscovery(issuer) {
  const base = String(issuer).replace(/\/$/, '');
  const url = base.endsWith('/.well-known/openid-configuration') ? base : `${base}/.well-known/openid-configuration`;
  const cached = oidcCache.get(base);
  if (cached && Date.now() - cached.at < 10 * 60_000) return cached.doc;
  const res = await fetch(url, { signal: AbortSignal.timeout(10_000) });
  if (!res.ok) throw new Error(`discovery respondeu HTTP ${res.status} em ${url}`);
  const doc = await res.json();
  if (!doc.authorization_endpoint || !doc.token_endpoint) {
    throw new Error('discovery inválido — endpoints ausentes');
  }
  oidcCache.set(base, { at: Date.now(), doc });
  return doc;
}

export async function exchangeCode(doc, provider, code, redirectUri) {
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code, redirect_uri: redirectUri,
    client_id: provider.client_id,
    client_secret: provider.client_secret ?? '',
  });
  const res = await fetch(doc.token_endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
    signal: AbortSignal.timeout(10_000),
  });
  if (!res.ok) throw new Error(`token endpoint respondeu HTTP ${res.status}`);
  return res.json();
}

export async function fetchUserInfo(doc, accessToken) {
  if (!doc.userinfo_endpoint) return null;
  const res = await fetch(doc.userinfo_endpoint, {
    headers: { Authorization: `Bearer ${accessToken}` },
    signal: AbortSignal.timeout(10_000),
  });
  if (!res.ok) return null;
  return res.json();
}

export function getProvider(code) {
  return sql('SELECT * FROM identity_providers WHERE code = $1', [code]).then((r) => r.rows[0] ?? null);
}

export function listProviders(enabledOnly = false) {
  return sql(
    `SELECT code, name, type, issuer, client_id, auto_provision, default_role, enabled, created_at
       FROM identity_providers ${enabledOnly ? 'WHERE enabled' : ''} ORDER BY name`
  ).then((r) => r.rows.map((p) => ({
    code: p.code, name: p.name, type: p.type, issuer: p.issuer,
    clientId: p.client_id, autoProvision: p.auto_provision,
    defaultRole: p.default_role, enabled: p.enabled,
    created: p.created_at ? Date.parse(p.created_at) : null,
    hasSecret: false, // nunca expor
  })));
}
