// ─────────────────────────────────────────────────────────────
// SOPIR API · camada de dados (PostgreSQL)
// + trilha de auditoria encadeada (hash chain / tamper-evident)
// ─────────────────────────────────────────────────────────────
import pg from 'pg';
import crypto from 'crypto';
import { AsyncLocalStorage } from 'async_hooks';

// Contexto por request (IP, user-agent, sessão) — preenchido pelo
// middleware global e consumido por addAudit automaticamente.
export const auditCtx = new AsyncLocalStorage();

export const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL || 'postgres://sopir:sopir@localhost:5432/sopir',
  max: 12,
});

export const sql = (text, params = []) => pool.query(text, params);

// camelCase → snake_case
export const snake = (s) => s.replace(/([A-Z])/g, '_$1').toLowerCase();

export async function waitForDb(maxTries = 30) {
  for (let i = 1; i <= maxTries; i++) {
    try {
      await sql('SELECT 1');
      return true;
    } catch (err) {
      console.log(`[db] aguardando PostgreSQL (${i}/${maxTries})… ${err.message.split('\n')[0]}`);
      await new Promise((r) => setTimeout(r, 2000));
    }
  }
  throw new Error('PostgreSQL indisponível');
}

// ── migrations idempotentes ──────────────────────────────────
export async function migrate() {
  const statements = [
    `CREATE TABLE IF NOT EXISTS tenants (
       id text PRIMARY KEY, name text NOT NULL, short text NOT NULL
     )`,
    `CREATE TABLE IF NOT EXISTS assets (
       id serial PRIMARY KEY, code text UNIQUE NOT NULL, tenant text NOT NULL,
       name text NOT NULL, type text NOT NULL, ip text, os text,
       crit int DEFAULT 50, status text DEFAULT 'online', owner text
     )`,
    `CREATE TABLE IF NOT EXISTS events (
       id serial PRIMARY KEY, code text UNIQUE NOT NULL, ext_id text UNIQUE,
       tenant text NOT NULL, source text NOT NULL, rule text NOT NULL, rule_id text,
       severity text NOT NULL, src_ip text, dst_ip text, app_user text,
       host text, agent text, description text, raw jsonb, ts timestamptz NOT NULL
     )`,
    `CREATE INDEX IF NOT EXISTS idx_events_ts ON events (ts DESC)`,
    `CREATE INDEX IF NOT EXISTS idx_events_tenant ON events (tenant)`,
    `CREATE TABLE IF NOT EXISTS alerts (
       id serial PRIMARY KEY, code text UNIQUE NOT NULL, tenant text NOT NULL,
       title text NOT NULL, severity text NOT NULL, status text NOT NULL,
       source text, rule text, rule_id text, src_ip text, dst_ip text,
       app_user text, host text, ts timestamptz NOT NULL, description text,
       assignee text, classification text, incident_code text
     )`,
    `CREATE TABLE IF NOT EXISTS incidents (
       code text PRIMARY KEY, tenant text NOT NULL, title text NOT NULL,
       severity text NOT NULL, status text NOT NULL, assignee text,
       ts timestamptz NOT NULL, sla_h int NOT NULL, asset text, case_code text
     )`,
    `CREATE TABLE IF NOT EXISTS incident_tasks (
       id serial PRIMARY KEY, inc_code text REFERENCES incidents(code) ON DELETE CASCADE,
       text text NOT NULL, done boolean DEFAULT false
     )`,
    `CREATE TABLE IF NOT EXISTS incident_timeline (
       id serial PRIMARY KEY, inc_code text REFERENCES incidents(code) ON DELETE CASCADE,
       ts timestamptz NOT NULL, text text NOT NULL, kind text DEFAULT 'user', author text
     )`,
    `CREATE TABLE IF NOT EXISTS incident_iocs (
       inc_code text REFERENCES incidents(code) ON DELETE CASCADE, ioc text NOT NULL
     )`,
    `CREATE TABLE IF NOT EXISTS incident_alerts (
       inc_code text REFERENCES incidents(code) ON DELETE CASCADE,
       alert_code text NOT NULL, UNIQUE (inc_code, alert_code)
     )`,
    `CREATE TABLE IF NOT EXISTS cases (
       code text PRIMARY KEY, tenant text NOT NULL, title text NOT NULL,
       severity text NOT NULL, stage text NOT NULL, assignee text, ts timestamptz NOT NULL
     )`,
    `CREATE TABLE IF NOT EXISTS case_comments (
       id serial PRIMARY KEY, case_code text REFERENCES cases(code) ON DELETE CASCADE,
       ts timestamptz NOT NULL, author text, text text NOT NULL
     )`,
    `CREATE TABLE IF NOT EXISTS case_refs (
       id serial PRIMARY KEY, case_code text REFERENCES cases(code) ON DELETE CASCADE,
       kind text NOT NULL, value text NOT NULL
     )`,
    // ── Case Management (fase 9): ciclo operacional completo ──
    `ALTER TABLE cases ADD COLUMN IF NOT EXISTS priority text`,
    `ALTER TABLE cases ADD COLUMN IF NOT EXISTS status text DEFAULT 'active'`,
    `ALTER TABLE cases ADD COLUMN IF NOT EXISTS opened_at timestamptz`,
    `ALTER TABLE cases ADD COLUMN IF NOT EXISTS closed_at timestamptz`,
    `CREATE TABLE IF NOT EXISTS case_tasks (
       id serial PRIMARY KEY, case_code text REFERENCES cases(code) ON DELETE CASCADE,
       text text NOT NULL, done boolean DEFAULT false, created_at timestamptz DEFAULT now()
     )`,
    `CREATE TABLE IF NOT EXISTS case_timeline (
       id serial PRIMARY KEY, case_code text REFERENCES cases(code) ON DELETE CASCADE,
       ts timestamptz NOT NULL, text text NOT NULL, kind text DEFAULT 'system', author text
     )`,
    `CREATE TABLE IF NOT EXISTS vulnerabilities (
       id serial PRIMARY KEY, code text UNIQUE NOT NULL, cve text NOT NULL,
       tenant text NOT NULL, title text NOT NULL, cvss numeric(3,1) NOT NULL,
       severity text NOT NULL, asset text, status text NOT NULL,
       found_ts timestamptz NOT NULL, fix text
     )`,
    `CREATE TABLE IF NOT EXISTS playbook_runs (
       code text PRIMARY KEY, pb_id text NOT NULL, pb_name text NOT NULL,
       step int DEFAULT 0, status text DEFAULT 'andamento',
       ts timestamptz NOT NULL, tenant text, actor text
     )`,
    `CREATE TABLE IF NOT EXISTS response_actions (
       id serial PRIMARY KEY, run_code text, kind text NOT NULL, target text,
       status text DEFAULT 'executada', ts timestamptz DEFAULT now()
     )`,
    `CREATE TABLE IF NOT EXISTS audit (
       id serial PRIMARY KEY, ts timestamptz DEFAULT now(), actor text NOT NULL,
       action text NOT NULL, target text, kind text DEFAULT 'system', tenant text
     )`,
    `CREATE TABLE IF NOT EXISTS connector_state (
       name text PRIMARY KEY, status text DEFAULT 'inicializando',
       last_ok timestamptz, last_error text, collected int DEFAULT 0,
       last_ts timestamptz
     )`,
    `CREATE TABLE IF NOT EXISTS users (
       username text PRIMARY KEY, name text NOT NULL, role text NOT NULL,
       tenant text, pass_hash text NOT NULL,
       active boolean DEFAULT true, last_login timestamptz
     )`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS active boolean DEFAULT true`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login timestamptz`,
    `ALTER TABLE tenants ADD COLUMN IF NOT EXISTS contact text`,
    `ALTER TABLE tenants ADD COLUMN IF NOT EXISTS created timestamptz DEFAULT now()`,
    `CREATE TABLE IF NOT EXISTS roles (
       name text PRIMARY KEY, display text NOT NULL, description text,
       permissions jsonb NOT NULL DEFAULT '[]', builtin boolean DEFAULT false,
       ts timestamptz DEFAULT now()
     )`,
    `CREATE TABLE IF NOT EXISTS investigations (
       code text PRIMARY KEY, tenant text, name text NOT NULL,
       root_type text, root_value text, graph jsonb NOT NULL,
       status text DEFAULT 'aberta', ts timestamptz DEFAULT now(), owner text
     )`,
    `CREATE TABLE IF NOT EXISTS connector_configs (
       code text PRIMARY KEY, name text NOT NULL, type text NOT NULL,
       tenant text NOT NULL, settings jsonb NOT NULL DEFAULT '{}',
       enabled boolean DEFAULT true, poll_seconds int DEFAULT 20,
       created timestamptz DEFAULT now()
     )`,
    `CREATE SEQUENCE IF NOT EXISTS seq_events START 80000`,
    `CREATE SEQUENCE IF NOT EXISTS seq_alerts START 4000`,
    `CREATE SEQUENCE IF NOT EXISTS seq_runs START 100`,
    `CREATE SEQUENCE IF NOT EXISTS seq_investigations START 10`,
    `CREATE SEQUENCE IF NOT EXISTS seq_connectors START 1`,
    // ── Identity & Authentication (fase 5) ──
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_secret text`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_enabled boolean DEFAULT false`,
    `CREATE TABLE IF NOT EXISTS sessions (
       sid text PRIMARY KEY, username text NOT NULL, token_hash text,
       ip text, ua text, created_at timestamptz DEFAULT now(),
       expires_at timestamptz NOT NULL, last_seen timestamptz,
       revoked_at timestamptz
     )`,
    `CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions (username)`,
    `CREATE TABLE IF NOT EXISTS recovery_codes (
       id serial PRIMARY KEY, username text NOT NULL,
       code_hash text NOT NULL, created_at timestamptz DEFAULT now(),
       used_at timestamptz
     )`,
    `CREATE TABLE IF NOT EXISTS password_resets (
       token_hash text PRIMARY KEY, username text NOT NULL,
       created_at timestamptz DEFAULT now(), expires_at timestamptz NOT NULL,
       used_at timestamptz
     )`,
    `CREATE TABLE IF NOT EXISTS identity_providers (
       code text PRIMARY KEY, name text NOT NULL, type text DEFAULT 'oidc',
       issuer text NOT NULL, client_id text NOT NULL, client_secret text,
       auto_provision boolean DEFAULT true, default_role text DEFAULT 'SOC Analyst',
       enabled boolean DEFAULT true, created_at timestamptz DEFAULT now()
     )`,
    `CREATE TABLE IF NOT EXISTS security_settings (
       key text PRIMARY KEY, value jsonb NOT NULL
     )`,
    // ── Multi-Tenancy: organizações, ambientes, quotas, branding ──
    `CREATE TABLE IF NOT EXISTS orgs (
       id text PRIMARY KEY, name text NOT NULL, short text,
       created timestamptz DEFAULT now()
     )`,
    `CREATE TABLE IF NOT EXISTS environments (
       code text PRIMARY KEY, tenant text NOT NULL, name text NOT NULL,
       kind text DEFAULT 'producao', created timestamptz DEFAULT now()
     )`,
    `ALTER TABLE tenants ADD COLUMN IF NOT EXISTS org_id text`,
    `ALTER TABLE tenants ADD COLUMN IF NOT EXISTS brand_color text`,
    `ALTER TABLE tenants ADD COLUMN IF NOT EXISTS tagline text`,
    `ALTER TABLE tenants ADD COLUMN IF NOT EXISTS max_users int`,
    `ALTER TABLE tenants ADD COLUMN IF NOT EXISTS max_assets int`,
    `ALTER TABLE tenants ADD COLUMN IF NOT EXISTS max_connectors int`,
    `ALTER TABLE events ADD COLUMN IF NOT EXISTS env text`,
    `ALTER TABLE alerts ADD COLUMN IF NOT EXISTS env text`,
    // enriquecimento de IOCs: além de src/dst IP, guarda hash/domínio/URL
    // extraídos na normalização (por evento) e agregados no alerta
    `ALTER TABLE events ADD COLUMN IF NOT EXISTS iocs jsonb DEFAULT '[]'`,
    // texto original detalhado (ex.: full_log do Wazuh, _raw do Splunk, a
    // própria linha CEF) e IP do host/agente reportante — distinto do IP de
    // origem da conexão (srcIp), quando a fonte expõe os dois
    `ALTER TABLE events ADD COLUMN IF NOT EXISTS message text`,
    `ALTER TABLE events ADD COLUMN IF NOT EXISTS host_ip text`,
    `ALTER TABLE alerts ADD COLUMN IF NOT EXISTS message text`,
    `ALTER TABLE alerts ADD COLUMN IF NOT EXISTS iocs jsonb DEFAULT '[]'`,
    `ALTER TABLE incidents ADD COLUMN IF NOT EXISTS env text`,
    `ALTER TABLE assets ADD COLUMN IF NOT EXISTS env text`,
    `ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS env text`,
    `ALTER TABLE connector_configs ADD COLUMN IF NOT EXISTS env text`,
    `CREATE SEQUENCE IF NOT EXISTS seq_orgs START 1`,
    `CREATE SEQUENCE IF NOT EXISTS seq_envs START 1`,
    // ── Audit & Compliance (fase 6) ──
    `ALTER TABLE audit ADD COLUMN IF NOT EXISTS ts_ms bigint`,
    `ALTER TABLE audit ADD COLUMN IF NOT EXISTS ip text`,
    `ALTER TABLE audit ADD COLUMN IF NOT EXISTS ua text`,
    `ALTER TABLE audit ADD COLUMN IF NOT EXISTS sid text`,
    `ALTER TABLE audit ADD COLUMN IF NOT EXISTS outcome text DEFAULT 'ok'`,
    `ALTER TABLE audit ADD COLUMN IF NOT EXISTS before jsonb`,
    `ALTER TABLE audit ADD COLUMN IF NOT EXISTS after jsonb`,
    `ALTER TABLE audit ADD COLUMN IF NOT EXISTS prev_hash text`,
    `ALTER TABLE audit ADD COLUMN IF NOT EXISTS hash text`,
    `ALTER TABLE audit ADD COLUMN IF NOT EXISTS control text`,
    `CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit (ts_ms DESC)`,
    `CREATE INDEX IF NOT EXISTS idx_audit_kind ON audit (kind)`,
    // ── Event Management (fase 7): supressão de alertas ──
    `CREATE TABLE IF NOT EXISTS suppression_rules (
       id serial PRIMARY KEY, rule_id text, host text, src_ip text,
       reason text, tenant text, enabled boolean DEFAULT true,
       expires_at timestamptz NOT NULL, created_at timestamptz DEFAULT now()
     )`,
    // ── Incident Management (fase 8): prioridade + SLA duplo ──
    `ALTER TABLE incidents ADD COLUMN IF NOT EXISTS priority text DEFAULT 'P3'`,
    `ALTER TABLE incidents ADD COLUMN IF NOT EXISTS first_response_at timestamptz`,
    `ALTER TABLE incidents ADD COLUMN IF NOT EXISTS resolved_at timestamptz`,
    `CREATE TABLE IF NOT EXISTS sla_policies (
       id serial PRIMARY KEY, tenant text NOT NULL, severity text NOT NULL,
       response_min int NOT NULL, resolution_min int NOT NULL,
       enabled boolean DEFAULT true, UNIQUE (tenant, severity)
     )`,
    // ── Retenção de eventos: quanto tempo guardar telemetria bruta antes
    // de apagar. tenant='*' é o padrão global; qualquer outro id é um
    // override específico daquele cliente (mesmo modelo do SLA acima).
    `CREATE TABLE IF NOT EXISTS retention_policies (
       tenant text PRIMARY KEY, days int NOT NULL DEFAULT 90,
       enabled boolean DEFAULT true, updated_at timestamptz DEFAULT now()
     )`,
    // ── Detection & Correlation: regras customizáveis ──
    `CREATE TABLE IF NOT EXISTS correlation_policies (
       code text PRIMARY KEY, name text NOT NULL, description text,
       severity text NOT NULL DEFAULT 'medium', enabled boolean DEFAULT true,
       window_sec int NOT NULL DEFAULT 300, threshold int NOT NULL DEFAULT 3,
       group_by jsonb NOT NULL DEFAULT '["host"]',
       match jsonb NOT NULL DEFAULT '{}',
       mode text NOT NULL DEFAULT 'count',
       mitre text, cooldown_sec int, builtin boolean DEFAULT false,
       created_at timestamptz DEFAULT now()
     )`,
    `CREATE SEQUENCE IF NOT EXISTS seq_correlation START 1`,
    // índice único pra permitir ON CONFLICT DO NOTHING ao extrair IOCs
    // automaticamente na escalação de alerta → incidente (evita duplicata)
    `CREATE UNIQUE INDEX IF NOT EXISTS idx_incident_iocs_unique ON incident_iocs (inc_code, ioc)`,
    // ── vínculo alerta ↔ evento(s) de origem — permite mostrar em "Eventos
    // relacionados" exatamente o que disparou o alerta, não uma busca genérica ──
    `CREATE TABLE IF NOT EXISTS alert_events (
       alert_code text NOT NULL REFERENCES alerts(code) ON DELETE CASCADE,
       event_code text NOT NULL,
       UNIQUE (alert_code, event_code)
     )`,
    `CREATE INDEX IF NOT EXISTS idx_alert_events_alert ON alert_events(alert_code)`,
  ];
  for (const st of statements) await sql(st);
  console.log('[db] migrações aplicadas');
  await sealLegacyAudit();
}

// ── cadeia de auditoria (tamper-evident) ─────────────────────
export const computeHash = (prev, tsMs, actor, action, target, kind) =>
  crypto.createHash('sha256')
    .update([prev, tsMs, actor, action, target ?? '', kind].join('|'))
    .digest('hex');

// Mapeia cada ação para um controle de referência (base SOC 2 / ISO 27001)
export function mapControl(kind, action = '') {
  const a = String(action).toLowerCase();
  if (a.includes('entre tenants')) return 'CC6.1';
  if (a.includes('login') || a.includes('senha') || a.includes('mfa') || a.includes('sessão')) return 'CC6.1';
  if (a.includes('bloque') || a.includes('isolamento') || a.includes('quarentena')) return 'CC6.6';
  if (a.includes('incidente')) return 'CC7.3';
  if (a.includes('alerta') || a.includes('triage') || a.includes('reconheceu')) return 'CC7.2';
  if (a.includes('playbook') || a.includes('resposta')) return 'CC7.4';
  const byKind = { auth: 'CC6.1', triage: 'CC7.2', response: 'CC7.4', data: 'CC8.1', system: 'CC8.1' };
  return byKind[kind] ?? 'CC8.1';
}

/** Sela registros antigos (sem hash) na cadeia — idempotente. */
async function sealLegacyAudit() {
  const missing = await sql(
    `SELECT id, ts, actor, action, target, kind FROM audit WHERE hash IS NULL ORDER BY id`);
  if (!missing.rowCount) return;
  const lastRow = await sql('SELECT hash FROM audit WHERE hash IS NOT NULL ORDER BY id DESC LIMIT 1');
  let prev = lastRow.rowCount ? lastRow.rows[0].hash : 'GENESIS';
  for (const r of missing.rows) {
    const tsMs = Date.parse(r.ts);
    const hash = computeHash(prev, tsMs, r.actor, r.action, r.target ?? '', r.kind);
    await sql(
      `UPDATE audit SET ts_ms=$2, prev_hash=$3, hash=$4, control=$5,
         outcome = COALESCE(outcome, 'ok')
       WHERE id=$1`,
      [r.id, tsMs, prev, hash, mapControl(r.kind, r.action)]);
    prev = hash;
  }
  console.log(`[audit] cadeia: ${missing.rowCount} registro(s) selado(s)`);
}

// ── helpers ──────────────────────────────────────────────────
export async function nextCode(prefix, seqName) {
  const r = await sql(`SELECT nextval('${seqName}') AS n`);
  return `${prefix}-${r.rows[0].n}`;
}

// Insere linhas a partir de objetos camelCase (chaves → colunas snake_case).
export async function insertRows(table, rows, conflictCol = null) {
  if (!rows.length) return;
  const keys = Object.keys(rows[0]);
  const cols = keys.map(snake);
  const ph = rows
    .map((_, i) => '(' + keys.map((_, j) => `$${i * keys.length + j + 1}`).join(',') + ')')
    .join(',');
  const values = rows.flatMap((r) => keys.map((k) => {
    const v = r[k] ?? null;
    // epoch ms → ISO 8601 para colunas timestamptz
    if (typeof v === 'number' && (k === 'ts' || /Ts$/.test(k))) return new Date(v).toISOString();
    return v;
  }));
  const onc = conflictCol ? ` ON CONFLICT (${conflictCol}) DO NOTHING` : '';
  await sql(`INSERT INTO ${table} (${cols.join(',')}) VALUES ${ph}${onc}`, values);
}

/**
 * Registra uma ação na trilha de auditoria.
 *  · enriquecida automaticamente com IP / user-agent / sessão (auditCtx);
 *  · encadeada: hash SHA-256 sobre (hash anterior + campos) — qualquer
 *    adulteração de um registro quebra a verificação dali em diante;
 *  · tag de controle de compliance derivada da ação;
 *  · opts: { before, after, outcome ('ok'|'denied'), control }.
 */
export async function addAudit(actor, action, target, kind = 'system', tenant = null, opts = {}) {
  const ctx = auditCtx.getStore() ?? {};
  const tsMs = Date.now();
  const control = opts.control ?? mapControl(kind, action);
  const last = await sql('SELECT hash FROM audit ORDER BY id DESC LIMIT 1');
  const prevHash = last.rowCount && last.rows[0].hash ? last.rows[0].hash : 'GENESIS';
  const hash = computeHash(prevHash, tsMs, actor, action, target ?? '', kind);
  await sql(
    `INSERT INTO audit
       (ts, ts_ms, actor, action, target, kind, tenant, ip, ua, sid,
        outcome, before, after, prev_hash, hash, control)
     VALUES (to_timestamp($1 / 1000.0), $1, $2, $3, $4, $5, $6, $7, $8, $9,
             $10, $11, $12, $13, $14, $15)`,
    [
      tsMs, actor, action, target, kind, tenant,
      ctx.ip ?? null, ctx.ua ?? null, ctx.sid ?? null,
      opts.outcome ?? 'ok',
      opts.before ? JSON.stringify(opts.before) : null,
      opts.after ? JSON.stringify(opts.after) : null,
      prevHash, hash, control,
    ],
  );
}
