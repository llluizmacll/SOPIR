// ─────────────────────────────────────────────────────────────
// SOPIR API · baseline inicial
// Inserido apenas quando o banco está vazio.
// ─────────────────────────────────────────────────────────────
import bcrypt from 'bcryptjs';
import { sql, insertRows, addAudit, nextCode } from './db.js';

// usuários padrão — senha única: "sopir"
const DEMO_USERS = [
  { username: 'luiz.almeida', name: 'Luiz Almeida', role: 'Admin', tenant: null },
  { username: 'ana.ribeiro', name: 'Ana Ribeiro', role: 'SOC Manager', tenant: null },
  { username: 'carlos.mendes', name: 'Carlos Mendes', role: 'SOC Analyst', tenant: null },
  { username: 'marina.sousa', name: 'Marina Sousa', role: 'Security Engineer', tenant: null },
];

// nenhum tenant de demonstração é semeado — uma instalação nova começa vazia;
// o primeiro cliente real entra pelo fluxo de "Onboarding de cliente" (Admin → Organizações)
const TENANTS = [];

const ASSETS = [];

export async function ensureUsers() {
  const count = await sql('SELECT count(*)::int AS n FROM users');
  if (count.rows[0].n > 0) return;
  await insertRows(
    'users',
    DEMO_USERS.map((u) => ({ ...u, passHash: bcrypt.hashSync('sopir', 10) })),
    'username',
  );
  await addAudit('sistema', 'criou usuários padrão (senha: sopir)', 'users', 'system', null);
  console.log('[seed] usuários padrão criados (senha: sopir)');
}

export async function ensureRoles() {
  const { ROLE_PERMS } = await import('./auth.js');
  const DESC = {
    Admin: 'Acesso total à plataforma, incluindo administração.',
    'SOC Manager': 'Gestão completa da operação do SOC.',
    'SOC Analyst': 'Triagem de alertas, incidentes e cases.',
    'Security Engineer': 'Vulnerabilidades, remediação e ativos.',
    Customer: 'Portal do cliente — somente o próprio ambiente.',
  };
  for (const [name, perms] of Object.entries(ROLE_PERMS)) {
    const cur = await sql('SELECT permissions FROM roles WHERE name = $1', [name]);
    if (!cur.rowCount) {
      await sql(
        `INSERT INTO roles (name, display, description, permissions, builtin)
         VALUES ($1, $1, $2, $3, true)`,
        [name, DESC[name] ?? '', JSON.stringify(perms)],
      );
    } else {
      const merged = Array.from(new Set([...(cur.rows[0].permissions ?? []), ...perms]));
      await sql('UPDATE roles SET permissions = $2 WHERE name = $1', [name, JSON.stringify(merged)]);
    }
  }
}

export async function ensureOrgsEnvs() {
  // nenhuma organização de demonstração é semeada — cria-se pela tela
  // de Organizações quando o primeiro cliente real for cadastrado

  const tenants = await sql('SELECT id FROM tenants');
  for (const t of tenants.rows) {
    const has = await sql('SELECT 1 FROM environments WHERE tenant = $1 LIMIT 1', [t.id]);
    if (has.rowCount) continue;
    const prod = await nextCode('ENV', 'seq_envs');
    await sql('INSERT INTO environments (code, tenant, name, kind) VALUES ($1,$2,$3,$4)', [prod, t.id, 'Produção', 'producao']);
  }
  console.log('[seed] ambientes garantidos para todos os tenants');
}

export async function seedIfEmpty() {
  const count = await sql('SELECT count(*)::int AS n FROM events');
  if (count.rows[0].n > 0) {
    console.log('[seed] banco já possui dados — pulando baseline');
    return;
  }
  console.log('[seed] banco vazio — inserindo baseline inicial…');

  await insertRows('tenants', TENANTS, 'id');

  if (ASSETS.length > 0) {
    await insertRows(
      'assets',
      ASSETS.map(([code, tenant, name, type, ip, os, crit, status, owner]) => ({
        code, tenant, name, type, ip, os, crit, status, owner,
      })),
      'code',
    );
  }

  console.log('[seed] baseline limpa inserida (sem dados de demonstração)');
}
