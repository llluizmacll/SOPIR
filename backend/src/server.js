// ─────────────────────────────────────────────────────────────
// SOPIR API — Security Operations & Incident Response Platform
// ─────────────────────────────────────────────────────────────
import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import { waitForDb, migrate, sql, auditCtx } from './db.js';
import { seedIfEmpty, ensureUsers, ensureRoles, ensureOrgsEnvs } from './seed.js';
import { startScheduler } from './connectors/scheduler.js';
import { startEngine } from './playbook-engine.js';
import { authRouter, requireAuth } from './auth.js';
import adminRouter from './admin.js';
import routes from './routes.js';
import { loadCustomPolicies } from './correlator.js';
import { ensureSlaPolicies } from './sla.js';
import { backfillCases } from './casemgmt.js';

const PORT = Number(process.env.PORT) || 3000;

// sequências usadas por códigos manuais (INC-/CASE-)
async function ensureSequences() {
  await sql('CREATE SEQUENCE IF NOT EXISTS seq_incidents START 3000');
  await sql('CREATE SEQUENCE IF NOT EXISTS seq_cases START 200');
}

async function main() {
  console.log('┌─────────────────────────────────────────────┐');
  console.log('│  SOPIR API · Security Ops & IR Platform     │');
  console.log('└─────────────────────────────────────────────┘');

  await waitForDb();
  await migrate();
  await ensureSequences();
  // usuários de demo devem existir sempre (idempotente) — o login depende deles
  await ensureUsers();
  // perfis embutidos na tabela roles (permite edição via Administração)
  await ensureRoles();
  // organizações + ambientes padrão (multi-tenancy)
  await ensureOrgsEnvs();
  // regras de correlação customizadas (Detection & Correlation)
  await loadCustomPolicies().then((n) => console.log(`[correlator] ${n} regra(s) customizada(s) carregada(s)`));
  // políticas de SLA padrão por severidade (multi-tenancy)
  await ensureSlaPolicies();
  // ciclo de vida de cases antigos (fase 9)
  await backfillCases();
  await seedIfEmpty();

  const app = express();
  app.use(cors());
  app.use(express.json({ limit: '10mb' }));
  // contexto de auditoria por request (IP + UA; o sid é anexado no requireAuth)
  app.use((req, res, next) => {
    auditCtx.run({ ip: req.ip ?? null, ua: req.headers['user-agent'] ?? null, sid: null }, next);
  });
  app.use((req, res, next) => {
    const start = Date.now();
    res.on('finish', () => {
      if (!req.path.startsWith('/api/v1/health')) {
        console.log(`[api] ${req.method} ${req.path} → ${res.statusCode} (${Date.now() - start}ms)`);
      }
    });
    next();
  });

  app.use('/api/v1/auth', authRouter);
  app.use('/api/v1/admin', requireAuth, adminRouter);
  app.use('/api/v1', routes);
  app.get('/health', (req, res) => res.json({ ok: true }));
  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => {
    console.error('[api] erro não tratado em', req.method, req.originalUrl, '→', err.stack || err.message);
    // em dev, devolve a causa real para facilitar diagnóstico (não vaza stack em produção)
    const detail = process.env.NODE_ENV === 'production' ? 'erro interno' : err.message;
    res.status(500).json({ error: detail });
  });

  app.listen(PORT, () => {
    console.log(`[api] ouvindo em http://0.0.0.0:${PORT}/api/v1`);
  });

  startEngine();
  startScheduler();
}

main().catch((err) => {
  console.error('[fatal] ' + (err.stack || err.message));
  process.exit(1);
});

// rede de segurança: rejeições não tratadas (timers, webhooks) não podem
// derrubar o processo — registramos e seguimos operando
process.on('unhandledRejection', (reason) => {
  console.error('[unhandledRejection] ' + (reason?.stack || reason?.message || reason));
});
process.on('uncaughtException', (err) => {
  console.error('[uncaughtException] ' + (err.stack || err.message));
});
