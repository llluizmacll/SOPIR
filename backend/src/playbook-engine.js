// ─────────────────────────────────────────────────────────────
// Response Engine — playbooks com aprovação, efeitos reais
// (isolamento de ativos, ações registradas) e auditoria.
// ─────────────────────────────────────────────────────────────
import { sql, nextCode, addAudit } from './db.js';

export const PLAYBOOKS = [
  {
    id: 'PB-RANSOM', name: 'Resposta a Ransomware',
    trigger: 'Regra 5551 — modificação em massa de arquivos', severity: 'critical',
    steps: [
      { id: 's1', label: 'Criar incidente crítico', desc: 'Abre incidente vinculado aos alertas correlacionados' },
      { id: 's2', label: 'Identificar host afetado', desc: 'Resolve agente, usuário e criticidade do ativo' },
      { id: 's3', label: 'Isolar endpoint', desc: 'Network containment via EDR', approval: true, effect: { isolate: 'WS-FIN-014' } },
      { id: 's4', label: 'Consultar IOCs em threat intel', desc: 'VirusTotal, AbuseIPDB e feeds internos' },
      { id: 's5', label: 'Bloquear C2 no firewall', desc: 'Regra deny de saída no FW-MATRIZ', approval: true, effect: { block: '45.155.205.86' } },
      { id: 's6', label: 'Criar tarefas de erradicação', desc: 'Forense, varredura e reimage' },
      { id: 's7', label: 'Notificar responsável', desc: 'Canal #soc-critical + e-mail do owner' },
      { id: 's8', label: 'Gerar relatório preliminar', desc: 'PDF executivo para o cliente' },
    ],
  },
  {
    id: 'PB-BRUTE', name: 'Contenção de Brute Force',
    trigger: 'Regra 5720/100215 — falhas em sequência', severity: 'high',
    steps: [
      { id: 's1', label: 'Identificar origem', desc: 'GeoIP, ASN e histórico da fonte' },
      { id: 's2', label: 'Verificar volume de tentativas', desc: 'Threshold: 10 falhas / 5 min' },
      { id: 's3', label: 'Consultar reputação do IP', desc: 'Feeds de Tor/proxies/abuso' },
      { id: 's4', label: 'Bloquear IP no firewall', desc: 'Lista de bloqueio automática', approval: true, effect: { block: '185.220.101.34' } },
      { id: 's5', label: 'Verificar comprometimento', desc: 'Checa logins bem-sucedidos da origem' },
      { id: 's6', label: 'Criar incidente se necessário', desc: 'Somente se houver login bem-sucedido' },
    ],
  },
  {
    id: 'PB-PHISH', name: 'Triagem de Phishing',
    trigger: 'Reporte de usuário ou detecção de e-mail', severity: 'medium',
    steps: [
      { id: 's1', label: 'Extrair URLs e anexos', desc: 'Parser de cabeçalhos e corpo' },
      { id: 's2', label: 'Detonar anexos em sandbox', desc: 'Análise comportamental 120s' },
      { id: 's3', label: 'Consultar reputação de domínio', desc: 'WHOIS, idade, certificado' },
      { id: 's4', label: 'Remover e-mail das caixas', desc: 'Purge global via API do M365', approval: true },
      { id: 's5', label: 'Notificar usuários afetados', desc: 'Orientação de segurança' },
    ],
  },
  {
    id: 'PB-IOC', name: 'Bloqueio de IOC',
    trigger: 'IOC confirmado em investigação', severity: 'medium',
    steps: [
      { id: 's1', label: 'Validar IOC', desc: 'Tipo, formato e falsos positivos' },
      { id: 's2', label: 'Consultar feeds de ameaça', desc: 'Confiança mínima: 2 fontes' },
      { id: 's3', label: 'Bloquear IP/domínio', desc: 'Firewall + DNS sinkhole', approval: true, effect: { block: 'evil.example-cdn.com' } },
      { id: 's4', label: 'Criar regra de detecção no SIEM', desc: 'Correlação retroativa 30 dias' },
      { id: 's5', label: 'Registrar evidência no case', desc: 'Snapshot da consulta e decisão' },
    ],
  },
];

const findPb = (id) => PLAYBOOKS.find((p) => p.id === id);

export async function startRun(pbId, actor, tenant) {
  const pb = findPb(pbId);
  if (!pb) throw new Error('Playbook não encontrado: ' + pbId);
  const code = await nextCode('RUN', 'seq_runs');
  await sql(
    `INSERT INTO playbook_runs (code, pb_id, pb_name, step, status, ts, tenant, actor)
     VALUES ($1,$2,$3,0,'andamento', now(), $4, $5)`,
    [code, pb.id, pb.name, tenant, actor],
  );
  await addAudit(actor, 'iniciou playbook', pb.name, 'response', tenant);
  return code;
}

async function applyEffects(run, pb, step) {
  if (!step.effect) return;
  const actorName = `Playbook ${pb.id}`;
  if (step.effect.isolate) {
    await sql(`UPDATE assets SET status = 'isolado' WHERE name = $1`, [step.effect.isolate]);
    await sql(`INSERT INTO response_actions (run_code, kind, target) VALUES ($1,'isolamento',$2)`, [run.code, step.effect.isolate]);
    await addAudit(actorName, 'executou isolamento de endpoint', step.effect.isolate, 'response', run.tenant);
  }
  if (step.effect.block) {
    await sql(`INSERT INTO response_actions (run_code, kind, target) VALUES ($1,'bloqueio',$2)`, [run.code, step.effect.block]);
    await addAudit(actorName, 'bloqueou IOC no firewall', step.effect.block, 'response', run.tenant);
  }
}

async function advance(run, pb) {
  const next = run.step + 1;
  if (next >= pb.steps.length) {
    await sql(`UPDATE playbook_runs SET status='concluido', step=$2 WHERE code=$1`, [run.code, next]);
    await addAudit(`Playbook ${pb.id}`, 'concluiu playbook', pb.name, 'response', run.tenant);
    return;
  }
  await sql(`UPDATE playbook_runs SET step=$2, status='andamento' WHERE code=$1`, [run.code, next]);
}

export async function approveRun(code, actor) {
  const r = await sql('SELECT * FROM playbook_runs WHERE code=$1', [code]);
  if (!r.rowCount) throw new Error('Execução não encontrada: ' + code);
  const run = r.rows[0];
  if (run.status !== 'aprovacao') throw new Error('Execução não está aguardando aprovação');
  const pb = findPb(run.pb_id);
  const step = pb.steps[run.step];
  await addAudit(actor, 'aprovou passo do playbook', `${run.code} · ${step.label}`, 'response', run.tenant);
  await applyEffects(run, pb, step);
  await advance(run, pb);
}

export async function rejectRun(code, actor) {
  const r = await sql('SELECT * FROM playbook_runs WHERE code=$1', [code]);
  if (!r.rowCount) throw new Error('Execução não encontrada: ' + code);
  const run = r.rows[0];
  await sql(`UPDATE playbook_runs SET status='rejeitado' WHERE code=$1`, [code]);
  await addAudit(actor, 'rejeitou execução de playbook', run.pb_name, 'response', run.tenant);
}

// Motor: avança execuções em andamento a cada ~900ms
export function startEngine() {
  setInterval(async () => {
    try {
      const r = await sql(`SELECT * FROM playbook_runs WHERE status='andamento' ORDER BY ts`);
      for (const run of r.rows) {
        const pb = findPb(run.pb_id);
        const step = pb?.steps[run.step];
        if (!step) {
          await sql(`UPDATE playbook_runs SET status='concluido' WHERE code=$1`, [run.code]);
          continue;
        }
        if (step.approval) {
          await sql(`UPDATE playbook_runs SET status='aprovacao' WHERE code=$1`, [run.code]);
          await addAudit(`Playbook ${pb.id}`, 'solicitou aprovação para passo', step.label, 'response', run.tenant);
          continue;
        }
        await applyEffects(run, pb, step);
        await advance(run, pb);
      }
    } catch (err) {
      console.error('[engine] ' + err.message);
    }
  }, 900);
}
