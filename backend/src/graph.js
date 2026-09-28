// ─────────────────────────────────────────────────────────────
// SOPIR API · Investigation Graph
// Expansão de grafo: a partir de uma semente (ip, user, host,
// rule, ioc, incident) retorna nós + arestas relacionados.
// Processos são derivados da regra (modelo enriquecido).
// ─────────────────────────────────────────────────────────────
import { sql } from './db.js';

// regra → processo típico observado (enriquecimento para o grafo)
const PROCESS_BY_RULE = {
  '5551': 'explorer.exe', '5549': 'vssadmin.exe', '100220': 'powershell.exe',
  '5716': 'sshd', '5720': 'sshd', '5715': 'sshd', '5901': 'net.exe',
  '100215': 'termsrv.dll', '5503': 'sysmon', '502': 'systemd',
  '28002': 'nmap', '100301': 'vuln-scanner',
};

export function processForRule(ruleId) {
  return PROCESS_BY_RULE[String(ruleId)] ?? null;
}

/**
 * Monta o subgrafo vizinho de uma semente.
 * Retorna { nodes: [{id,type,value,sub}], edges: [{id,source,target,label}] }.
 */
export async function expandGraph(type, value, tenant) {
  const nodes = new Map();
  const edges = new Map();

  const addNode = (t, v, sub = '') => {
    const id = `${t}:${v}`;
    if (!nodes.has(id)) nodes.set(id, { id, type: t, value: v, sub });
    return id;
  };
  const addEdge = (source, target, label) => {
    const id = `${source}|${target}|${label}`;
    if (source !== target && !edges.has(id)) edges.set(id, { id, source, target, label });
  };

  const scoped = tenant && tenant !== 'all';
  const tw = scoped ? ' AND tenant = $2' : '';
  const base = scoped ? [value, tenant] : [value];

  // conecta um evento ao grafo (host, user, ips, regra, processo)
  const linkEvent = (e, focusId) => {
    const hostId = e.host ? addNode('host', e.host, e.os ?? '') : null;
    const userId = e.app_user ? addNode('user', e.app_user) : null;
    const ruleId = addNode('rule', e.rule_id || e.rule, e.rule);
    if (hostId && focusId) addEdge(focusId, hostId, 'observado em');
    if (hostId && userId) addEdge(hostId, userId, 'sessão de');
    if (hostId) addEdge(hostId, ruleId, 'disparou');
    const proc = processForRule(e.rule_id);
    if (proc && hostId) {
      const pid = addNode('process', proc, 'derivado da regra');
      addEdge(hostId, pid, 'executou');
      addEdge(pid, ruleId, 'gerou');
    }
    return { hostId, userId, ruleId };
  };

  if (type === 'ip') {
    const root = addNode('ip', value);
    const r = await sql(
      `SELECT * FROM events WHERE (src_ip = $1 OR dst_ip = $1) AND ts > now() - interval '48 hours'${tw}
       ORDER BY ts DESC LIMIT 40`, base);
    for (const e of r.rows) {
      const { hostId } = linkEvent(e, root);
      const otherIp = e.src_ip === value ? e.dst_ip : e.src_ip;
      if (otherIp && hostId) {
        const oid = addNode('ip', otherIp);
        addEdge(root, oid, e.src_ip === value ? 'falou com' : 'recebeu de');
      }
    }
    // IP como IOC em incidentes
    const ioc = await sql(`SELECT inc_code FROM incident_iocs WHERE ioc = $1`, [value]);
    for (const row of ioc.rows) {
      const iid = addNode('incident', row.inc_code);
      addEdge(root, iid, 'indicador de');
    }
  }

  if (type === 'user') {
    const root = addNode('user', value);
    const r = await sql(
      `SELECT * FROM events WHERE app_user = $1 AND ts > now() - interval '48 hours'${tw}
       ORDER BY ts DESC LIMIT 40`, base);
    for (const e of r.rows) {
      const hostId = e.host ? addNode('host', e.host) : null;
      const ruleId = addNode('rule', e.rule_id || e.rule, e.rule);
      if (hostId) addEdge(root, hostId, 'autenticou em');
      if (hostId) addEdge(hostId, ruleId, 'disparou');
      if (e.src_ip) {
        const ipid = addNode('ip', e.src_ip);
        addEdge(root, ipid, 'origem');
      }
    }
  }

  if (type === 'host') {
    const root = addNode('host', value);
    const r = await sql(
      `SELECT * FROM events WHERE host = $1 AND ts > now() - interval '48 hours'${tw}
       ORDER BY ts DESC LIMIT 50`, base);
    for (const e of r.rows) linkEvent(e, root);
    // incidentes onde o host é o ativo afetado
    const inc = await sql(
      `SELECT code, severity FROM incidents WHERE asset = $1${tw.replace('$2', scoped ? '$2' : '$1')}`,
      scoped ? [value, tenant] : [value]);
    for (const i of inc.rows) {
      const iid = addNode('incident', i.code, i.severity);
      addEdge(root, iid, 'afetado por');
      const iocs = await sql(`SELECT ioc FROM incident_iocs WHERE inc_code = $1`, [i.code]);
      for (const o of iocs.rows) {
        const oid = addNode('ioc', o.ioc);
        addEdge(iid, oid, 'contém IOC');
      }
    }
  }

  if (type === 'rule') {
    const root = addNode('rule', value);
    const r = await sql(
      `SELECT * FROM events WHERE rule_id = $1 AND ts > now() - interval '48 hours'${tw}
       ORDER BY ts DESC LIMIT 40`, base);
    for (const e of r.rows) {
      const hostId = e.host ? addNode('host', e.host) : null;
      if (hostId) addEdge(root, hostId, 'disparada em');
      if (e.app_user && hostId) addEdge(hostId, addNode('user', e.app_user), 'sessão de');
      const proc = processForRule(e.rule_id);
      if (proc && hostId) {
        const pid = addNode('process', proc, 'derivado da regra');
        addEdge(hostId, pid, 'executou');
      }
    }
  }

  if (type === 'ioc') {
    const root = addNode('ioc', value);
    const r = await sql(`SELECT inc_code FROM incident_iocs WHERE ioc = $1`, [value]);
    for (const row of r.rows) {
      const iid = addNode('incident', row.inc_code);
      addEdge(root, iid, 'indicador de');
      const inc = await sql(`SELECT asset FROM incidents WHERE code = $1`, [row.inc_code]);
      for (const i of inc.rows) if (i.asset) addEdge(iid, addNode('host', i.asset), 'afetou');
    }
    const ev = await sql(
      `SELECT * FROM events WHERE (src_ip = $1 OR dst_ip = $1) AND ts > now() - interval '48 hours'${tw}
       ORDER BY ts DESC LIMIT 20`, base);
    for (const e of ev.rows) if (e.host) addEdge(root, addNode('host', e.host), 'comunicou');
  }

  if (type === 'incident') {
    const root = addNode('incident', value);
    const inc = await sql(`SELECT * FROM incidents WHERE code = $1`, [value]);
    const i = inc.rows[0];
    if (i) {
      if (i.asset) addEdge(root, addNode('host', i.asset), 'afetou');
      const iocs = await sql(`SELECT ioc FROM incident_iocs WHERE inc_code = $1`, [value]);
      for (const o of iocs.rows) addEdge(root, addNode('ioc', o.ioc), 'contém IOC');
      const als = await sql(`SELECT alert_code FROM incident_alerts WHERE inc_code = $1`, [value]);
      for (const a of als.rows) {
        const al = await sql(`SELECT * FROM alerts WHERE code = $1`, [a.alert_code]);
        for (const row of al.rows) {
          const rid = addNode('rule', row.rule_id || row.rule, row.rule);
          addEdge(root, rid, 'originado de');
          if (row.host) addEdge(rid, addNode('host', row.host), 'disparada em');
        }
      }
    }
  }

  return { nodes: [...nodes.values()], edges: [...edges.values()] };
}
