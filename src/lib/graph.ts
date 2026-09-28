// ─────────────────────────────────────────────────────────────
// Investigation Graph · tipos + construtor local (modo demo)
// Espelha a lógica de backend/src/graph.js usando o estado local.
// ─────────────────────────────────────────────────────────────
import type { Alert, Asset, Ev, Incident } from '../data/mock';

export type GraphNodeType = 'ip' | 'user' | 'host' | 'process' | 'rule' | 'ioc' | 'incident';

export interface GNode {
  id: string; type: GraphNodeType; value: string; sub?: string;
  x: number; y: number; vx: number; vy: number;
  fx?: number | null; fy?: number | null;
}
export interface GEdge { id: string; source: string; target: string; label: string }
export interface GraphData { nodes: GNode[]; edges: GEdge[] }

export const NODE_META: Record<GraphNodeType, { label: string; color: string; r: number }> = {
  ip:       { label: 'IP',        color: '#56c4ff', r: 16 },
  user:     { label: 'Usuário',   color: '#ffc53d', r: 15 },
  host:     { label: 'Endpoint',  color: '#2fd6a5', r: 17 },
  process:  { label: 'Processo',  color: '#ff9142', r: 13 },
  rule:     { label: 'Regra',     color: '#8fa3c8', r: 13 },
  ioc:      { label: 'IOC',       color: '#ff4d5e', r: 14 },
  incident: { label: 'Incidente', color: '#ff9142', r: 16 },
};

const PROCESS_BY_RULE: Record<string, string> = {
  '5551': 'explorer.exe', '5549': 'vssadmin.exe', '100220': 'powershell.exe',
  '5716': 'sshd', '5720': 'sshd', '5715': 'sshd', '5901': 'net.exe',
  '100215': 'termsrv.dll', '5503': 'sysmon', '502': 'systemd',
  '28002': 'nmap', '100301': 'vuln-scanner',
};
export const processForRule = (ruleId: string): string | null => PROCESS_BY_RULE[String(ruleId)] ?? null;

export interface GraphCtx { events: Ev[]; alerts: Alert[]; incidents: Incident[]; assets: Asset[] }

const now = () => Date.now();
const WINDOW = 48 * 3_600_000;

/** Expansão local (modo demonstração) — devolve nós/arestas vizinhos da semente. */
export function expandLocal(type: GraphNodeType, value: string, ctx: GraphCtx): GraphData {
  const nodes = new Map<string, Omit<GNode, 'x' | 'y' | 'vx' | 'vy'>>();
  const edges = new Map<string, GEdge>();
  const addNode = (t: GraphNodeType, v: string, sub = '') => {
    const id = `${t}:${v}`;
    if (!nodes.has(id)) nodes.set(id, { id, type: t, value: v, sub });
    return id;
  };
  const addEdge = (s: string, t: string, label: string) => {
    const id = `${s}|${t}|${label}`;
    if (s !== t && !edges.has(id)) edges.set(id, { id, source: s, target: t, label });
  };
  const recent = ctx.events.filter(e => now() - e.ts < WINDOW);

  const linkEvent = (e: Ev, focusId: string) => {
    const hostId = e.host && e.host !== '—' ? addNode('host', e.host) : null;
    const userId = e.user && e.user !== '—' ? addNode('user', e.user) : null;
    const ruleId = addNode('rule', e.ruleId || e.rule, e.rule);
    if (hostId && focusId) addEdge(focusId, hostId, 'observado em');
    if (hostId && userId) addEdge(hostId, userId, 'sessão de');
    if (hostId) addEdge(hostId, ruleId, 'disparou');
    const proc = processForRule(e.ruleId);
    if (proc && hostId) {
      const pid = addNode('process', proc, 'derivado da regra');
      addEdge(hostId, pid, 'executou');
      addEdge(pid, ruleId, 'gerou');
    }
    return { hostId, userId, ruleId };
  };

  if (type === 'ip') {
    const root = addNode('ip', value);
    for (const e of recent.filter(e => e.srcIp === value || e.dstIp === value).slice(0, 40)) {
      const { hostId } = linkEvent(e, root);
      const other = e.srcIp === value ? e.dstIp : e.srcIp;
      if (other && other !== '—' && hostId) addEdge(root, addNode('ip', other), e.srcIp === value ? 'falou com' : 'recebeu de');
    }
    for (const i of ctx.incidents) if (i.iocs.includes(value)) addEdge(root, addNode('incident', i.id, i.severity), 'indicador de');
  }

  if (type === 'user') {
    const root = addNode('user', value);
    for (const e of recent.filter(e => e.user === value).slice(0, 40)) {
      const hostId = e.host && e.host !== '—' ? addNode('host', e.host) : null;
      const ruleId = addNode('rule', e.ruleId || e.rule, e.rule);
      if (hostId) addEdge(root, hostId, 'autenticou em');
      if (hostId) addEdge(hostId, ruleId, 'disparou');
      if (e.srcIp && e.srcIp !== '—') addEdge(root, addNode('ip', e.srcIp), 'origem');
    }
  }

  if (type === 'host') {
    const root = addNode('host', value);
    for (const e of recent.filter(e => e.host === value).slice(0, 50)) linkEvent(e, root);
    for (const i of ctx.incidents) if (i.asset === value) {
      const iid = addNode('incident', i.id, i.severity);
      addEdge(root, iid, 'afetado por');
      for (const o of i.iocs) addEdge(iid, addNode('ioc', o), 'contém IOC');
    }
  }

  if (type === 'rule') {
    const root = addNode('rule', value);
    for (const e of recent.filter(e => (e.ruleId || e.rule) === value).slice(0, 40)) {
      const hostId = e.host && e.host !== '—' ? addNode('host', e.host) : null;
      if (hostId) addEdge(root, hostId, 'disparada em');
      if (e.user && e.user !== '—' && hostId) addEdge(hostId, addNode('user', e.user), 'sessão de');
      const proc = processForRule(e.ruleId);
      if (proc && hostId) addEdge(hostId, addNode('process', proc, 'derivado da regra'), 'executou');
    }
  }

  if (type === 'ioc') {
    const root = addNode('ioc', value);
    for (const i of ctx.incidents) if (i.iocs.includes(value)) {
      const iid = addNode('incident', i.id, i.severity);
      addEdge(root, iid, 'indicador de');
      if (i.asset) addEdge(iid, addNode('host', i.asset), 'afetou');
    }
    for (const e of recent.filter(e => e.srcIp === value || e.dstIp === value).slice(0, 20)) {
      if (e.host && e.host !== '—') addEdge(root, addNode('host', e.host), 'comunicou');
    }
  }

  if (type === 'incident') {
    const root = addNode('incident', value);
    const i = ctx.incidents.find(x => x.id === value);
    if (i) {
      if (i.asset) addEdge(root, addNode('host', i.asset), 'afetou');
      for (const o of i.iocs) addEdge(root, addNode('ioc', o), 'contém IOC');
      for (const aId of i.alertIds) {
        const a = ctx.alerts.find(x => x.id === aId);
        if (a) {
          const rid = addNode('rule', a.ruleId || a.rule, a.rule);
          addEdge(root, rid, 'originado de');
          if (a.host && a.host !== '—') addEdge(rid, addNode('host', a.host), 'disparada em');
        }
      }
    }
  }

  return {
    nodes: [...nodes.values()].map(n => ({ ...n, x: 0, y: 0, vx: 0, vy: 0 })),
    edges: [...edges.values()],
  };
}

/** Sugestões de sementes a partir do estado (para o campo de busca). */
export function seedSuggestions(ctx: GraphCtx): { type: GraphNodeType; value: string }[] {
  const out: { type: GraphNodeType; value: string }[] = [];
  const seen = new Set<string>();
  const push = (type: GraphNodeType, value: string) => {
    if (!value || value === '—' || seen.has(type + value)) return;
    seen.add(type + value); out.push({ type, value });
  };
  for (const i of ctx.incidents.slice(0, 4)) { push('incident', i.id); for (const o of i.iocs.slice(0, 2)) push('ioc', o); }
  for (const a of ctx.alerts.slice(0, 8)) { if (a.srcIp && !a.srcIp.startsWith('10.')) push('ip', a.srcIp); if (a.host && a.host !== '—') push('host', a.host); }
  for (const e of ctx.events.slice(0, 12)) { if (e.user && e.user !== '—') push('user', e.user); }
  return out.slice(0, 12);
}
