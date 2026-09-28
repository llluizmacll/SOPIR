// ─────────────────────────────────────────────────────────────
// Catálogo de permissões (espelha backend/src/auth.js)
// + helpers de RBAC para o frontend
// ─────────────────────────────────────────────────────────────

export interface PermModule { module: string; icon: string; perms: { id: string; label: string }[] }

export const PERM_CATALOG: PermModule[] = [
  { module: 'Alertas', icon: 'bell', perms: [{ id: 'alerts.read', label: 'Visualizar alertas' }, { id: 'alerts.update', label: 'Triagem & atualização' }] },
  { module: 'Incidentes', icon: 'flame', perms: [{ id: 'incidents.read', label: 'Visualizar incidentes' }, { id: 'incidents.update', label: 'Gerir ciclo de vida' }] },
  { module: 'Cases', icon: 'folder', perms: [{ id: 'cases.read', label: 'Visualizar cases' }, { id: 'cases.update', label: 'Gerir cases' }] },
  { module: 'Ativos', icon: 'server', perms: [{ id: 'assets.read', label: 'Visualizar inventário' }, { id: 'assets.update', label: 'Isolar / liberar ativos' }] },
  { module: 'Vulnerabilidades', icon: 'bug', perms: [{ id: 'vulns.read', label: 'Visualizar findings' }, { id: 'vulns.update', label: 'Remediação & aceite de risco' }] },
  { module: 'Correlação', icon: 'crosshair', perms: [{ id: 'correlations.read', label: 'Ver políticas' }, { id: 'correlations.update', label: 'Ativar / desativar políticas' }] },
  { module: 'Investigação', icon: 'network', perms: [{ id: 'investigations.read', label: 'Montar grafo' }, { id: 'investigations.update', label: 'Salvar investigações' }] },
  { module: 'Resposta (SOAR)', icon: 'zap', perms: [{ id: 'response.execute', label: 'Executar playbooks' }, { id: 'response.approve', label: 'Aprovar ações' }] },
  { module: 'Remediação', icon: 'refresh', perms: [{ id: 'remediation.execute', label: 'Executar remediações' }] },
  { module: 'Relatórios', icon: 'file', perms: [{ id: 'reports.export', label: 'Exportar relatórios' }] },
  { module: 'Auditoria', icon: 'history', perms: [{ id: 'audit.read', label: 'Ler trilha de auditoria' }] },
  { module: 'Portal do Cliente', icon: 'globe', perms: [{ id: 'portal.read', label: 'Visão executiva do cliente' }] },
  { module: 'Integrações', icon: 'layers', perms: [{ id: 'connectors.read', label: 'Ver connectors & saúde' }, { id: 'connectors.update', label: 'Configurar connectors por cliente' }] },
  { module: 'SLA & Performance', icon: 'clock', perms: [{ id: 'sla.read', label: 'Ver políticas & conformidade SLA' }, { id: 'sla.update', label: 'Editar políticas de SLA' }] },
  { module: 'Identidade', icon: 'key', perms: [{ id: 'identity.read', label: 'Ver provedores SSO & políticas' }, { id: 'identity.manage', label: 'Gerir SSO, MFA e políticas' }] },
  { module: 'Administração', icon: 'shield', perms: [{ id: 'admin.users', label: 'Gerir usuários' }, { id: 'admin.roles', label: 'Gerir perfis de acesso' }, { id: 'admin.tenants', label: 'Gerir clientes (tenants)' }] },
];

export const ALL_PERMS = PERM_CATALOG.flatMap(m => m.perms.map(p => p.id));

export function hasPerm(perms: string[], perm: string): boolean {
  return perms.some(p => p === '*' || p === perm || (p.endsWith('.*') && perm.startsWith(p.slice(0, -1))));
}

/**
 * Rotas de navegação liberadas para uma lista de permissões
 * (usado por perfis customizados no RBAC).
 */
export function routesForPerms(perms: string[]): string[] {
  const has = (p: string) => hasPerm(perms, p);
  const routes: string[] = [];
  const any = perms.length > 0;
  if (any) routes.push('dashboard');
  if (has('alerts.read')) routes.push('explorer', 'alerts');
  if (has('correlations.read')) routes.push('correlation', 'ingestion');
  if (has('investigations.read')) routes.push('investigation');
  if (has('incidents.read')) routes.push('incidents');
  if (has('cases.read')) routes.push('cases');
  if (has('alerts.read') || has('response.execute') || has('response.approve')) routes.push('playbooks');
  if (has('vulns.read') || has('vulns.update')) routes.push('vulns');
  if (has('assets.read')) routes.push('assets');
  if (has('reports.export')) routes.push('reports');
  if (has('audit.read')) routes.push('audit');
  if (has('portal.read')) routes.push('portal');
  if (has('connectors.read')) routes.push('connectors');
  if (has('sla.read')) routes.push('sla');
  if (has('admin.users') || has('admin.roles') || has('admin.tenants')) routes.push('admin');
  return routes;
}
