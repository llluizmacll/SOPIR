import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { AdminRole, AdminTenant, AdminUser, IdentitySettings, IdpProvider, Org, IsolationRow } from '../lib/api';
import { api as srv } from '../lib/api';
import { PERM_CATALOG, hasPerm } from '../data/perms';
import { permsFor, timeAgo, useStore } from '../lib/store';
import { Avatar, EmptyState, Field, Icon, Modal, Pill } from '../components/ui';
import type { IconName } from '../components/icons';

const BUILTIN_ROLES = ['Admin', 'SOC Manager', 'SOC Analyst', 'Security Engineer', 'Customer'];

type Tab = 'users' | 'roles' | 'tenants' | 'orgs' | 'identity';

const DEFAULT_IDENTITY: IdentitySettings = {
  session_ttl_hours: 12, min_password_length: 8, mfa_required_roles: [],
  sso_enabled: true, sso_auto_provision: true,
};

const ROLE_COLORS: Record<string, string> = {
  Admin: '#ff4d5e', 'SOC Manager': '#ff9142', 'SOC Analyst': '#56c4ff',
  'Security Engineer': '#ffc53d', Customer: '#2fd6a5',
};
const roleColor = (r: string) => ROLE_COLORS[r] ?? '#5aa2ff';

// ── dados locais de fallback ─────────────────────
const LOCAL_USERS: AdminUser[] = [
  { username: 'luiz.almeida', name: 'Luiz Almeida', role: 'Admin', tenant: null, tenantName: null, active: true, lastLogin: Date.now() - 3_600_000 },
  { username: 'ana.ribeiro', name: 'Ana Ribeiro', role: 'SOC Manager', tenant: null, tenantName: null, active: true, lastLogin: Date.now() - 7_200_000 },
  { username: 'carlos.mendes', name: 'Carlos Mendes', role: 'SOC Analyst', tenant: 'vetra', tenantName: 'Grupo Vetra S.A.', active: true, lastLogin: Date.now() - 86_400_000 },
  { username: 'marina.sousa', name: 'Marina Sousa', role: 'Security Engineer', tenant: null, tenantName: null, active: true, lastLogin: null },
  { username: 'cliente.vetra', name: 'Portal — Grupo Vetra', role: 'Customer', tenant: 'vetra', tenantName: 'Grupo Vetra S.A.', active: true, lastLogin: Date.now() - 2 * 86_400_000 },
];

export default function Admin() {
  const { s, backend, toast, me, syncTenants } = useStore();
  const online = backend === 'online';
  const myPerms = permsFor(s.role);

  const canUsers = hasPerm(myPerms, 'admin.users');
  const canRoles = hasPerm(myPerms, 'admin.roles');
  const canTenants = hasPerm(myPerms, 'admin.tenants');
  const canIdentity = hasPerm(myPerms, 'identity.manage') || hasPerm(myPerms, 'identity.read');
  const canIdentityManage = hasPerm(myPerms, 'identity.manage');

  const [tab, setTab] = useState<Tab>(canUsers ? 'users' : canRoles ? 'roles' : canTenants ? 'tenants' : 'identity');
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [roles, setRoles] = useState<AdminRole[]>([]);
  const [tenants, setTenants] = useState<AdminTenant[]>([]);
  const [identity, setIdentity] = useState<IdentitySettings>(DEFAULT_IDENTITY);
  const [providers, setProviders] = useState<IdpProvider[]>([]);
  const [orgs, setOrgs] = useState<Org[]>([]);
  const [isolation, setIsolation] = useState<IsolationRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [q, setQ] = useState('');
  const [providerModal, setProviderModal] = useState<IdpProvider | 'new' | null>(null);
  const [onboardOpen, setOnboardOpen] = useState(false);
  const [envTenant, setEnvTenant] = useState<AdminTenant | null>(null);
  const [orgView, setOrgView] = useState<'tree' | 'matrix'>('tree');

  // modais
  const [userModal, setUserModal] = useState<AdminUser | 'new' | null>(null);
  const [roleModal, setRoleModal] = useState<AdminRole | 'new' | null>(null);
  const [tenantModal, setTenantModal] = useState<AdminTenant | 'new' | null>(null);
  const [pwUser, setPwUser] = useState<AdminUser | null>(null);
  const [confirm, setConfirm] = useState<{ title: string; msg: string; danger?: boolean; action: () => void } | null>(null);

  const load = useCallback(async () => {
    if (online) {
      setLoading(true);
      const [u, r, t, iset, prov, og, iso] = await Promise.all([
        canUsers ? srv.users() : Promise.resolve(null),
        canRoles ? srv.roles() : Promise.resolve(null),
        canTenants ? srv.tenants() : Promise.resolve(null),
        canIdentity ? srv.identitySettings() : Promise.resolve(null),
        canIdentity ? srv.idpProviders() : Promise.resolve(null),
        canTenants ? srv.orgs() : Promise.resolve(null),
        canTenants ? srv.isolationMatrix() : Promise.resolve(null),
      ]);
      if (u) setUsers(u);
      if (r) setRoles(r);
      if (t) setTenants(t);
      if (iset) setIdentity(iset);
      if (prov) setProviders(prov);
      if (og) setOrgs(og);
      if (iso) setIsolation(iso);
      setLoading(false);
    } else {
      // fallback local quando a API estiver indisponível
      setLoading(true);
      setUsers(LOCAL_USERS);
      setRoles(BUILTIN_ROLES.map(name => ({
        name, display: name, description: '', builtin: true,
        permissions: permsFor(name),
        users: LOCAL_USERS.filter(u => u.role === name).length,
      })));
      setTenants([
        { id: 'vetra', name: 'Grupo Vetra S.A.', short: 'VET', contact: 'soc@vetra.com.br', orgId: 'ORG-1', orgName: 'Vetra Participações', brandColor: '#2fd6a5', tagline: null, quotas: { maxUsers: null, maxAssets: null, maxConnectors: null }, created: null, assets: 10, alerts: 12, incidents: 5, users: 2, vulns: 7, connectors: 1, environments: [{ id: 'ENV-1', name: 'Produção', kind: 'producao' }, { id: 'ENV-2', name: 'Laboratório', kind: 'laboratorio' }] },
        { id: 'atlantico', name: 'Banco Atlântico', short: 'ATL', contact: 'seguranca@atlantico.com.br', orgId: null, orgName: null, brandColor: null, tagline: null, quotas: { maxUsers: null, maxAssets: null, maxConnectors: null }, created: null, assets: 4, alerts: 4, incidents: 1, users: 0, vulns: 4, connectors: 0, environments: [{ id: 'ENV-3', name: 'Produção', kind: 'producao' }] },
        { id: 'medcore', name: 'Hospital Medcore', short: 'MED', contact: 'ti@medcore.org', orgId: null, orgName: null, brandColor: null, tagline: null, quotas: { maxUsers: null, maxAssets: null, maxConnectors: null }, created: null, assets: 3, alerts: 3, incidents: 0, users: 0, vulns: 2, connectors: 0, environments: [{ id: 'ENV-4', name: 'Produção', kind: 'producao' }] },
      ]);
      setOrgs([
        { id: 'ORG-1', name: 'Vetra Participações', short: 'VPR', tenants: [{ id: 'vetra', name: 'Grupo Vetra S.A.', short: 'VET' }] },
      ]);
      setIsolation([
        { tenant: 'vetra', tenantName: 'Grupo Vetra S.A.', cells: [
          { table: 'events', label: 'Eventos', count: 1240 }, { table: 'alerts', label: 'Alertas', count: 12 }, { table: 'incidents', label: 'Incidentes', count: 5 },
          { table: 'cases', label: 'Cases', count: 3 }, { table: 'vulnerabilities', label: 'Vulnerabilidades', count: 7 }, { table: 'assets', label: 'Ativos', count: 10 },
          { table: 'users', label: 'Usuários', count: 2 }, { table: 'connector_configs', label: 'Connectors', count: 1 }, { table: 'environments', label: 'Ambientes', count: 2 },
        ] },
        { tenant: 'atlantico', tenantName: 'Banco Atlântico', cells: [
          { table: 'events', label: 'Eventos', count: 580 }, { table: 'alerts', label: 'Alertas', count: 4 }, { table: 'incidents', label: 'Incidentes', count: 1 },
          { table: 'cases', label: 'Cases', count: 1 }, { table: 'vulnerabilities', label: 'Vulnerabilidades', count: 4 }, { table: 'assets', label: 'Ativos', count: 4 },
          { table: 'users', label: 'Usuários', count: 0 }, { table: 'connector_configs', label: 'Connectors', count: 0 }, { table: 'environments', label: 'Ambientes', count: 1 },
        ] },
        { tenant: 'medcore', tenantName: 'Hospital Medcore', cells: [
          { table: 'events', label: 'Eventos', count: 210 }, { table: 'alerts', label: 'Alertas', count: 3 }, { table: 'incidents', label: 'Incidentes', count: 0 },
          { table: 'cases', label: 'Cases', count: 0 }, { table: 'vulnerabilities', label: 'Vulnerabilidades', count: 2 }, { table: 'assets', label: 'Ativos', count: 3 },
          { table: 'users', label: 'Usuários', count: 0 }, { table: 'connector_configs', label: 'Connectors', count: 0 }, { table: 'environments', label: 'Ambientes', count: 1 },
        ] },
      ]);
      setLoading(false);
    }
  }, [online, canUsers, canRoles, canTenants, canIdentity]);

  useEffect(() => { void load(); }, [load]);

  // reflete a lista de clientes no seletor do topo (store global),
  // em qualquer mudança — criação, edição ou remoção, demo ou online.
  useEffect(() => {
    syncTenants(tenants.map(t => ({ id: t.id, name: t.name, short: t.short })));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tenants]);

  const filteredUsers = useMemo(() => {
    const query = q.trim().toLowerCase();
    if (!query) return users;
    return users.filter(u => [u.name, u.username, u.role, u.tenantName ?? ''].some(f => f.toLowerCase().includes(query)));
  }, [users, q]);

  if (!canUsers && !canRoles && !canTenants && !canIdentity) {
    return <EmptyState icon="lock" title="Acesso restrito" sub="Seu perfil não possui permissões de administração (admin.*, identity.read)." />;
  }

  const tabs: { id: Tab; label: string; icon: IconName; count: number; show: boolean }[] = [
    { id: 'users', label: 'Usuários', icon: 'users', count: users.length, show: canUsers },
    { id: 'roles', label: 'Perfis de Acesso', icon: 'shield', count: roles.length, show: canRoles },
    { id: 'tenants', label: 'Clientes', icon: 'globe', count: tenants.length, show: canTenants },
    { id: 'orgs', label: 'Multi-Tenancy', icon: 'layers', count: orgs.length, show: canTenants },
    { id: 'identity', label: 'Identidade & SSO', icon: 'key', count: providers.length, show: canIdentity },
  ];

  return (
    <div className="flex h-full flex-col">
      {/* cabeçalho + abas */}
      <div className="a-up shrink-0 border-b border-line bg-panel/40 px-5 py-3.5">
        <div className="flex flex-wrap items-center gap-3">
          <div className="flex items-center gap-1 rounded-lg border border-line bg-panel p-1">
            {tabs.filter(t => t.show).map(t => (
              <button key={t.id} onClick={() => setTab(t.id)}
                className={`flex items-center gap-2 rounded-md px-3.5 py-1.5 text-[12.5px] font-medium transition-all ${tab === t.id ? 'bg-teal/15 text-teal border border-teal/40' : 'text-sub hover:text-ink border border-transparent'}`}>
                <Icon name={t.icon} size={14} />
                {t.label}
                <span className="rounded bg-raise px-1.5 py-0.5 font-mono text-[10px]">{t.count}</span>
              </button>
            ))}
          </div>
          {!online && (
            <span className="flex items-center gap-1.5 rounded-md border border-high/40 bg-high/10 px-2.5 py-1 text-[10.5px] text-high">
              <Icon name="alertTriangle" size={11} /> API indisponível — alterações não persistem
            </span>
          )}
          {tab === 'users' && (
            <div className="relative ml-auto w-[240px]">
              <span className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-faint"><Icon name="search" size={13} /></span>
              <input className="input w-full pl-8" placeholder="Buscar usuário…" value={q} onChange={e => setQ(e.target.value)} />
            </div>
          )}
          {tab === 'users' && canUsers && (
            <button className="btn btn-primary btn-xs" onClick={() => setUserModal('new')}><Icon name="plus" size={12} /> Novo usuário</button>
          )}
          {tab === 'roles' && canRoles && (
            <button className="btn btn-primary btn-xs ml-auto" onClick={() => setRoleModal('new')}><Icon name="plus" size={12} /> Novo perfil</button>
          )}
          {tab === 'tenants' && canTenants && (
            <button className="btn btn-primary btn-xs ml-auto" onClick={() => setTenantModal('new')}><Icon name="plus" size={12} /> Novo cliente</button>
          )}
        </div>
      </div>

      <div className="min-h-0 flex-1 overflow-y-auto p-5">
        {loading ? (
          <div className="flex h-full items-center justify-center text-[12px] text-faint">carregando…</div>
        ) : (
          <>
            {tab === 'users' && <UsersTab users={filteredUsers} total={users.length} me={me} roles={roles} tenants={tenants}
              onClearSearch={() => setQ('')}
              onEdit={u => setUserModal(u)} onPassword={u => setPwUser(u)}
              onToggle={u => setConfirm({
                title: u.active ? 'Suspender usuário' : 'Reativar usuário',
                msg: u.active
                  ? `${u.name} (${u.username}) não poderá acessar a plataforma até ser reativado.`
                  : `${u.name} (${u.username}) voltará a ter acesso conforme seu perfil.`,
                danger: u.active,
                action: async () => {
                  if (online) await srv.updateUser(u.username, { active: !u.active });
                  else setUsers(p => p.map(x => x.username === u.username ? { ...x, active: !x.active } : x));
                  toast('ok', `Usuário ${u.active ? 'suspenso' : 'reativado'}`);
                  void load();
                },
              })}
              onDelete={u => setConfirm({
                title: 'Excluir usuário', danger: true,
                msg: `Remover permanentemente ${u.name} (${u.username})? Essa ação não pode ser desfeita.`,
                action: async () => {
                  if (online) await srv.deleteUser(u.username);
                  else setUsers(p => p.filter(x => x.username !== u.username));
                  toast('ok', 'Usuário excluído');
                  void load();
                },
              })}
              onResetMfa={u => setConfirm({
                title: 'Resetar MFA', danger: true,
                msg: `Desativar a autenticação de dois fatores de ${u.name} (${u.username})? O usuário poderá reativar pela própria conta.`,
                action: async () => {
                  if (online) await srv.adminResetMfa(u.username);
                  else setUsers(p => p.map(x => x.username === u.username ? { ...x, mfaEnabled: false } : x));
                  toast('ok', 'MFA desativado para o usuário');
                  void load();
                },
              })} />}

            {tab === 'roles' && <RolesTab roles={roles}
              onEdit={r => setRoleModal(r)}
              onDelete={r => setConfirm({
                title: 'Excluir perfil', danger: true,
                msg: `Remover o perfil "${r.display}"? Somente perfis sem usuários podem ser excluídos.`,
                action: async () => {
                  const res = online ? await srv.deleteRole(r.name) : null;
                  if (online && !res) { toast('err', 'Perfil em uso ou embutido — não pode ser excluído'); return; }
                  setRoles(p => p.filter(x => x.name !== r.name));
                  toast('ok', 'Perfil excluído');
                  void load();
                },
              })} />}

            {tab === 'tenants' && <TenantsTab tenants={tenants}
              onEdit={t => setTenantModal(t)}
              onToggleStatus={(t, active) => setConfirm({
                title: active ? 'Ativar cliente' : 'Desativar cliente',
                msg: active 
                  ? `Deseja reativar o tenant "${t.name}"?` 
                  : `Deseja desativar o tenant "${t.name}"? O processamento de novos dados será interrompido.`,
                action: async () => {
                  if (online) {
                    const res = await srv.patchTenantStatus(t.id, active);
                    if (!res?.ok) { toast('err', res?.error ?? 'Falha ao alterar status'); return; }
                  }
                  setTenants(p => p.map(x => x.id === t.id ? { ...x, active } : x));
                  toast('ok', active ? 'Cliente ativado' : 'Cliente desativado');
                  void load();
                },
              })}
              onDelete={t => setConfirm({
                title: 'Excluir permanentemente cliente', danger: true,
                msg: `ATENÇÃO: Esta ação irá EXCLUIR PERMANENTEMENTE todos os dados do tenant "${t.name}" incluindo:\n\n• Alertas\n• Incidentes\n• Casos\n• Eventos\n• Vulnerabilidades\n• Ativos\n• Usuários\n• Conectores\n• Ambientes\n\nEsta operação NÃO PODE SER DESFEITA. Deseja continuar?`,
                action: async () => {
                  if (online) {
                    const res = await srv.deleteTenant(t.id);
                    if (!res?.ok) { toast('err', res?.error ?? 'Falha ao excluir tenant'); return; }
                  }
                  setTenants(p => p.filter(x => x.id !== t.id));
                  toast('ok', 'Cliente e todos os seus dados foram excluídos permanentemente');
                  void load();
                },
              })} />}

            {tab === 'orgs' && canTenants && (
              <MultiTenancyTab orgs={orgs} tenants={tenants} isolation={isolation} view={orgView} onView={setOrgView}
                onOnboard={() => setOnboardOpen(true)}
                onEnvs={t => setEnvTenant(t)}
                onCreateOrg={async name => {
                  if (online) { const res = await srv.createOrg({ name }); if (!res?.ok) { toast('err', res?.error ?? 'Falha'); return; } }
                  else setOrgs(p => [...p, { id: 'ORG-' + Date.now(), name, short: name.slice(0, 3).toUpperCase(), tenants: [] }]);
                  toast('ok', 'Organização criada');
                  void load();
                }}
                onDeleteOrg={o => setConfirm({
                  title: 'Remover organização', danger: true,
                  msg: `Remover a organização "${o.name}"? Só é possível quando não há clientes vinculados.`,
                  action: async () => {
                    const res = online ? await srv.deleteOrg(o.id) : null;
                    if (online && !res) { toast('err', 'Organização possui clientes — mova-os antes'); return; }
                    setOrgs(p => p.filter(x => x.id !== o.id));
                    toast('ok', 'Organização removida');
                    void load();
                  },
                })} />
            )}

            {tab === 'identity' && (
              <IdentityTab settings={identity} providers={providers} roles={roles} canManage={canIdentityManage} online={online}
                onSettings={patch => {
                  setIdentity(prev => ({ ...prev, ...patch }));
                  if (online) void srv.patchIdentitySettings({ ...identity, ...patch }).then(res => { if (res) setIdentity(res); });
                  else toast('info', 'Política atualizada (local)');
                }}
                onNewProvider={() => setProviderModal('new')}
                onEditProvider={p => setProviderModal(p)}
                onToggleProvider={p => {
                  const enabled = !p.enabled;
                  setProviders(prev => prev.map(x => x.code === p.code ? { ...x, enabled } : x));
                  if (online) void srv.patchIdp(p.code, { enabled });
                  toast('info', `Provedor ${enabled ? 'ativado' : 'desativado'}`);
                }}
                onDeleteProvider={p => setConfirm({
                  title: 'Remover provedor SSO', danger: true,
                  msg: `Remover o provedor "${p.name}"? Usuários provisionados não serão afetados.`,
                  action: async () => {
                    if (online) await srv.deleteIdp(p.code);
                    setProviders(prev => prev.filter(x => x.code !== p.code));
                    toast('ok', 'Provedor removido');
                  },
                })} />
            )}
          </>
        )}
      </div>

      {/* modais */}
      <UserModal state={userModal} onClose={() => setUserModal(null)} roles={roles} tenants={tenants} online={online}
        onSaved={() => { setUserModal(null); toast('ok', 'Usuário salvo'); void load(); }} setLocal={setUsers} />
      <RoleModal state={roleModal} onClose={() => setRoleModal(null)} online={online}
        onSaved={() => { setRoleModal(null); toast('ok', 'Perfil de acesso salvo'); void load(); }} setLocal={setRoles} />
      <TenantModal state={tenantModal} onClose={() => setTenantModal(null)} online={online}
        onSaved={() => { setTenantModal(null); toast('ok', 'Cliente salvo'); void load(); }} setLocal={setTenants} />
      <ProviderModal state={providerModal} onClose={() => setProviderModal(null)} roles={roles} online={online}
        onSaved={() => { setProviderModal(null); toast('ok', 'Provedor salvo'); void load(); }}
        setLocal={setProviders} />
      <PasswordModal user={pwUser} onClose={() => setPwUser(null)} online={online}
        onSaved={() => { setPwUser(null); toast('ok', 'Senha redefinida'); }} />
      <OnboardModal open={onboardOpen} onClose={() => setOnboardOpen(false)} orgs={orgs} online={online}
        onSaved={() => { setOnboardOpen(false); toast('ok', 'Onboarding concluído'); void load(); }} />
      <EnvironmentsModal tenant={envTenant} onClose={() => setEnvTenant(null)} online={online}
        onSaved={() => { setEnvTenant(null); toast('ok', 'Ambientes atualizados'); void load(); }} />

      <Modal open={!!confirm} onClose={() => setConfirm(null)} title={confirm?.title ?? ''} width={430}
        footer={<>
          <button className="btn btn-xs" onClick={() => setConfirm(null)}>Cancelar</button>
          <button className={`btn btn-xs ${confirm?.danger ? 'btn-danger' : 'btn-primary'}`}
            onClick={() => { void confirm?.action(); setConfirm(null); }}>Confirmar</button>
        </>}>
        <p className="text-[12.5px] leading-relaxed text-sub">{confirm?.msg}</p>
      </Modal>
    </div>
  );
}

// ═══════════════ USUÁRIOS ═══════════════
function UsersTab({ users, total, me, roles, tenants, onEdit, onPassword, onToggle, onDelete, onResetMfa, onClearSearch }: {
  users: AdminUser[]; total: number; me: string; roles: AdminRole[]; tenants: AdminTenant[];
  onEdit: (u: AdminUser) => void; onPassword: (u: AdminUser) => void;
  onToggle: (u: AdminUser) => void; onDelete: (u: AdminUser) => void;
  onResetMfa: (u: AdminUser) => void;
  onClearSearch: () => void;
}) {
  const roleName = (r: string) => roles.find(x => x.name === r)?.display ?? r;
  // sem nenhum usuário cadastrado
  if (!total) return <EmptyState icon="users" title="Nenhum usuário" sub="Crie o primeiro usuário para acessar a plataforma." />;
  // há usuários, mas a busca não retornou nada
  if (!users.length) {
    return (
      <EmptyState icon="search" title="Nenhum resultado para a busca" sub="Nenhum usuário corresponde ao termo pesquisado." />
    );
  }
  return (
    <div className="panel a-up overflow-hidden">
      <table className="tbl">
        <thead>
          <tr><th>Usuário</th><th>Perfil</th><th>Cliente</th><th>Status</th><th>Último acesso</th><th className="text-right">Ações</th></tr>
        </thead>
        <tbody>
          {users.map((u, i) => {
            const name = u?.name ?? '(sem nome)';
            const username = u?.username ?? `usuario-${i}`;
            return (
              <tr key={username} className="rowline">
                <td>
                  <div className="flex items-center gap-3">
                    <Avatar name={name} size={30} />
                    <div>
                      <div className="text-[12.5px] font-medium text-ink/95">{name}{name === me && <span className="ml-1.5 text-[10px] text-teal">(você)</span>}</div>
                      <div className="font-mono text-[10.5px] text-faint">@{username}</div>
                    </div>
                  </div>
                </td>
                <td>
                  <div className="flex items-center gap-1.5">
                    <Pill label={roleName(u.role)} color={roleColor(u.role)} />
                    {u.mfaEnabled && <Pill label="MFA" color="#2fd6a5" sm />}
                  </div>
                </td>
                <td>
                  {u.tenant ? (
                    <span className="font-mono text-[11px] text-cyan">{u.tenantName ?? u.tenant}</span>
                  ) : <span className="text-[11px] text-faint">MSSP (todos)</span>}
                </td>
                <td>
                  <span className={`inline-flex items-center gap-1.5 text-[11px] ${u.active ? 'text-teal' : 'text-crit'}`}>
                    <span className={`h-1.5 w-1.5 rounded-full ${u.active ? 'bg-teal dot-live' : 'bg-crit'}`} />
                    {u.active ? 'Ativo' : 'Suspenso'}
                  </span>
                </td>
                <td className="font-mono text-[10.5px] text-faint">{u.lastLogin ? timeAgo(u.lastLogin) : 'nunca'}</td>
                <td>
                  <div className="flex justify-end gap-1">
                    <button className="btn btn-ghost btn-xs" title="Editar" onClick={() => onEdit(u)}><Icon name="edit" size={13} /></button>
                    <button className="btn btn-ghost btn-xs" title="Redefinir senha" onClick={() => onPassword(u)}><Icon name="lock" size={13} /></button>
                    {u.mfaEnabled && (
                      <button className="btn btn-ghost btn-xs" title="Resetar MFA (usuário perdeu o autenticador)" onClick={() => onResetMfa(u)}>
                        <Icon name="key" size={13} className="text-teal" />
                      </button>
                    )}
                    <button className="btn btn-ghost btn-xs" title={u.active ? 'Suspender' : 'Reativar'} onClick={() => onToggle(u)}>
                      <Icon name="power" size={13} className={u.active ? '' : 'text-teal'} />
                    </button>
                    <button className="btn btn-ghost btn-xs hover:!text-crit" title="Excluir" onClick={() => onDelete(u)} disabled={name === me}>
                      <Icon name="trash" size={13} />
                    </button>
                  </div>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
      {users.length < total && (
        <button onClick={onClearSearch}
          className="flex w-full items-center justify-center gap-2 border-t border-line px-4 py-2.5 text-[11.5px] text-teal transition-colors hover:bg-raise">
          <Icon name="search" size={12} /> mostrando {users.length} de {total} — limpar busca
        </button>
      )}
    </div>
  );
}

// ═══════════════ PERFIS ═══════════════
function RolesTab({ roles, onEdit, onDelete }: { roles: AdminRole[]; onEdit: (r: AdminRole) => void; onDelete: (r: AdminRole) => void }) {
  if (!roles.length) return <EmptyState icon="shield" title="Nenhum perfil" sub="Crie um perfil de acesso customizado." />;
  return (
    <div className="grid grid-cols-1 gap-3.5 md:grid-cols-2 2xl:grid-cols-3">
      {roles.map((r, i) => (
        <div key={r.name} className="panel a-up flex flex-col p-4 transition-all hover:border-line2" style={{ animationDelay: `${i * 40}ms` }}>
          <div className="flex items-start gap-3">
            <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-line bg-panel2" style={{ color: roleColor(r.name) }}>
              <Icon name="shield" size={16} />
            </span>
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2">
                <span className="font-display text-[14px] font-semibold text-ink">{r.display}</span>
                {r.builtin ? <Pill label="embutido" color="#8fa3c8" sm /> : <Pill label="customizado" color="#2fd6a5" sm />}
              </div>
              <div className="font-mono text-[10px] text-faint">{r.name}</div>
            </div>
          </div>
          <p className="mt-2.5 min-h-[32px] text-[11.5px] leading-snug text-sub">{r.description || 'Sem descrição.'}</p>
          <div className="mt-2 flex items-center gap-3 font-mono text-[10.5px] text-faint">
            <span className="flex items-center gap-1"><Icon name="users" size={11} /> {r.users} usuário{r.users !== 1 ? 's' : ''}</span>
            <span className="flex items-center gap-1"><Icon name="check" size={11} /> {r.permissions.includes('*') ? 'total' : `${r.permissions.length} permissões`}</span>
          </div>
          <div className="mt-3 flex flex-wrap gap-1">
            {(r.permissions.includes('*') ? ['*'] : r.permissions.slice(0, 4)).map(p => (
              <span key={p} className="rounded border border-line bg-panel2 px-1.5 py-0.5 font-mono text-[9.5px] text-sub">{p}</span>
            ))}
            {!r.permissions.includes('*') && r.permissions.length > 4 && (
              <span className="rounded border border-line bg-panel2 px-1.5 py-0.5 font-mono text-[9.5px] text-faint">+{r.permissions.length - 4}</span>
            )}
          </div>
          <div className="mt-3.5 flex gap-2 border-t border-line pt-3">
            <button className="btn btn-xs flex-1" onClick={() => onEdit(r)} disabled={r.name === 'Admin'}>
              <Icon name="edit" size={12} /> {r.name === 'Admin' ? 'Protegido' : 'Editar permissões'}
            </button>
            {!r.builtin && (
              <button className="btn btn-ghost btn-xs hover:!text-crit" onClick={() => onDelete(r)} disabled={r.users > 0}
                title={r.users > 0 ? 'Perfil em uso' : 'Excluir perfil'}>
                <Icon name="trash" size={12} />
              </button>
            )}
          </div>
        </div>
      ))}
    </div>
  );
}

// ═══════════════ CLIENTES ═══════════════
function TenantsTab({ tenants, onEdit, onDelete, onToggleStatus }: { tenants: AdminTenant[]; onEdit: (t: AdminTenant) => void; onDelete: (t: AdminTenant) => void; onToggleStatus: (t: AdminTenant, active: boolean) => void }) {
  if (!tenants.length) return <EmptyState icon="globe" title="Nenhum cliente" sub="Cadastre o primeiro tenant para isolar ambientes." />;
  return (
    <div className="grid grid-cols-1 gap-3.5 md:grid-cols-2 2xl:grid-cols-3">
      {tenants.map((t, i) => (
        <div key={t.id} className={`panel a-up flex flex-col p-4 transition-all hover:border-teal/40 ${!t.active ? 'opacity-60' : ''}`} style={{ animationDelay: `${i * 40}ms` }}>
          <div className="flex items-center gap-3">
            <span className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-lg border font-display text-[13px] font-bold ${t.active ? 'border-teal/40 bg-teal/10 text-teal' : 'border-red/40 bg-red/10 text-red'}`}>
              {t.short}
            </span>
            <div className="min-w-0 flex-1">
              <div className="truncate font-display text-[14.5px] font-semibold text-ink">{t.name}</div>
              <div className="font-mono text-[10px] text-faint">tenant: {t.id}{t.contact ? ` · ${t.contact}` : ''}</div>
            </div>
            <Icon name={t.active ? "globe" : "circle-x"} size={15} className={`shrink-0 ${t.active ? 'text-faint' : 'text-red'}`} />
          </div>
          <div className="mt-3.5 grid grid-cols-4 gap-2">
            {([['Ativos', t.assets, 'server'], ['Alertas', t.alerts, 'bell'], ['Incidentes', t.incidents, 'flame'], ['Vulns', t.vulns, 'bug']] as [string, number, IconName][]).map(([label, val, icon]) => (
              <div key={label} className="rounded-md border border-line/70 bg-panel px-2 py-2 text-center">
                <div className="font-mono text-[15px] font-bold text-ink tabular-nums">{val}</div>
                <div className="mt-0.5 flex items-center justify-center gap-1 text-[9px] uppercase tracking-wide text-faint">
                  <Icon name={icon} size={9} /> {label}
                </div>
              </div>
            ))}
          </div>
          <div className="mt-3 flex items-center justify-between border-t border-line pt-3">
            <span className="flex items-center gap-1.5 font-mono text-[10px] text-faint">
              <Icon name="users" size={11} /> {t.users} usuário{t.users !== 1 ? 's' : ''}
            </span>
            <span className={`flex items-center gap-1 text-[10px] ${t.active ? 'text-teal' : 'text-red'}`}>
              <Icon name={t.active ? "lock" : "unlock"} size={10} /> {t.active ? 'dados isolados' : 'inativo'}
            </span>
          </div>
          <div className="mt-3 flex gap-2">
            <button className="btn btn-xs flex-1" onClick={() => onEdit(t)}><Icon name="edit" size={12} /> Editar</button>
            <button 
              className={`btn btn-xs ${t.active ? 'hover:!text-orange' : 'hover:!text-green'}`} 
              onClick={() => onToggleStatus(t, !t.active)}
              title={t.active ? 'Desativar tenant' : 'Ativar tenant'}>
              <Icon name={t.active ? "pause" : "play"} size={12} /> {t.active ? 'Desativar' : 'Ativar'}
            </button>
            <button className="btn btn-ghost btn-xs hover:!text-crit" onClick={() => onDelete(t)}
              title="Excluir permanentemente todos os dados do tenant">
              <Icon name="trash" size={12} />
            </button>
          </div>
        </div>
      ))}
    </div>
  );
}

// ═══════════════ MODAIS ═══════════════
function useLocal<T>(initial: T) {
  const [v, setV] = useState(initial);
  useEffect(() => setV(initial), [initial]);
  return [v, setV] as const;
}

function UserModal({ state, onClose, roles, tenants, online, onSaved, setLocal }: {
  state: AdminUser | 'new' | null; onClose: () => void; roles: AdminRole[]; tenants: AdminTenant[];
  online: boolean; onSaved: () => void; setLocal: React.Dispatch<React.SetStateAction<AdminUser[]>>;
}) {
  const editing = state !== null && state !== 'new' ? state : null;
  const [name, setName] = useLocal(editing?.name ?? '');
  const [username, setUsername] = useLocal(editing?.username ?? '');
  const [password, setPassword] = useState('');
  const [role, setRole] = useLocal(editing?.role ?? 'SOC Analyst');
  const [tenant, setTenant] = useLocal(editing?.tenant ?? '');
  const [active, setActive] = useLocal(editing?.active ?? true);
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (state !== null) { setErr(''); setPassword(''); }
  }, [state]);

  const save = async () => {
    setErr('');
    if (!name.trim() || (!editing && !username.trim())) { setErr('Nome e usuário são obrigatórios.'); return; }
    if (!editing && password.length < 4) { setErr('A senha deve ter ao menos 4 caracteres.'); return; }
    if (role === 'Customer' && !tenant) { setErr('O perfil Customer exige um cliente (tenant).'); return; }
    setBusy(true);
    const body: { name: string; role: string; tenant: string | null; active: boolean; username?: string; password?: string } = {
      name: name.trim(), role, tenant: tenant || null, active,
      ...(editing ? {} : { username: username.trim().toLowerCase(), password }),
    };
    if (online) {
      const res = editing ? await srv.updateUser(editing.username, body) : await srv.createUser(body);
      if (!res?.ok) { setErr(res?.error ?? 'Falha ao salvar.'); setBusy(false); return; }
    } else {
      if (editing) {
        setLocal(p => p.map(u => u.username === editing.username ? { ...u, ...body, tenantName: tenants.find(t => t.id === body.tenant)?.name ?? null } : u));
      } else {
        const nu: AdminUser = {
          username: body.username ?? '', name: body.name, role: body.role, tenant: body.tenant,
          tenantName: tenants.find(t => t.id === body.tenant)?.name ?? null, active: body.active, lastLogin: null,
        };
        setLocal(p => p.some(u => u.username === nu.username) ? p : [...p, nu]);
      }
    }
    setBusy(false);
    onSaved();
  };

  return (
    <Modal open={state !== null} onClose={onClose} title={editing ? 'Editar usuário' : 'Novo usuário'} width={480}
      footer={<>
        <button className="btn btn-xs" onClick={onClose}>Cancelar</button>
        <button className="btn btn-primary btn-xs" onClick={() => void save()} disabled={busy}>
          {busy ? 'Salvando…' : <><Icon name="check" size={12} /> Salvar usuário</>}
        </button>
      </>}>
      <div className="flex flex-col gap-3.5">
        <div className="grid grid-cols-2 gap-3">
          <Field label="Nome completo"><input className="input w-full" value={name} onChange={e => setName(e.target.value)} placeholder="Ex.: João da Silva" /></Field>
          <Field label="Usuário (login)">
            <input className="input w-full font-mono" value={username} onChange={e => setUsername(e.target.value)} disabled={!!editing} placeholder="joao.silva" />
          </Field>
        </div>
        {!editing && (
          <Field label="Senha inicial"><input className="input w-full font-mono" type="text" value={password} onChange={e => setPassword(e.target.value)} placeholder="mínimo 4 caracteres" /></Field>
        )}
        <div className="grid grid-cols-2 gap-3">
          <Field label="Perfil de acesso">
            <select className="select w-full" value={role} onChange={e => setRole(e.target.value)}>
              {roles.map(r => <option key={r.name} value={r.name}>{r.display}</option>)}
            </select>
          </Field>
          <Field label="Cliente (tenant)">
            <select className="select w-full" value={tenant} onChange={e => setTenant(e.target.value)}>
              <option value="">MSSP — todos os clientes</option>
              {tenants.map(t => <option key={t.id} value={t.id}>{t.name}</option>)}
            </select>
          </Field>
        </div>
        <label className="flex cursor-pointer items-center gap-2.5 rounded-md border border-line bg-panel px-3 py-2.5">
          <button type="button" onClick={() => setActive(!active)}
            className={`relative h-5 w-9 rounded-full transition-colors ${active ? 'bg-teal' : 'bg-line2'}`}>
            <span className={`absolute top-0.5 h-4 w-4 rounded-full bg-white transition-all ${active ? 'left-[18px]' : 'left-0.5'}`} />
          </button>
          <span className="text-[12px] text-sub">{active ? 'Conta ativa — pode acessar' : 'Conta suspensa — acesso bloqueado'}</span>
        </label>
        {err && <div className="flex items-center gap-2 rounded-md border border-crit/40 bg-crit/10 px-3 py-2 text-[11.5px] text-crit"><Icon name="alertTriangle" size={13} /> {err}</div>}
        <div className="rounded-md border border-line bg-panel px-3 py-2 font-mono text-[10px] leading-relaxed text-faint">
          Usuários com cliente definido enxergam <span className="text-teal">apenas aquele tenant</span> (isolamento garantido no token JWT).
        </div>
      </div>
    </Modal>
  );
}

function RoleModal({ state, onClose, online, onSaved, setLocal }: {
  state: AdminRole | 'new' | null; onClose: () => void; online: boolean;
  onSaved: () => void; setLocal: React.Dispatch<React.SetStateAction<AdminRole[]>>;
}) {
  const editing = state !== null && state !== 'new' ? state : null;
  const [display, setDisplay] = useLocal(editing?.display ?? '');
  const [name, setName] = useLocal(editing?.name ?? '');
  const [description, setDescription] = useLocal(editing?.description ?? '');
  const [perms, setPerms] = useLocal<string[]>(editing?.permissions ?? []);
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);

  useEffect(() => { if (state !== null) setErr(''); }, [state]);

  const toggle = (id: string) => setPerms(p => p.includes(id) ? p.filter(x => x !== id) : [...p, id]);
  const toggleModule = (ids: string[]) => {
    const allOn = ids.every(id => perms.includes(id));
    setPerms(p => allOn ? p.filter(x => !ids.includes(x)) : [...new Set([...p, ...ids])]);
  };

  const save = async () => {
    setErr('');
    if (!display.trim()) { setErr('Nome de exibição é obrigatório.'); return; }
    if (!editing && !name.trim()) { setErr('Identificador é obrigatório.'); return; }
    if (!perms.length) { setErr('Selecione ao menos uma permissão.'); return; }
    setBusy(true);
    const body = { display: display.trim(), description: description.trim(), permissions: perms, ...(editing ? {} : { name: name.trim() }) };
    if (online) {
      const res = editing ? await srv.updateRole(editing.name, body) : await srv.createRole(body);
      if (!res?.ok) { setErr(res?.error ?? 'Falha ao salvar.'); setBusy(false); return; }
    } else if (editing) {
      setLocal(p => p.map(r => r.name === editing.name ? { ...r, ...body } : r));
    } else {
      setLocal(p => [...p, { name: name.trim().toLowerCase().replace(/\s+/g, '-'), display: body.display, description: body.description, permissions: body.permissions, builtin: false, users: 0 }]);
    }
    setBusy(false);
    onSaved();
  };

  return (
    <Modal open={state !== null} onClose={onClose} title={editing ? `Editar perfil — ${editing.display}` : 'Novo perfil de acesso'} width={620}
      footer={<>
        <button className="btn btn-xs" onClick={onClose}>Cancelar</button>
        <button className="btn btn-primary btn-xs" onClick={() => void save()} disabled={busy}>
          {busy ? 'Salvando…' : <><Icon name="check" size={12} /> Salvar perfil</>}
        </button>
      </>}>
      <div className="flex flex-col gap-3.5">
        <div className="grid grid-cols-2 gap-3">
          <Field label="Nome de exibição"><input className="input w-full" value={display} onChange={e => setDisplay(e.target.value)} placeholder="Ex.: Analista N1" /></Field>
          <Field label="Identificador (slug)">
            <input className="input w-full font-mono" value={name} onChange={e => setName(e.target.value)} disabled={!!editing} placeholder="analista-n1" />
          </Field>
        </div>
        <Field label="Descrição"><input className="input w-full" value={description} onChange={e => setDescription(e.target.value)} placeholder="O que este perfil faz?" /></Field>

        <div>
          <div className="mb-2 flex items-center justify-between">
            <span className="lbl">Permissões ({perms.length} selecionadas)</span>
          </div>
          <div className="max-h-[300px] overflow-y-auto rounded-lg border border-line">
            {PERM_CATALOG.map(mod => {
              const ids = mod.perms.map(p => p.id);
              const allOn = ids.every(id => perms.includes(id));
              const someOn = ids.some(id => perms.includes(id));
              return (
                <div key={mod.module} className="border-b border-line/60 last:border-b-0">
                  <button type="button" onClick={() => toggleModule(ids)}
                    className={`flex w-full items-center gap-2.5 px-3 py-2 text-left transition-colors hover:bg-raise ${someOn ? 'bg-teal/[.04]' : ''}`}>
                    <span className={`flex h-4 w-4 items-center justify-center rounded border ${allOn ? 'border-teal bg-teal text-[#04160f]' : someOn ? 'border-teal/60' : 'border-line2'}`}>
                      {allOn && <Icon name="check" size={10} strokeWidth={3} />}
                      {!allOn && someOn && <span className="h-1.5 w-1.5 rounded-sm bg-teal" />}
                    </span>
                    <Icon name={mod.icon as IconName} size={13} className={someOn ? 'text-teal' : 'text-faint'} />
                    <span className={`text-[12px] font-medium ${someOn ? 'text-ink' : 'text-sub'}`}>{mod.module}</span>
                    <span className="ml-auto font-mono text-[9.5px] text-faint">{ids.filter(id => perms.includes(id)).length}/{ids.length}</span>
                  </button>
                  <div className="grid grid-cols-2 gap-x-3 px-3 pb-2">
                    {mod.perms.map(p => (
                      <button key={p.id} type="button" onClick={() => toggle(p.id)} className="flex items-center gap-2 rounded px-1.5 py-1 text-left hover:bg-raise transition-colors">
                        <span className={`flex h-3.5 w-3.5 shrink-0 items-center justify-center rounded-sm border ${perms.includes(p.id) ? 'border-teal bg-teal text-[#04160f]' : 'border-line2'}`}>
                          {perms.includes(p.id) && <Icon name="check" size={9} strokeWidth={3} />}
                        </span>
                        <span className="truncate text-[11px] text-sub">{p.label}</span>
                      </button>
                    ))}
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {err && <div className="flex items-center gap-2 rounded-md border border-crit/40 bg-crit/10 px-3 py-2 text-[11.5px] text-crit"><Icon name="alertTriangle" size={13} /> {err}</div>}
      </div>
    </Modal>
  );
}

function TenantModal({ state, onClose, online, onSaved, setLocal }: {
  state: AdminTenant | 'new' | null; onClose: () => void; online: boolean;
  onSaved: () => void; setLocal: React.Dispatch<React.SetStateAction<AdminTenant[]>>;
}) {
  const editing = state !== null && state !== 'new' ? state : null;
  const [name, setName] = useLocal(editing?.name ?? '');
  const [id, setId] = useLocal(editing?.id ?? '');
  const [short, setShort] = useLocal(editing?.short ?? '');
  const [contact, setContact] = useLocal(editing?.contact ?? '');
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);

  useEffect(() => { if (state !== null) setErr(''); }, [state]);

  const autoId = (v: string) => v.toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '').replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');

  const save = async () => {
    setErr('');
    if (!name.trim()) { setErr('Nome do cliente é obrigatório.'); return; }
    const tid = editing ? editing.id : (id.trim() || autoId(name));
    if (!tid) { setErr('Identificador inválido.'); return; }
    setBusy(true);
    const body = { name: name.trim(), short: (short.trim() || name.trim().slice(0, 3)).toUpperCase(), contact: contact.trim() || null, ...(editing ? {} : { id: tid }) };
    if (online) {
      const res = editing ? await srv.updateTenant(editing.id, body) : await srv.createTenant(body);
      if (!res?.ok) { setErr(res?.error ?? 'Falha ao salvar.'); setBusy(false); return; }
    } else if (editing) {
      setLocal(p => p.map(t => t.id === editing.id ? { ...t, ...body } : t));
    } else {
      setLocal(p => p.some(t => t.id === tid) ? p : [...p, {
        id: tid, name: body.name, short: body.short, contact: body.contact,
        orgId: null, orgName: null, brandColor: null, tagline: null,
        quotas: { maxUsers: null, maxAssets: null, maxConnectors: null },
        created: Date.now(), assets: 0, alerts: 0, incidents: 0, users: 0, vulns: 0,
        connectors: 0, environments: [{ id: 'ENV-novo', name: 'Produção', kind: 'producao' }],
      }]);
    }
    setBusy(false);
    onSaved();
  };

  return (
    <Modal open={state !== null} onClose={onClose} title={editing ? 'Editar cliente' : 'Novo cliente (tenant)'} width={460}
      footer={<>
        <button className="btn btn-xs" onClick={onClose}>Cancelar</button>
        <button className="btn btn-primary btn-xs" onClick={() => void save()} disabled={busy}>
          {busy ? 'Salvando…' : <><Icon name="check" size={12} /> Salvar cliente</>}
        </button>
      </>}>
      <div className="flex flex-col gap-3.5">
        <Field label="Nome do cliente">
          <input className="input w-full" value={name} onChange={e => { setName(e.target.value); if (!editing && !id) setId(autoId(e.target.value)); }} placeholder="Ex.: Acme Corp" autoFocus />
        </Field>
        <div className="grid grid-cols-2 gap-3">
          <Field label="Identificador (tenant)">
            <input className="input w-full font-mono" value={editing ? editing.id : id} onChange={e => setId(e.target.value)} disabled={!!editing} placeholder="acme-corp" />
          </Field>
          <Field label="Sigla (até 4)">
            <input className="input w-full font-mono uppercase" value={short} onChange={e => setShort(e.target.value.slice(0, 4))} placeholder="ACM" />
          </Field>
        </div>
        <Field label="Contato de segurança"><input className="input w-full" value={contact} onChange={e => setContact(e.target.value)} placeholder="soc@cliente.com" /></Field>
        {err && <div className="flex items-center gap-2 rounded-md border border-crit/40 bg-crit/10 px-3 py-2 text-[11.5px] text-crit"><Icon name="alertTriangle" size={13} /> {err}</div>}
        <div className="rounded-md border border-line bg-panel px-3 py-2 font-mono text-[10px] leading-relaxed text-faint">
          Cada tenant tem <span className="text-teal">eventos, alertas, incidentes, casos e vulnerabilidades isolados</span>. Um cliente jamais enxerga dados de outro.
        </div>
      </div>
    </Modal>
  );
}

function PasswordModal({ user, onClose, online, onSaved }: { user: AdminUser | null; onClose: () => void; online: boolean; onSaved: () => void }) {
  const [pw, setPw] = useState('');
  const [err, setErr] = useState('');
  useEffect(() => { if (user) { setPw(''); setErr(''); } }, [user]);
  const save = async () => {
    if (pw.length < 4) { setErr('A senha deve ter ao menos 4 caracteres.'); return; }
    if (online) {
      const res = await srv.resetPassword(user!.username, pw);
      if (!res?.ok) { setErr(res?.error ?? 'Falha ao redefinir.'); return; }
    }
    onSaved();
  };
  return (
    <Modal open={!!user} onClose={onClose} title={`Redefinir senha — ${user?.name ?? ''}`} width={400}
      footer={<>
        <button className="btn btn-xs" onClick={onClose}>Cancelar</button>
        <button className="btn btn-primary btn-xs" onClick={() => void save()}><Icon name="lock" size={12} /> Redefinir</button>
      </>}>
      <div className="flex flex-col gap-3">
        <Field label="Nova senha"><input className="input w-full font-mono" type="text" value={pw} onChange={e => setPw(e.target.value)} placeholder="mínimo 4 caracteres" autoFocus /></Field>
        {err && <div className="flex items-center gap-2 rounded-md border border-crit/40 bg-crit/10 px-3 py-2 text-[11.5px] text-crit"><Icon name="alertTriangle" size={13} /> {err}</div>}
        <div className="rounded-md border border-line bg-panel px-3 py-2 text-[11px] text-faint">A ação fica registrada na trilha de auditoria.</div>
      </div>
    </Modal>
  );
}

// ═══════════════ IDENTIDADE & AUTENTICAÇÃO ═══════════════
function Toggle({ on, onChange, disabled = false }: { on: boolean; onChange: (v: boolean) => void; disabled?: boolean }) {
  return (
    <button type="button" disabled={disabled} onClick={() => onChange(!on)}
      className={`relative h-[20px] w-[38px] shrink-0 rounded-full border transition-all ${disabled ? 'opacity-40' : 'cursor-pointer'} ${on ? 'border-teal/60 bg-teal/25' : 'border-line2 bg-panel2'}`}>
      <span className={`absolute top-1/2 h-[14px] w-[14px] -translate-y-1/2 rounded-full transition-all ${on ? 'left-[20px] bg-teal shadow-[0_0_8px_rgba(47,214,165,.6)]' : 'left-[3px] bg-faint'}`} />
    </button>
  );
}

function IdentityTab({ settings, providers, roles, canManage, online, onSettings, onNewProvider, onEditProvider, onToggleProvider, onDeleteProvider }: {
  settings: IdentitySettings; providers: IdpProvider[]; roles: AdminRole[]; canManage: boolean; online: boolean;
  onSettings: (patch: Partial<IdentitySettings>) => void;
  onNewProvider: () => void; onEditProvider: (p: IdpProvider) => void;
  onToggleProvider: (p: IdpProvider) => void; onDeleteProvider: (p: IdpProvider) => void;
}) {
  const mfaCount = settings.mfa_required_roles.length;
  return (
    <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
      {/* ── Política de acesso ── */}
      <div className="panel a-up p-5">
        <div className="flex items-center gap-2.5">
          <span className="flex h-8 w-8 items-center justify-center rounded-lg border border-teal/40 bg-teal/10 text-teal"><Icon name="clock" size={15} /></span>
          <div>
            <div className="font-display text-[13.5px] font-semibold text-ink">Política de Sessão</div>
            <div className="text-[10.5px] text-faint">validade do token JWT</div>
          </div>
        </div>
        <div className="mt-4">
          <Field label="Expiração da sessão (horas)">
            <div className="flex items-center gap-2.5">
              <input type="range" min={1} max={24} value={settings.session_ttl_hours} disabled={!canManage}
                onChange={e => onSettings({ session_ttl_hours: Number(e.target.value) })}
                className="flex-1 accent-teal" />
              <span className="w-[52px] rounded-md border border-line bg-panel px-2 py-1 text-center font-mono text-[12px] text-teal">{settings.session_ttl_hours}h</span>
            </div>
          </Field>
          <p className="mt-2 text-[11px] leading-relaxed text-faint">
            Após este período o usuário precisa autenticar novamente. Sessões ativas podem ser encerradas na área "Minha conta".
          </p>
        </div>
        <div className="mt-4 border-t border-line pt-4">
          <Field label="Comprimento mínimo de senha">
            <div className="flex items-center gap-2.5">
              <input type="range" min={4} max={24} value={settings.min_password_length} disabled={!canManage}
                onChange={e => onSettings({ min_password_length: Number(e.target.value) })}
                className="flex-1 accent-teal" />
              <span className="w-[52px] rounded-md border border-line bg-panel px-2 py-1 text-center font-mono text-[12px] text-teal">{settings.min_password_length} chars</span>
            </div>
          </Field>
          <p className="mt-2 text-[11px] text-faint">Aplicado na criação de usuários e na troca de senha.</p>
        </div>
      </div>

      {/* ── MFA ── */}
      <div className="panel a-up p-5" style={{ animationDelay: '60ms' }}>
        <div className="flex items-center gap-2.5">
          <span className="flex h-8 w-8 items-center justify-center rounded-lg border border-med/40 bg-med/10 text-med"><Icon name="shield" size={15} /></span>
          <div>
            <div className="font-display text-[13.5px] font-semibold text-ink">Autenticação Multifator</div>
            <div className="text-[10.5px] text-faint">TOTP · códigos de recuperação</div>
          </div>
        </div>
        <p className="mt-3 text-[11.5px] leading-relaxed text-sub">
          Exigir MFA para os perfis abaixo. Usuários desses perfis serão obrigados a configurar um autenticador no próximo login.
        </p>
        <div className="mt-3.5 flex flex-col gap-1.5">
          {roles.filter(r => r.name !== 'Customer').map(r => {
            const on = settings.mfa_required_roles.includes(r.name);
            return (
              <div key={r.name} className="flex items-center gap-3 rounded-lg border border-line bg-panel px-3 py-2.5">
                <Pill label={r.display} color={roleColor(r.name)} sm />
                <span className="text-[10.5px] text-faint">{r.users} usuário{r.users === 1 ? '' : 's'}</span>
                <span className="ml-auto">
                  <Toggle on={on} disabled={!canManage}
                    onChange={v => onSettings({
                      mfa_required_roles: v
                        ? [...settings.mfa_required_roles, r.name]
                        : settings.mfa_required_roles.filter(x => x !== r.name),
                    })} />
                </span>
              </div>
            );
          })}
        </div>
        <div className={`mt-3.5 flex items-center gap-2 rounded-md border px-3 py-2 text-[11px] ${mfaCount ? 'border-teal/40 bg-teal/[.06] text-teal' : 'border-line bg-panel text-faint'}`}>
          <Icon name={mfaCount ? 'check' : 'alertTriangle'} size={13} />
          {mfaCount ? `MFA obrigatório para ${mfaCount} perfil(is)` : 'Nenhum perfil exige MFA'}
        </div>
      </div>

      {/* ── SSO / Provedores ── */}
      <div className="panel a-up p-5" style={{ animationDelay: '120ms' }}>
        <div className="flex items-center gap-2.5">
          <span className="flex h-8 w-8 items-center justify-center rounded-lg border border-cyan/40 bg-cyan/10 text-cyan"><Icon name="globe" size={15} /></span>
          <div className="min-w-0 flex-1">
            <div className="font-display text-[13.5px] font-semibold text-ink">Single Sign-On (OIDC)</div>
            <div className="text-[10.5px] text-faint">Entra ID · Okta · Keycloak</div>
          </div>
          <Toggle on={settings.sso_enabled} disabled={!canManage} onChange={v => onSettings({ sso_enabled: v })} />
        </div>
        <div className="mt-3 flex items-center justify-between rounded-lg border border-line bg-panel px-3 py-2.5">
          <div>
            <div className="text-[12px] font-medium text-ink/90">Auto-provisionamento</div>
            <div className="text-[10.5px] text-faint">cria usuário no 1º login via SSO</div>
          </div>
          <Toggle on={settings.sso_auto_provision} disabled={!canManage || !settings.sso_enabled}
            onChange={v => onSettings({ sso_auto_provision: v })} />
        </div>

        <div className="mt-4 flex items-center justify-between">
          <span className="lbl">Provedores · {providers.length}</span>
          {canManage && (
            <button className="btn btn-primary btn-xs" onClick={onNewProvider}><Icon name="plus" size={11} /> Provedor</button>
          )}
        </div>

        <div className="mt-2.5 flex flex-col gap-2">
          {providers.length === 0 && (
            <div className="rounded-lg border border-dashed border-line px-3 py-5 text-center text-[11px] text-faint">
              Nenhum provedor SSO configurado.<br />Adicione Entra ID, Okta ou Keycloak.
            </div>
          )}
          {providers.map(p => (
            <div key={p.code} className={`rounded-lg border px-3 py-3 transition-colors ${p.enabled ? 'border-line bg-panel' : 'border-line/60 bg-panel/50 opacity-60'}`}>
              <div className="flex items-center gap-2.5">
                <span className={`flex h-7 w-7 items-center justify-center rounded-md border ${p.enabled ? 'border-cyan/40 bg-cyan/10 text-cyan' : 'border-line bg-panel2 text-faint'}`}>
                  <Icon name="globe" size={13} />
                </span>
                <div className="min-w-0 flex-1">
                  <div className="truncate text-[12.5px] font-medium text-ink/95">{p.name}</div>
                  <div className="truncate font-mono text-[9.5px] text-faint">{p.issuer}</div>
                </div>
                <Pill label={p.type.toUpperCase()} color="#56c4ff" sm />
                <Toggle on={p.enabled} disabled={!canManage} onChange={() => onToggleProvider(p)} />
              </div>
              {canManage && (
                <div className="mt-2 flex justify-end gap-1 border-t border-line/60 pt-2">
                  <button className="btn btn-ghost btn-xs" onClick={() => onEditProvider(p)}><Icon name="edit" size={12} /> Editar</button>
                  <button className="btn btn-ghost btn-xs hover:!text-crit" onClick={() => onDeleteProvider(p)}><Icon name="trash" size={12} /> Remover</button>
                </div>
              )}
            </div>
          ))}
        </div>
      </div>

      <div className="a-up col-span-1 flex items-center gap-4 rounded-lg border border-line/60 bg-panel/50 px-4 py-2.5 font-mono text-[10.5px] text-faint xl:col-span-3" style={{ animationDelay: '180ms' }}>
        <span className="text-teal">● políticas aplicadas em tempo real</span>
        <span>{online ? 'persistidas na sopir-api' : 'local (não persiste)'}</span>
        <span className="ml-auto">MFA: TOTP RFC 6238 · 8 códigos de recuperação por usuário</span>
      </div>
    </div>
  );
}

// ═══════════════ MODAL DE PROVEDOR SSO ═══════════════
function ProviderModal({ state, onClose, roles, online, onSaved, setLocal }: {
  state: IdpProvider | 'new' | null; onClose: () => void; roles: AdminRole[]; online: boolean;
  onSaved: () => void; setLocal: (fn: (p: IdpProvider[]) => IdpProvider[]) => void;
}) {
  const editing = state && state !== 'new' ? state : null;
  const [name, setName] = useState('');
  const [type, setType] = useState('oidc');
  const [issuer, setIssuer] = useState('');
  const [clientId, setClientId] = useState('');
  const [clientSecret, setClientSecret] = useState('');
  const [defaultRole, setDefaultRole] = useState('SOC Analyst');
  const [autoProvision, setAutoProvision] = useState(true);
  const [err, setErr] = useState('');
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<{ ok: boolean; message: string } | null>(null);

  useEffect(() => {
    if (!state) return;
    if (editing) {
      setName(editing.name); setType(editing.type); setIssuer(editing.issuer);
      setClientId(editing.clientId); setClientSecret(''); setDefaultRole(editing.defaultRole);
      setAutoProvision(editing.autoProvision);
    } else {
      setName(''); setType('oidc'); setIssuer(''); setClientId(''); setClientSecret('');
      setDefaultRole('SOC Analyst'); setAutoProvision(true);
    }
    setErr(''); setTestResult(null);
  }, [state, editing]);

  const presets: { label: string; issuer: string }[] = [
    { label: 'Microsoft Entra ID', issuer: 'https://login.microsoftonline.com/{tenant-id}/v2.0' },
    { label: 'Okta', issuer: 'https://{org}.okta.com' },
    { label: 'Keycloak', issuer: 'https://{host}/realms/{realm}' },
  ];

  const testDiscovery = async () => {
    if (!issuer.trim()) { setErr('Informe a URL do issuer.'); return; }
    setTesting(true); setErr(''); setTestResult(null);
    const res = await srv.testIdp(issuer.trim());
    setTesting(false);
    setTestResult(res ? { ok: res.ok, message: res.message } : { ok: false, message: 'Falha de comunicação com a API.' });
  };

  const save = async () => {
    if (!name.trim() || !issuer.trim() || !clientId.trim()) { setErr('Nome, issuer e client ID são obrigatórios.'); return; }
    const body = {
      name: name.trim(), type, issuer: issuer.trim(), clientId: clientId.trim(),
      clientSecret: clientSecret || undefined, defaultRole, autoProvision,
    };
    if (online) {
      const res = editing ? await srv.patchIdp(editing.code, body) : await srv.createIdp(body);
      if (!res) { setErr('Falha ao salvar o provedor.'); return; }
    } else {
      setLocal(p => editing
        ? p.map(x => x.code === editing.code ? { ...x, ...body, clientSecret: undefined } as IdpProvider : x)
        : [...p, { code: 'idp-' + Date.now(), enabled: true, created: Date.now(), ...body } as IdpProvider]);
    }
    onSaved();
  };

  return (
    <Modal open={!!state} onClose={onClose} title={editing ? `Editar provedor — ${editing.name}` : 'Novo provedor SSO'} width={520}
      footer={<>
        <button className="btn btn-xs" onClick={onClose}>Cancelar</button>
        <button className="btn btn-primary btn-xs" onClick={() => void save()}><Icon name="globe" size={12} /> {editing ? 'Salvar' : 'Adicionar provedor'}</button>
      </>}>
      <div className="flex flex-col gap-3.5">
        <Field label="Modelos rápidos">
          <div className="flex flex-wrap gap-1.5">
            {presets.map(pr => (
              <button key={pr.label} type="button" className="chip" onClick={() => { setIssuer(pr.issuer); setType('oidc'); }}>
                <Icon name="globe" size={11} /> {pr.label}
              </button>
            ))}
          </div>
        </Field>
        <div className="grid grid-cols-2 gap-3">
          <Field label="Nome de exibição"><input className="input w-full" value={name} onChange={e => setName(e.target.value)} placeholder="Ex.: Entra ID — Vetra" autoFocus /></Field>
          <Field label="Protocolo">
            <select className="select w-full" value={type} onChange={e => setType(e.target.value)}>
              <option value="oidc">OpenID Connect</option>
            </select>
          </Field>
        </div>
        <Field label="Issuer URL (discovery)">
          <div className="flex gap-2">
            <input className="input w-full font-mono text-[11.5px]" value={issuer} onChange={e => { setIssuer(e.target.value); setTestResult(null); }} placeholder="https://login.microsoftonline.com/…/v2.0" />
            <button className="btn btn-xs shrink-0" onClick={() => void testDiscovery()} disabled={testing}>
              {testing ? 'Testando…' : <><Icon name="zap" size={12} /> Testar</>}
            </button>
          </div>
        </Field>
        {testResult && (
          <div className={`flex items-center gap-2 rounded-md border px-3 py-2 text-[11.5px] ${testResult.ok ? 'border-teal/40 bg-teal/[.06] text-teal' : 'border-crit/40 bg-crit/10 text-crit'}`}>
            <Icon name={testResult.ok ? 'check' : 'alertTriangle'} size={13} /> {testResult.message}
          </div>
        )}
        <div className="grid grid-cols-2 gap-3">
          <Field label="Client ID"><input className="input w-full font-mono text-[11.5px]" value={clientId} onChange={e => setClientId(e.target.value)} placeholder="00000000-0000-…" /></Field>
          <Field label="Client Secret"><input className="input w-full font-mono text-[11.5px]" type="password" value={clientSecret} onChange={e => setClientSecret(e.target.value)} placeholder={editing ? '••• (mantido se vazio)' : 'segredo'} /></Field>
        </div>
        <div className="grid grid-cols-2 gap-3">
          <Field label="Perfil padrão (auto-provision)">
            <select className="select w-full" value={defaultRole} onChange={e => setDefaultRole(e.target.value)}>
              {roles.filter(r => r.name !== 'Admin').map(r => <option key={r.name} value={r.name}>{r.display}</option>)}
            </select>
          </Field>
          <Field label="Auto-provisionamento">
            <div className="flex h-[34px] items-center"><Toggle on={autoProvision} onChange={setAutoProvision} /></div>
          </Field>
        </div>
        {err && <div className="flex items-center gap-2 rounded-md border border-crit/40 bg-crit/10 px-3 py-2 text-[11.5px] text-crit"><Icon name="alertTriangle" size={13} /> {err}</div>}
        <div className="rounded-md border border-line bg-panel px-3 py-2 font-mono text-[10px] leading-relaxed text-faint">
          Redirect URI a configurar no provedor:<br />
          <span className="text-cyan">{typeof window !== 'undefined' ? window.location.origin : 'http://localhost:8080'}/sso/callback</span>
        </div>
      </div>
    </Modal>
  );
}

// ═══════════════ MULTI-TENANCY ═══════════════
const ENV_KIND: Record<string, { label: string; color: string }> = {
  producao: { label: 'Produção', color: '#2fd6a5' },
  homologacao: { label: 'Homologação', color: '#56c4ff' },
  laboratorio: { label: 'Laboratório', color: '#ffc53d' },
  dr: { label: 'DR / Contingência', color: '#ff9142' },
};

function MultiTenancyTab({ orgs, tenants, isolation, view, onView, onOnboard, onEnvs, onCreateOrg, onDeleteOrg }: {
  orgs: Org[]; tenants: AdminTenant[]; isolation: IsolationRow[];
  view: 'tree' | 'matrix'; onView: (v: 'tree' | 'matrix') => void;
  onOnboard: () => void; onEnvs: (t: AdminTenant) => void;
  onCreateOrg: (name: string) => void; onDeleteOrg: (o: Org) => void;
}) {
  const [orgName, setOrgName] = useState('');
  const standalone = tenants.filter(t => !t.orgId);
  const heat = (n: number) => {
    if (n === 0) return 'rgba(28,43,71,0.25)';
    const t = Math.min(1, Math.log10(n + 1) / 4);
    return `rgba(47,214,165,${0.12 + t * 0.75})`;
  };
  const heatText = (n: number) => (n === 0 ? 'text-faint/50' : Math.log10(n + 1) / 4 > 0.5 ? 'text-[#04160f] font-semibold' : 'text-teal');

  return (
    <div className="flex flex-col gap-4">
      <div className="a-up flex flex-wrap items-center gap-2">
        <div className="flex rounded-lg border border-line bg-panel p-0.5">
          {(['tree', 'matrix'] as const).map(v => (
            <button key={v} onClick={() => onView(v)}
              className={`flex items-center gap-1.5 rounded-md px-3 py-1.5 text-[11.5px] font-medium transition-all ${view === v ? 'bg-teal/15 text-teal' : 'text-faint hover:text-sub'}`}>
              <Icon name={v === 'tree' ? 'layers' : 'grid'} size={13} />
              {v === 'tree' ? 'Hierarquia' : 'Matriz de isolamento'}
            </button>
          ))}
        </div>
        <div className="ml-auto flex items-center gap-2">
          <input className="input py-1.5! text-[11.5px] w-[180px]" placeholder="Nova organização…" value={orgName}
            onChange={e => setOrgName(e.target.value)}
            onKeyDown={e => { if (e.key === 'Enter' && orgName.trim()) { onCreateOrg(orgName.trim()); setOrgName(''); } }} />
          <button className="btn btn-xs" disabled={!orgName.trim()} onClick={() => { onCreateOrg(orgName.trim()); setOrgName(''); }}>
            <Icon name="plus" size={12} /> Criar org
          </button>
          <button className="btn btn-primary btn-xs" onClick={onOnboard}>
            <Icon name="sparkles" size={12} /> Onboarding de cliente
          </button>
        </div>
      </div>

      {view === 'tree' ? (
        <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
          {orgs.map((o, oi) => (
            <div key={o.id} className="panel a-up overflow-hidden" style={{ animationDelay: `${oi * 60}ms` }}>
              <div className="panel-hd border-b-0!">
                <span className="flex h-8 w-8 items-center justify-center rounded-lg border border-cyan/40 bg-cyan/10 text-cyan"><Icon name="building" size={15} /></span>
                <div className="min-w-0 flex-1">
                  <div className="truncate text-[13px] font-semibold text-ink">{o.name}</div>
                  <div className="font-mono text-[10px] text-faint">{o.short} · {o.tenants.length} cliente(s)</div>
                </div>
                {o.tenants.length === 0 && (
                  <button className="btn btn-ghost btn-xs hover:text-crit!" title="Remover organização" onClick={() => onDeleteOrg(o)}><Icon name="trash" size={13} /></button>
                )}
              </div>
              <div className="border-t border-line px-4 py-3">
                {o.tenants.length === 0 && <div className="py-2 text-center text-[11px] text-faint">Nenhum cliente vinculado</div>}
                {o.tenants.map(tId => {
                  const t = tenants.find(x => x.id === tId.id);
                  if (!t) return null;
                  return <TenantNode key={t.id} t={t} onEnvs={onEnvs} />;
                })}
              </div>
            </div>
          ))}

          {standalone.length > 0 && (
            <div className="panel a-up overflow-hidden xl:col-span-2" style={{ animationDelay: `${orgs.length * 60}ms` }}>
              <div className="panel-hd border-b-0!">
                <span className="flex h-8 w-8 items-center justify-center rounded-lg border border-line bg-panel2 text-faint"><Icon name="globe" size={15} /></span>
                <div>
                  <div className="text-[13px] font-semibold text-sub">Sem organização</div>
                  <div className="font-mono text-[10px] text-faint">{standalone.length} cliente(s) — sem organização vinculada</div>
                </div>
              </div>
              <div className="grid grid-cols-1 gap-3 border-t border-line px-4 py-3 md:grid-cols-2 xl:grid-cols-3">
                {standalone.map(t => <TenantNode key={t.id} t={t} onEnvs={onEnvs} />)}
              </div>
            </div>
          )}
        </div>
      ) : (
        <div className="panel a-up overflow-x-auto">
          <div className="panel-hd">
            <Icon name="grid" size={14} className="text-teal" />
            <span className="text-[12.5px] font-semibold text-ink">Matriz de isolamento por tenant</span>
            <span className="ml-auto font-mono text-[10px] text-faint">cada cliente enxerga apenas suas próprias linhas</span>
          </div>
          <table className="tbl min-w-[760px]">
            <thead>
              <tr>
                <th className="sticky left-0 z-10 bg-panel">Cliente</th>
                {(isolation[0]?.cells ?? []).map(c => <th key={c.table} className="text-center">{c.label}</th>)}
              </tr>
            </thead>
            <tbody>
              {isolation.map(row => (
                <tr key={row.tenant} className="rowline">
                  <td className="sticky left-0 z-10 bg-panel">
                    <div className="flex items-center gap-2">
                      <span className="h-2 w-2 rounded-full" style={{ background: tenants.find(t => t.id === row.tenant)?.brandColor ?? '#5aa2ff' }} />
                      <span className="text-[12px] font-medium text-ink/90">{row.tenantName}</span>
                    </div>
                  </td>
                  {row.cells.map(c => (
                    <td key={c.table} className="text-center">
                      <span className={`inline-flex min-w-[52px] justify-center rounded-md px-2 py-1 font-mono text-[11px] tabular-nums ${heatText(c.count)}`}
                        style={{ background: heat(c.count) }}>
                        {c.count.toLocaleString('pt-BR')}
                      </span>
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
          <div className="flex items-center gap-2 border-t border-line px-4 py-2.5 font-mono text-[10px] text-faint">
            <span>intensidade = volume de registros</span>
            <span className="ml-auto flex items-center gap-1">
              0 <span className="h-2.5 w-16 rounded-sm" style={{ background: 'linear-gradient(90deg, rgba(47,214,165,0.12), rgba(47,214,165,0.87))' }} /> 10k+
            </span>
          </div>
        </div>
      )}
    </div>
  );
}

function TenantNode({ t, onEnvs }: { t: AdminTenant; onEnvs: (t: AdminTenant) => void }) {
  const brand = t.brandColor ?? '#5aa2ff';
  return (
    <div className="group mb-2 rounded-lg border border-line bg-panel2/60 p-3 transition-all last:mb-0 hover:border-line2">
      <div className="flex items-center gap-2.5">
        <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-md font-display text-[11px] font-bold"
          style={{ background: brand + '1f', color: brand, border: `1px solid ${brand}55` }}>{t.short}</span>
        <div className="min-w-0 flex-1">
          <div className="truncate text-[12.5px] font-medium text-ink/95">{t.name}</div>
          <div className="font-mono text-[10px] text-faint">{t.id} · {t.assets} ativos · {t.users} usuário(s)</div>
        </div>
        <button className="btn btn-ghost btn-xs opacity-0 transition-opacity group-hover:opacity-100" onClick={() => onEnvs(t)} title="Gerenciar ambientes">
          <Icon name="server" size={13} /> {t.environments.length}
        </button>
      </div>
      {t.environments.length > 0 && (
        <div className="mt-2 flex flex-wrap gap-1.5">
          {t.environments.map(e => {
            const k = ENV_KIND[e.kind] ?? { label: e.kind, color: '#8fa3c8' };
            return <Pill key={e.id} label={e.name} color={k.color} sm />;
          })}
        </div>
      )}
      {(t.quotas.maxUsers || t.quotas.maxAssets || t.quotas.maxConnectors) && (
        <div className="mt-2 flex flex-wrap gap-2 font-mono text-[9.5px] text-faint">
          {t.quotas.maxUsers && <span>usuários ≤ {t.quotas.maxUsers}</span>}
          {t.quotas.maxAssets && <span>ativos ≤ {t.quotas.maxAssets}</span>}
          {t.quotas.maxConnectors && <span>connectors ≤ {t.quotas.maxConnectors}</span>}
        </div>
      )}
    </div>
  );
}

function OnboardModal({ open, onClose, orgs, online, onSaved }: {
  open: boolean; onClose: () => void; orgs: Org[]; online: boolean; onSaved: () => void;
}) {
  const [step, setStep] = useState(0);
  const [name, setName] = useState('');
  const [short, setShort] = useState('');
  const [contact, setContact] = useState('');
  const [orgId, setOrgId] = useState('');
  const [brandColor, setBrandColor] = useState('#2fd6a5');
  const [createUser, setCreateUser] = useState(true);
  const [portalPass, setPortalPass] = useState('');
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);

  useEffect(() => { if (open) { setStep(0); setName(''); setShort(''); setContact(''); setOrgId(''); setBrandColor('#2fd6a5'); setCreateUser(true); setPortalPass(''); setErr(''); } }, [open]);

  const submit = async () => {
    setErr('');
    if (!name.trim()) { setErr('Informe o nome do cliente.'); return; }
    if (createUser && online && portalPass.length < 8) { setErr('A senha do portal deve ter ao menos 8 caracteres.'); return; }
    setBusy(true);
    const body = {
      name: name.trim(), short: short.trim() || undefined, contact: contact.trim() || undefined,
      orgId: orgId || undefined, brandColor,
      createPortalUser: createUser, portalPassword: createUser ? portalPass : undefined,
    };
    if (online) {
      const res = await srv.onboard(body);
      if (!res?.ok) { setErr(res?.error ?? 'Falha no onboarding.'); setBusy(false); return; }
    }
    setBusy(false);
    onSaved();
  };

  const steps = ['Cliente', 'Identidade visual', 'Acesso do portal'];
  return (
    <Modal open={open} onClose={onClose} title="Onboarding de cliente" width={520}
      footer={<>
        {step > 0 && <button className="btn btn-xs" onClick={() => setStep(s => s - 1)}><Icon name="chevronLeft" size={12} /> Voltar</button>}
        <button className="btn btn-xs" onClick={onClose}>Cancelar</button>
        {step < 2
          ? <button className="btn btn-primary btn-xs" onClick={() => setStep(s => s + 1)}>Avançar <Icon name="chevronRight" size={12} /></button>
          : <button className="btn btn-primary btn-xs" disabled={busy} onClick={() => void submit()}>{busy ? 'Provisionando…' : <><Icon name="check" size={12} /> Concluir onboarding</>}</button>}
      </>}>
      <div className="mb-4 flex items-center gap-1.5">
        {steps.map((st, i) => (
          <div key={st} className="flex flex-1 items-center gap-1.5">
            <span className={`flex h-5 w-5 shrink-0 items-center justify-center rounded-full text-[10px] font-semibold ${i <= step ? 'bg-teal text-[#04160f]' : 'border border-line2 text-faint'}`}>{i + 1}</span>
            <span className={`text-[10.5px] ${i <= step ? 'text-ink/90' : 'text-faint'}`}>{st}</span>
            {i < 2 && <span className={`h-px flex-1 ${i < step ? 'bg-teal/50' : 'bg-line'}`} />}
          </div>
        ))}
      </div>

      {step === 0 && (
        <div className="flex flex-col gap-3.5">
          <Field label="Nome do cliente *"><input className="input w-full" value={name} onChange={e => setName(e.target.value)} placeholder="Ex.: Acme Corp" autoFocus /></Field>
          <div className="grid grid-cols-2 gap-3">
            <Field label="Sigla (3–4 letras)"><input className="input w-full font-mono uppercase" maxLength={4} value={short} onChange={e => setShort(e.target.value)} placeholder="ACM" /></Field>
            <Field label="Organização">
              <select className="select w-full" value={orgId} onChange={e => setOrgId(e.target.value)}>
                <option value="">— sem organização —</option>
                {orgs.map(o => <option key={o.id} value={o.id}>{o.name}</option>)}
              </select>
            </Field>
          </div>
          <Field label="Contato de segurança"><input className="input w-full" value={contact} onChange={e => setContact(e.target.value)} placeholder="soc@acme.com" /></Field>
          <div className="rounded-md border border-line bg-panel px-3 py-2 text-[10.5px] leading-relaxed text-faint">
            O onboarding cria automaticamente o <span className="text-teal">tenant</span>, o ambiente <span className="text-teal">Produção</span> e (opcional) o usuário do portal.
          </div>
        </div>
      )}

      {step === 1 && (
        <div className="flex flex-col gap-4">
          <Field label="Cor da marca">
            <div className="flex items-center gap-3">
              <input type="color" className="h-9 w-14 cursor-pointer rounded-md border border-line bg-panel" value={brandColor} onChange={e => setBrandColor(e.target.value)} />
              <span className="font-mono text-[11.5px] text-sub">{brandColor}</span>
            </div>
          </Field>
          <div>
            <div className="lbl mb-2">Pré-visualização</div>
            <div className="flex items-center gap-3 rounded-lg border border-line bg-panel2/60 p-3">
              <span className="flex h-9 w-9 items-center justify-center rounded-lg font-display text-[13px] font-bold"
                style={{ background: brandColor + '1f', color: brandColor, border: `1px solid ${brandColor}55` }}>
                {(short || name || 'AC').slice(0, 3).toUpperCase()}
              </span>
              <div>
                <div className="text-[13px] font-semibold" style={{ color: brandColor }}>{name || 'Acme Corp'}</div>
                <div className="font-mono text-[10px] text-faint">Portal do Cliente · Security Score</div>
              </div>
            </div>
          </div>
          <p className="text-[11px] leading-relaxed text-faint">A cor da marca personaliza o Portal do Cliente e os selos do tenant em toda a plataforma.</p>
        </div>
      )}

      {step === 2 && (
        <div className="flex flex-col gap-3.5">
          <div className="flex items-center justify-between rounded-lg border border-line bg-panel px-3 py-2.5">
            <div>
              <div className="text-[12.5px] font-medium text-ink/90">Criar usuário do portal</div>
              <div className="text-[10.5px] text-faint">Perfil Customer, acesso restrito ao próprio tenant</div>
            </div>
            <Toggle on={createUser} onChange={setCreateUser} />
          </div>
          {createUser && (
            <Field label="Senha inicial do portal *">
              <input className="input w-full font-mono" type="text" value={portalPass} onChange={e => setPortalPass(e.target.value)} placeholder="mínimo 8 caracteres" />
            </Field>
          )}
          <div className="rounded-md border border-teal/30 bg-teal/[.06] px-3 py-2.5 text-[11px] leading-relaxed text-sub">
            <span className="font-semibold text-teal">Resumo:</span> tenant <span className="font-mono">{(name || 'acme').toLowerCase().replace(/[^a-z0-9]+/g, '-')}</span> +
            ambiente <span className="text-teal">Produção</span>{createUser ? ' + usuário portal' : ''}. Dados totalmente isolados dos demais clientes.
          </div>
          {err && <div className="flex items-center gap-2 rounded-md border border-crit/40 bg-crit/10 px-3 py-2 text-[11.5px] text-crit"><Icon name="alertTriangle" size={13} /> {err}</div>}
        </div>
      )}
    </Modal>
  );
}

function EnvironmentsModal({ tenant, onClose, online, onSaved }: {
  tenant: AdminTenant | null; onClose: () => void; online: boolean; onSaved: () => void;
}) {
  const [envs, setEnvs] = useState<{ id: string; name: string; kind: string }[]>([]);
  const [name, setName] = useState('');
  const [kind, setKind] = useState('producao');

  useEffect(() => { if (tenant) { setEnvs(tenant.environments); setName(''); setKind('producao'); } }, [tenant]);

  const add = async () => {
    if (!name.trim() || !tenant) return;
    if (online) {
      const res = await srv.createEnvironment(tenant.id, { name: name.trim(), kind });
      if (!res?.ok) return;
    }
    setEnvs(p => [...p, { id: 'ENV-' + Date.now(), name: name.trim(), kind }]);
    setName('');
    onSaved();
  };
  const remove = async (code: string) => {
    if (!tenant) return;
    if (online) await srv.deleteEnvironment(code);
    setEnvs(p => p.filter(e => e.id !== code));
    onSaved();
  };

  return (
    <Modal open={!!tenant} onClose={onClose} title={`Ambientes — ${tenant?.name ?? ''}`} width={480}>
      <div className="flex flex-col gap-2">
        {envs.length === 0 && <div className="py-4 text-center text-[11.5px] text-faint">Nenhum ambiente cadastrado</div>}
        {envs.map(e => {
          const k = ENV_KIND[e.kind] ?? { label: e.kind, color: '#8fa3c8' };
          return (
            <div key={e.id} className="flex items-center gap-2.5 rounded-lg border border-line bg-panel2/60 px-3 py-2.5">
              <span className="h-2 w-2 rounded-full" style={{ background: k.color, boxShadow: `0 0 6px ${k.color}` }} />
              <span className="flex-1 text-[12.5px] font-medium text-ink/90">{e.name}</span>
              <Pill label={k.label} color={k.color} sm />
              <span className="font-mono text-[9.5px] text-faint">{e.id}</span>
              {e.kind !== 'producao' && (
                <button className="btn btn-ghost btn-xs hover:!text-crit" onClick={() => void remove(e.id)} title="Remover ambiente"><Icon name="trash" size={13} /></button>
              )}
            </div>
          );
        })}
        <div className="mt-2 flex gap-2 border-t border-line pt-3">
          <input className="input flex-1" placeholder="Nome do ambiente…" value={name} onChange={e => setName(e.target.value)}
            onKeyDown={ev => { if (ev.key === 'Enter') void add(); }} />
          <select className="select" value={kind} onChange={e => setKind(e.target.value)}>
            {Object.entries(ENV_KIND).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}
          </select>
          <button className="btn btn-primary btn-xs" disabled={!name.trim()} onClick={() => void add()}><Icon name="plus" size={12} /> Adicionar</button>
        </div>
        <p className="text-[10.5px] leading-relaxed text-faint">
          Ambientes particionam eventos, alertas e ativos dentro do tenant (ex.: Produção vs. Laboratório). O ambiente padrão Produção não pode ser removido.
        </p>
      </div>
    </Modal>
  );
}
