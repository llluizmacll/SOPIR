import { useEffect, useState } from 'react';
import { useStore } from '../lib/store';
import type { SessionInfo } from '../lib/api';
import { timeAgo } from '../lib/store';
import { Avatar, Drawer, Icon, Pill } from './ui';
import MfaEnroll from './MfaEnroll';

function parseDevice(ua: string | null): { browser: string; os: string } {
  const u = ua ?? '';
  const browser = /Brave/i.test(u) ? 'Brave' : /Edg\//i.test(u) ? 'Edge' : /Chrome\//i.test(u) ? 'Chrome'
    : /Firefox\//i.test(u) ? 'Firefox' : /Safari\//i.test(u) ? 'Safari' : 'Navegador';
  const os = /Windows/i.test(u) ? 'Windows' : /Mac OS/i.test(u) ? 'macOS' : /Linux/i.test(u) ? 'Linux'
    : /Android/i.test(u) ? 'Android' : /iPhone|iPad/i.test(u) ? 'iOS' : '—';
  return { browser, os };
}

export default function AccountDrawer({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { s, mfaDisable, regenRecoveryCodes, listSessions, revokeSession, revokeOtherSessions, toast, logout } = useStore();
  const user = s.user;

  const [mode, setMode] = useState<'idle' | 'enroll' | 'disable' | 'codes'>('idle');
  const [codes, setCodes] = useState<string[]>([]);
  const [disableCode, setDisableCode] = useState('');
  const [disableErr, setDisableErr] = useState('');
  const [sessions, setSessions] = useState<SessionInfo[]>([]);
  const [loadingSess, setLoadingSess] = useState(false);

  const mfaEnabled = !!user?.mfaEnabled || (typeof localStorage !== 'undefined' && !!user && !!localStorage.getItem('sopir.demo.mfa.' + user.username));

  useEffect(() => {
    if (!open) return;
    setMode('idle'); setCodes([]); setDisableCode(''); setDisableErr('');
    setLoadingSess(true);
    void listSessions().then(list => { setSessions(list); setLoadingSess(false); });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  const doDisable = async () => {
    setDisableErr('');
    const res = await mfaDisable(disableCode);
    if (!res.ok) { setDisableErr(res.error ?? 'Código inválido.'); return; }
    toast('ok', 'MFA desativado');
    setMode('idle');
  };

  const doRegen = async () => {
    const c = await regenRecoveryCodes();
    setCodes(c);
    toast('ok', 'Novos códigos gerados — os anteriores foram invalidados');
  };

  const copyAll = async () => {
    try {
      await navigator.clipboard.writeText(codes.join('\n'));
      toast('ok', 'Códigos copiados');
    } catch { toast('err', 'Não foi possível copiar'); }
  };

  return (
    <Drawer open={open} onClose={onClose} width={520}
      title={<span className="flex items-center gap-2.5"><Icon name="key" size={16} className="text-teal" /> Minha conta · segurança</span>}
      sub={user ? (<><Avatar name={user.name} size={20} /><span>{user.name}</span><Pill label={user.role} color="#2fd6a5" sm /></>) : undefined}>

      {/* ── MFA ── */}
      <section className="panel p-4">
        <div className="flex items-center gap-2.5">
          <span className={`flex h-8 w-8 items-center justify-center rounded-lg border ${mfaEnabled ? 'border-teal/50 bg-teal/10 text-teal' : 'border-line bg-panel2 text-faint'}`}>
            <Icon name="shieldCheck" size={15} />
          </span>
          <div className="min-w-0 flex-1">
            <div className="text-[13px] font-semibold text-ink">Autenticação em dois fatores (TOTP)</div>
            <div className="text-[11px] text-faint">Google Authenticator, Aegis, 1Password…</div>
          </div>
          {mfaEnabled
            ? <Pill label="Ativo" color="#2fd6a5" />
            : <Pill label="Desativado" color="#8fa3c8" />}
        </div>

        {mode === 'idle' && (
          <div className="mt-3.5 flex gap-2">
            {!mfaEnabled && (
              <button className="btn btn-primary btn-xs" onClick={() => setMode('enroll')}>
                <Icon name="plus" size={12} /> Configurar MFA
              </button>
            )}
            {mfaEnabled && (
              <>
                <button className="btn btn-xs" onClick={() => void doRegen()}>
                  <Icon name="refresh" size={12} /> Códigos de recuperação
                </button>
                <button className="btn btn-danger btn-xs" onClick={() => setMode('disable')}>
                  <Icon name="x" size={12} /> Desativar
                </button>
              </>
            )}
          </div>
        )}

        {mode === 'enroll' && (
          <div className="mt-4 border-t border-line pt-4">
            <MfaEnroll
              onDone={rc => {
                setMode('idle');
                if (rc?.length) { setCodes(rc); setMode('codes'); }
                toast('ok', 'MFA ativado com sucesso');
              }}
              onCancel={() => setMode('idle')}
            />
          </div>
        )}

        {mode === 'disable' && (
          <div className="mt-4 border-t border-line pt-4">
            <div className="lbl mb-1.5">Digite um código atual para confirmar a desativação</div>
            <div className="flex gap-2">
              <input className="input flex-1 text-center font-mono tracking-[0.3em]" placeholder="000000" maxLength={6}
                value={disableCode} onChange={e => setDisableCode(e.target.value.replace(/\D/g, '').slice(0, 6))} />
              <button className="btn btn-danger btn-xs" onClick={() => void doDisable()}><Icon name="x" size={12} /> Confirmar</button>
              <button className="btn btn-ghost btn-xs" onClick={() => setMode('idle')}>Voltar</button>
            </div>
            {disableErr && <div className="mt-2 text-[11.5px] text-crit">{disableErr}</div>}
          </div>
        )}

        {mode === 'codes' && codes.length > 0 && (
          <div className="a-pop mt-4 border-t border-line pt-4">
            <div className="flex items-center gap-2">
              <span className="text-med"><Icon name="alertTriangle" size={14} /></span>
              <span className="text-[12.5px] font-semibold text-ink">Códigos de recuperação — guarde em local seguro</span>
            </div>
            <p className="mt-1 text-[11px] text-faint">Cada código funciona uma única vez, caso você perca o autenticador. Eles não serão exibidos novamente.</p>
            <div className="mt-3 grid grid-cols-2 gap-1.5">
              {codes.map(c => (
                <div key={c} className="rounded-md border border-line bg-input-bg px-3 py-1.5 text-center font-mono text-[12px] tracking-wider text-teal">{c}</div>
              ))}
            </div>
            <div className="mt-3 flex gap-2">
              <button className="btn btn-xs" onClick={() => void copyAll()}><Icon name="copy" size={12} /> Copiar todos</button>
              <button className="btn btn-primary btn-xs" onClick={() => { setCodes([]); setMode('idle'); }}>
                <Icon name="check" size={12} /> Guardei os códigos
              </button>
            </div>
          </div>
        )}
      </section>

      {/* ── Sessões ── */}
      <section className="panel mt-4 p-4">
        <div className="flex items-center gap-2.5">
          <span className="flex h-8 w-8 items-center justify-center rounded-lg border border-line bg-panel2 text-cyan">
            <Icon name="monitor" size={15} />
          </span>
          <div className="min-w-0 flex-1">
            <div className="text-[13px] font-semibold text-ink">Sessões ativas</div>
            <div className="text-[11px] text-faint">Dispositivos autenticados com sua conta</div>
          </div>
          {sessions.some(x => !x.current && !x.revoked) && (
            <button className="btn btn-xs" onClick={() => { void revokeOtherSessions(); void listSessions().then(setSessions); }}>
              Encerrar outras
            </button>
          )}
        </div>

        <div className="mt-3.5 flex flex-col gap-2">
          {loadingSess && <div className="py-3 text-center text-[11.5px] text-faint">carregando sessões…</div>}
          {!loadingSess && sessions.length === 0 && <div className="py-3 text-center text-[11.5px] text-faint">Nenhuma sessão registrada.</div>}
          {!loadingSess && sessions.filter(x => !x.revoked).map(sn => {
            const dev = parseDevice(sn.ua);
            return (
              <div key={sn.id} className={`flex items-center gap-3 rounded-lg border px-3 py-2.5 ${sn.current ? 'border-teal/40 bg-teal/[.05]' : 'border-line bg-panel'}`}>
                <span className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-md border ${sn.current ? 'border-teal/50 text-teal' : 'border-line text-sub'}`}>
                  <Icon name={dev.os === 'Android' || dev.os === 'iOS' ? 'send' : 'monitor'} size={14} />
                </span>
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <span className="text-[12px] font-medium text-ink/90">{dev.browser} · {dev.os}</span>
                    {sn.current && <Pill label="sessão atual" color="#2fd6a5" sm />}
                  </div>
                  <div className="mt-0.5 font-mono text-[10px] text-faint">
                    {sn.ip ?? 'ip não registrado'} · vista {sn.lastSeen ? timeAgo(sn.lastSeen) : 'agora'} · expira {timeAgo(sn.expires).replace('há', 'em')}
                  </div>
                </div>
                {!sn.current && (
                  <button className="btn btn-ghost btn-xs hover:border-crit/50! hover:text-crit!"
                    onClick={() => { void revokeSession(sn.id).then(ok => { if (ok) setSessions(p => p.filter(x => x.id !== sn.id)); }); }}>
                    <Icon name="power" size={12} /> Encerrar
                  </button>
                )}
              </div>
            );
          })}
        </div>
      </section>

      {/* ── rodapé ── */}
      <div className="mt-4 flex items-center justify-between rounded-lg border border-line/70 bg-panel/60 px-3.5 py-2.5">
        <span className="font-mono text-[10px] text-faint">conta: {user?.username}</span>
        <button className="btn btn-danger btn-xs" onClick={() => { onClose(); logout(); }}>
          <Icon name="power" size={12} /> Encerrar sessão
        </button>
      </div>
    </Drawer>
  );
}
