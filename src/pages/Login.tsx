import { useEffect, useState } from 'react';
import type { FormEvent } from 'react';
import { DEMO_USERS } from '../data/mock';
import { api as srv } from '../lib/api';
import type { SsoProviderPublic } from '../lib/api';
import { useStore } from '../lib/store';
import { Icon } from '../components/icons';
import MfaEnroll from '../components/MfaEnroll';

const STAGES = [
  { icon: 'radar', label: 'Detectar', desc: 'Wazuh · FortiSIEM · EDR' },
  { icon: 'crosshair', label: 'Correlacionar', desc: 'políticas por padrão' },
  { icon: 'flame', label: 'Responder', desc: 'playbooks com aprovação' },
  { icon: 'bug', label: 'Remediar', desc: 'vulns → patch → validação' },
];

type Step = 'creds' | 'mfa' | 'enroll' | 'codes';

export default function Login() {
  const { s, login, verifyMfa, applySsoToken, forgotPassword, resetPasswordToken, toast } = useStore();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [shake, setShake] = useState(0);

  const [step, setStep] = useState<Step>('creds');
  const [mfaToken, setMfaToken] = useState('');
  const [mfaUser, setMfaUser] = useState('');
  const [code, setCode] = useState('');
  const [recoveryCodes, setRecoveryCodes] = useState<string[]>([]);

  const [ssoProviders, setSsoProviders] = useState<SsoProviderPublic[]>([]);
  const [forgot, setForgot] = useState(false);
  const [fgUser, setFgUser] = useState('');
  const [fgToken, setFgToken] = useState('');
  const [fgPass, setFgPass] = useState('');
  const [fgMsg, setFgMsg] = useState('');

  // retorno do SSO: #sso=<token> ou #sso_error=<msg>
  useEffect(() => {
    const hash = window.location.hash;
    if (hash.startsWith('#sso=')) {
      const token = decodeURIComponent(hash.slice(5));
      window.history.replaceState(null, '', window.location.pathname);
      void applySsoToken(token).then(ok => {
        if (!ok) setError('SSO: token inválido. Tente novamente.');
      });
    } else if (hash.startsWith('#sso_error=')) {
      setError('SSO: ' + decodeURIComponent(hash.slice(11)));
      window.history.replaceState(null, '', window.location.pathname);
    }
    // provedores SSO habilitados
    if (s.backend === 'online') {
      void srv.ssoProviders().then(list => setSsoProviders(list ?? []));
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [s.backend]);

  const submit = async (e?: FormEvent, u?: string, p?: string) => {
    e?.preventDefault();
    const user = u ?? username;
    const pass = p ?? password;
    if (!user || !pass) { setError('Informe usuário e senha.'); setShake(x => x + 1); return; }
    setBusy(true);
    setError('');
    try {
      const res = await login(user, pass);
      if (res.ok) return;
      if (res.mfa === 'verify') {
        setMfaToken(res.mfaToken ?? ''); setMfaUser(res.username ?? user); setCode(''); setStep('mfa'); return;
      }
      if (res.mfa === 'enroll') {
        setMfaToken(res.mfaToken ?? ''); setMfaUser(res.username ?? user); setStep('enroll'); return;
      }
      setError(res.error ?? 'Falha na autenticação.');
      setShake(x => x + 1);
    } catch {
      setError('Falha inesperada na autenticação.');
      setShake(x => x + 1);
    } finally {
      setBusy(false);
    }
  };

  const submitMfa = async () => {
    setError('');
    if (!/^\d{6}$/.test(code) && !/^[a-z0-9]{5}-[a-z0-9]{5}$/i.test(code)) {
      setError('Digite o código de 6 dígitos (ou um código de recuperação).');
      setShake(x => x + 1); return;
    }
    setBusy(true);
    try {
      const res = await verifyMfa(mfaToken, code);
      if (!res.ok) { setError(res.error ?? 'Código inválido.'); setShake(x => x + 1); }
    } finally {
      setBusy(false);
    }
  };

  const submitForgot = async () => {
    setFgMsg('');
    if (!fgUser.trim()) { setFgMsg('Informe o usuário.'); return; }
    const res = await forgotPassword(fgUser.trim());
    if (res.devToken) {
      setFgToken(res.devToken);
      setFgMsg('');
    } else {
      setFgMsg('Se a conta existir, um token de recuperação foi gerado (veja os logs da API em produção).');
    }
  };

  const submitReset = async () => {
    setFgMsg('');
    if (!fgToken.trim() || !fgPass) { setFgMsg('Informe o token e a nova senha.'); return; }
    const res = await resetPasswordToken(fgToken.trim(), fgPass);
    if (!res.ok) { setFgMsg(res.error ?? 'Falha ao redefinir.'); return; }
    toast('ok', 'Senha redefinida — entre com a nova senha');
    setForgot(false); setFgToken(''); setFgPass(''); setFgUser('');
  };

  const stepTitle = {
    creds: 'Acessar a plataforma',
    mfa: 'Verificação em duas etapas',
    enroll: 'Ative a verificação em duas etapas',
    codes: 'Códigos de recuperação',
  }[step];

  return (
    <div className="relative z-10 flex h-full">
      <div className="ambient" />

      {/* ── painel institucional ── */}
      <aside className="relative hidden flex-1 flex-col justify-between overflow-hidden border-r border-line bg-[#0a1120]/80 p-10 lg:flex">
        <div>
          <div className="flex items-center gap-3">
            <div className="relative flex h-11 w-11 items-center justify-center rounded-xl border border-teal/40 bg-teal/10 text-teal">
              <Icon name="shieldCheck" size={24} strokeWidth={2} />
              <svg className="sweep absolute inset-0" viewBox="0 0 44 44">
                <circle cx="22" cy="22" r="20" fill="none" stroke="url(#swl)" strokeWidth="1.4" />
                <defs>
                  <linearGradient id="swl" x1="0" y1="0" x2="1" y2="0">
                    <stop offset="0%" stopColor="#2fd6a5" stopOpacity="0" />
                    <stop offset="100%" stopColor="#2fd6a5" stopOpacity="0.85" />
                  </linearGradient>
                </defs>
              </svg>
            </div>
            <div>
              <div className="font-display text-[24px] font-bold tracking-[0.1em] text-ink">SOPIR</div>
              <div className="text-[10px] font-mono uppercase tracking-[0.18em] text-faint">Security Ops · IR Platform</div>
            </div>
          </div>

          <h1 className="a-up mt-12 max-w-[420px] font-display text-[34px] font-bold leading-[1.12] text-ink" style={{ animationDelay: '80ms' }}>
            Da detecção à postura de segurança,
            <span className="text-teal"> em um único lugar.</span>
          </h1>
          <p className="a-up mt-4 max-w-[400px] text-[13.5px] leading-relaxed text-sub" style={{ animationDelay: '160ms' }}>
            O SOPIR conecta seus SIEMs e EDRs, transforma eventos em incidentes e cases,
            executa respostas com aprovação e acompanha a remediação até a resolução.
          </p>
        </div>

        <div className="a-up grid grid-cols-4 gap-3" style={{ animationDelay: '240ms' }}>
          {STAGES.map((st, i) => (
            <div key={st.label} className="group rounded-xl border border-line bg-panel/70 p-4 transition-all hover:border-teal/40 hover:bg-panel">
              <div className="flex items-center gap-2">
                <span className="text-teal"><Icon name={st.icon} size={16} /></span>
                <span className="h-1.5 w-1.5 rounded-full bg-teal dot-live" style={{ animationDelay: `${i * 0.3}s` }} />
              </div>
              <div className="mt-2.5 font-display text-[13px] font-semibold text-ink">{st.label}</div>
              <div className="mt-0.5 text-[10.5px] leading-snug text-faint">{st.desc}</div>
            </div>
          ))}
        </div>

        <div className="a-up flex items-center gap-5 font-mono text-[10.5px] text-faint" style={{ animationDelay: '320ms' }}>
          <span className="flex items-center gap-1.5"><span className="h-1.5 w-1.5 rounded-full bg-teal dot-live" /> pipeline ativo</span>
          <span>JWT + MFA + SSO</span>
          <span>sessões revogáveis</span>
          <span className="ml-auto">RBAC · auditoria</span>
        </div>
      </aside>

      {/* ── formulário ── */}
      <main className="flex w-full flex-col items-center justify-center px-6 lg:w-[500px] lg:shrink-0">
        <div key={shake} className={`a-up w-full max-w-[400px] ${shake ? 'shake' : ''}`}>
          <div className="mb-7 lg:hidden">
            <div className="flex items-center gap-2.5">
              <span className="flex h-9 w-9 items-center justify-center rounded-lg border border-teal/40 bg-teal/10 text-teal"><Icon name="shieldCheck" size={18} /></span>
              <span className="font-display text-[19px] font-bold tracking-[0.1em] text-ink">SOPIR</span>
            </div>
          </div>

          {/* indicador de etapas */}
          <div className="mb-4 flex items-center gap-2">
            {(['creds', 'mfa'] as Step[]).map((st, i) => {
              const activeIdx = step === 'creds' ? 0 : 1;
              return (
                <span key={st} className={`h-1 flex-1 rounded-full transition-colors ${i <= activeIdx ? 'bg-teal' : 'bg-line'}`} />
              );
            })}
          </div>

          <div className="panel p-7">
            <h2 className="font-display text-[17px] font-bold text-ink">{stepTitle}</h2>
            <p className="mt-1 text-[12px] text-faint">
              {step === 'creds' && (s.backend === 'online'
                ? <span className="flex items-center gap-1.5 text-teal"><span className="h-1.5 w-1.5 rounded-full bg-teal dot-live" /> autenticando via sopir-api (JWT + sessões)</span>
                : s.backend === 'demo'
                  ? <span className="flex items-center gap-1.5 text-high"><span className="h-1.5 w-1.5 rounded-full bg-high" /> modo demonstração — validação local</span>
                  : <span className="text-faint">verificando conexão…</span>)}
              {step === 'mfa' && <>Conta <span className="font-mono text-sub">{mfaUser}</span> · use o código do autenticador ou um código de recuperação.</>}
              {step === 'enroll' && <>Seu perfil exige MFA. Escaneie o QR e confirme para concluir o acesso de <span className="font-mono text-sub">{mfaUser}</span>.</>}
              {step === 'codes' && 'Guarde estes códigos — eles substituem o autenticador se você o perder.'}
            </p>

            {/* ── credenciais ── */}
            {step === 'creds' && (
              <>
                <form className="mt-5 flex flex-col gap-3.5" onSubmit={submit}>
                  <div>
                    <label className="lbl mb-1.5 block" htmlFor="user">Usuário</label>
                    <div className="relative">
                      <span className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-faint"><Icon name="user" size={14} /></span>
                      <input id="user" className="input w-full pl-9" placeholder="nome.sobrenome" autoComplete="username"
                        value={username} onChange={e => setUsername(e.target.value)} />
                    </div>
                  </div>
                  <div>
                    <label className="lbl mb-1.5 block" htmlFor="pass">Senha</label>
                    <div className="relative">
                      <span className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-faint"><Icon name="lock" size={14} /></span>
                      <input id="pass" type="password" className="input w-full pl-9" placeholder="••••••••" autoComplete="current-password"
                        value={password} onChange={e => setPassword(e.target.value)} />
                    </div>
                  </div>

                  {error && (
                    <div className="flex items-center gap-2 rounded-md border border-crit/40 bg-crit/10 px-3 py-2 text-[11.5px] text-crit">
                      <Icon name="alertTriangle" size={13} /> {error}
                    </div>
                  )}

                  <button type="submit" className="btn btn-primary w-full py-2.5! text-[13px]" disabled={busy}>
                    {busy ? <span className="inline-block h-3.5 w-3.5 animate-spin rounded-full border-2 border-[#04160f]/30 border-t-[#04160f]" /> : <Icon name="chevronRight" size={14} />}
                    {busy ? 'Autenticando…' : 'Entrar no SOC'}
                  </button>
                </form>

                <button className="mt-2.5 self-start text-[11.5px] text-faint transition-colors hover:text-cyan" onClick={() => { setForgot(true); setFgUser(username); }}>
                  Esqueci minha senha
                </button>

                {ssoProviders.length > 0 && (
                  <div className="mt-4 border-t border-line pt-4">
                    <div className="lbl mb-2.5">Entrar com provedor de identidade (SSO)</div>
                    <div className="flex flex-col gap-1.5">
                      {ssoProviders.map(p => (
                        <a key={p.code} href={`${window.location.origin}/api/v1/auth/sso/${p.code}/start`}
                          className="flex items-center gap-2.5 rounded-md border border-line bg-panel2 px-3 py-2 text-[12.5px] font-medium text-ink/90 transition-all hover:border-cyan/50 hover:bg-raise">
                          <Icon name="globe" size={13} className="text-cyan" /> {p.name}
                          <span className="ml-auto font-mono text-[9.5px] uppercase text-faint">OIDC</span>
                        </a>
                      ))}
                    </div>
                  </div>
                )}

                <div className="mt-4 border-t border-line pt-4">
                  <div className="lbl mb-2.5">Contas de demonstração · senha <span className="font-mono text-teal">sopir</span></div>
                  <div className="flex flex-col gap-1.5">
                    {DEMO_USERS.map(u => (
                      <button key={u.username} type="button" onClick={() => { setUsername(u.username); setPassword(u.password); void submit(undefined, u.username, u.password); }}
                        className="flex items-center gap-2.5 rounded-md border border-line bg-panel2 px-3 py-2 text-left transition-all hover:border-teal/50 hover:bg-raise">
                        <Icon name={u.role === 'Customer' ? 'globe' : u.role === 'Admin' ? 'shield' : 'user'} size={13} className="text-sub" />
                        <span className="text-[12px] font-medium text-ink/90">{u.name}</span>
                        <span className="ml-auto rounded bg-raise px-1.5 py-0.5 font-mono text-[9.5px] uppercase tracking-wide text-faint">{u.role}</span>
                      </button>
                    ))}
                  </div>
                </div>
              </>
            )}

            {/* ── MFA ── */}
            {step === 'mfa' && (
              <div className="mt-5 flex flex-col gap-3.5">
                <input
                  className="input w-full py-3 text-center font-mono text-[20px] tracking-[0.5em]"
                  placeholder="••••••" maxLength={6} inputMode="numeric" autoFocus
                  value={code}
                  onChange={e => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                  onKeyDown={e => { if (e.key === 'Enter') void submitMfa(); }}
                />
                {error && (
                  <div className="flex items-center gap-2 rounded-md border border-crit/40 bg-crit/10 px-3 py-2 text-[11.5px] text-crit">
                    <Icon name="alertTriangle" size={13} /> {error}
                  </div>
                )}
                <button className="btn btn-primary w-full py-2.5!" disabled={busy} onClick={() => void submitMfa()}>
                  {busy ? <span className="inline-block h-3.5 w-3.5 animate-spin rounded-full border-2 border-[#04160f]/30 border-t-[#04160f]" /> : <Icon name="check" size={14} />}
                  Verificar código
                </button>
                <button className="btn btn-ghost btn-xs self-center" onClick={() => { setStep('creds'); setError(''); }}>
                  ← voltar para credenciais
                </button>
              </div>
            )}

            {/* ── matrícula MFA obrigatória ── */}
            {step === 'enroll' && (
              <div className="mt-5">
                <MfaEnroll mfaToken={mfaToken}
                  onDone={rc => {
                    if (rc?.length) { setRecoveryCodes(rc); setStep('codes'); }
                  }}
                  onCancel={() => setStep('creds')}
                />
              </div>
            )}

            {/* ── códigos de recuperação (pós-matrícula) ── */}
            {step === 'codes' && (
              <div className="mt-5">
                <div className="grid grid-cols-2 gap-1.5">
                  {recoveryCodes.map(c => (
                    <div key={c} className="rounded-md border border-line bg-[#0a1322] px-3 py-1.5 text-center font-mono text-[12px] tracking-wider text-teal">{c}</div>
                  ))}
                </div>
                <button className="btn btn-primary mt-4 w-full py-2.5!" onClick={() => {
                  void navigator.clipboard.writeText(recoveryCodes.join('\n')).catch(() => {});
                  toast('ok', 'Códigos copiados — sessão iniciada');
                }}>
                  <Icon name="copy" size={13} /> Copiar e entrar
                </button>
              </div>
            )}
          </div>

          <p className="mt-4 text-center font-mono text-[10px] text-faint">
            JWT com sessão revogável · MFA TOTP · SSO/OIDC · trilha de auditoria
          </p>
        </div>
      </main>

      {/* ── recuperação de senha ── */}
      {forgot && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
          <div className="absolute inset-0 bg-[#04070d]/72" onClick={() => setForgot(false)} />
          <div className="a-pop relative panel w-full max-w-[420px] p-6">
            <div className="flex items-center gap-2.5">
              <span className="text-cyan"><Icon name="key" size={17} /></span>
              <h3 className="font-display text-[15px] font-bold text-ink">Recuperar acesso</h3>
              <button className="btn btn-ghost btn-xs ml-auto" onClick={() => setForgot(false)}><Icon name="x" size={14} /></button>
            </div>

            {!fgToken ? (
              <div className="mt-4 flex flex-col gap-3">
                <p className="text-[12px] text-faint">Informe seu usuário. Se a conta existir, geraremos um token de recuperação (30 min, uso único).</p>
                <input className="input w-full" placeholder="nome.sobrenome" value={fgUser} onChange={e => setFgUser(e.target.value)} />
                {fgMsg && <div className="rounded-md border border-line bg-panel px-3 py-2 text-[11.5px] text-sub">{fgMsg}</div>}
                <button className="btn btn-primary" onClick={() => void submitForgot()}>Gerar token</button>
              </div>
            ) : (
              <div className="mt-4 flex flex-col gap-3">
                <div className="rounded-md border border-cyan/40 bg-cyan/[.07] px-3 py-2.5">
                  <div className="lbl mb-1" style={{ color: '#56c4ff' }}>Token de recuperação (dev/demo)</div>
                  <div className="max-h-[72px] overflow-auto break-all font-mono text-[10.5px] leading-relaxed text-cyan/90">{fgToken}</div>
                  <p className="mt-1.5 text-[10px] text-faint">Em produção com SMTP, o link vai por e-mail e este campo não aparece.</p>
                </div>
                <input className="input w-full" type="password" placeholder="Nova senha" value={fgPass} onChange={e => setFgPass(e.target.value)} />
                {fgMsg && <div className="rounded-md border border-crit/40 bg-crit/10 px-3 py-2 text-[11.5px] text-crit">{fgMsg}</div>}
                <button className="btn btn-primary" onClick={() => void submitReset()}>Redefinir senha</button>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
