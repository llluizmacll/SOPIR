import { useEffect, useMemo, useState } from 'react';
import qrcode from 'qrcode-generator';
import { useStore } from '../lib/store';
import { Icon } from './icons';

/**
 * Matrícula MFA (TOTP): QR code + chave manual + validação do 1º código.
 * Usado no login (matrícula obrigatória) e em Minha Conta.
 */
export default function MfaEnroll({ mfaToken, onDone, onCancel }: {
  mfaToken?: string;
  onDone: (recoveryCodes?: string[]) => void;
  onCancel?: () => void;
}) {
  const { mfaSetup, mfaEnable } = useStore();
  const [secret, setSecret] = useState('');
  const [otpauth, setOtpauth] = useState('');
  const [code, setCode] = useState('');
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    void mfaSetup(mfaToken).then(res => {
      setSecret(res.secret ?? '');
      setOtpauth(res.otpauth ?? '');
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [mfaToken]);

  const qrUrl = useMemo(() => {
    if (!otpauth) return '';
    try {
      const qr = qrcode(0, 'M');
      qr.addData(otpauth);
      qr.make();
      return qr.createDataURL(4, 2);
    } catch {
      return '';
    }
  }, [otpauth]);

  const verify = async () => {
    setErr('');
    if (!/^\d{6}$/.test(code)) { setErr('Digite o código de 6 dígitos do aplicativo.'); return; }
    setBusy(true);
    try {
      const res = await mfaEnable(code, mfaToken);
      if (!res.ok) { setErr(res.error ?? 'Código inválido.'); return; }
      onDone(res.recoveryCodes);
    } finally {
      setBusy(false);
    }
  };

  const copySecret = async () => {
    try {
      await navigator.clipboard.writeText(secret);
      setCopied(true);
      setTimeout(() => setCopied(false), 1600);
    } catch { /* clipboard indisponível */ }
  };

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-start gap-4">
        <div className="a-pop shrink-0 rounded-lg bg-white p-2 shadow-[0_0_30px_rgba(47,214,165,0.15)]">
          {qrUrl
            ? <img src={qrUrl} alt="QR code para o aplicativo autenticador" className="h-[124px] w-[124px]" />
            : <div className="flex h-[124px] w-[124px] items-center justify-center text-[10px] text-[#5b7099]">gerando…</div>}
        </div>
        <div className="min-w-0 flex-1">
          <div className="lbl mb-1.5">1 · Escaneie com seu autenticador</div>
          <p className="text-[11.5px] leading-relaxed text-sub">
            Google Authenticator, Aegis, 1Password, Microsoft Authenticator — qualquer app TOTP.
          </p>
          <div className="lbl mb-1 mt-3">Chave manual (sem câmera?)</div>
          <button onClick={() => void copySecret()}
            className="group flex w-full items-center gap-2 rounded-md border border-line bg-[#0a1322] px-2.5 py-1.5 text-left transition-colors hover:border-teal/50">
            <span className="truncate font-mono text-[11px] tracking-wider text-teal">{secret || '…'}</span>
            <span className="ml-auto shrink-0 text-faint group-hover:text-teal">
              <Icon name={copied ? 'check' : 'copy'} size={12} />
            </span>
          </button>
        </div>
      </div>

      <div>
        <div className="lbl mb-1.5">2 · Confirme com o código gerado</div>
        <div className="flex gap-2">
          <input
            className="input flex-1 text-center font-mono text-[16px] tracking-[0.4em]"
            placeholder="000000" maxLength={6} inputMode="numeric" autoFocus
            value={code}
            onChange={e => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
            onKeyDown={e => { if (e.key === 'Enter') void verify(); }}
          />
          <button className="btn btn-primary" disabled={busy} onClick={() => void verify()}>
            {busy ? <span className="inline-block h-3.5 w-3.5 animate-spin rounded-full border-2 border-[#04160f]/30 border-t-[#04160f]" /> : <Icon name="check" size={13} />}
            Validar
          </button>
        </div>
        {err && (
          <div className="mt-2 flex items-center gap-2 rounded-md border border-crit/40 bg-crit/10 px-3 py-2 text-[11.5px] text-crit">
            <Icon name="alertTriangle" size={13} /> {err}
          </div>
        )}
      </div>

      {onCancel && (
        <button className="btn btn-ghost btn-xs self-start" onClick={onCancel}>Cancelar</button>
      )}
    </div>
  );
}
