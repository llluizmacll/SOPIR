// ─────────────────────────────────────────────────────────────
// SOPIR API · TOTP (RFC 6238) — MFA sem dependências externas
// Compatível com Google Authenticator, Aegis, 1Password etc.
// ─────────────────────────────────────────────────────────────
import crypto from 'crypto';

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Encode(buf) {
  let bits = 0, value = 0, out = '';
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += B32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}

export function base32Decode(str) {
  const clean = str.toUpperCase().replace(/[^A-Z2-7]/g, '');
  let bits = 0, value = 0;
  const out = [];
  for (const ch of clean) {
    value = (value << 5) | B32.indexOf(ch);
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

export function generateSecret() {
  return base32Encode(crypto.randomBytes(20));
}

export function otpauthUri(secret, account, issuer = 'SOPIR') {
  return `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(account)}` +
    `?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
}

function hotp(secretB32, counter) {
  const key = base32Decode(secretB32);
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter));
  const hmac = crypto.createHmac('sha1', key).update(buf).digest();
  const off = hmac[hmac.length - 1] & 0x0f;
  const code = ((hmac[off] & 0x7f) << 24 | hmac[off + 1] << 16 | hmac[off + 2] << 8 | hmac[off + 3]) % 1_000_000;
  return String(code).padStart(6, '0');
}

export function totpNow(secretB32, ts = Date.now()) {
  return hotp(secretB32, Math.floor(ts / 30_000));
}

/** Valida com janela ±1 passo (±30s) para tolerância de clock. */
export function verifyTotp(secretB32, code, window = 1) {
  if (!secretB32 || !/^\d{6}$/.test(String(code ?? ''))) return false;
  const step = Math.floor(Date.now() / 30_000);
  for (let i = -window; i <= window; i++) {
    if (hotp(secretB32, step + i) === String(code)) return true;
  }
  return false;
}

/** Códigos de recuperação (uso único), formato "xxxxx-xxxxx". */
export function generateRecoveryCodes(n = 8) {
  return Array.from({ length: n }, () => {
    const b = crypto.randomBytes(5).toString('hex').slice(0, 10);
    return `${b.slice(0, 5)}-${b.slice(5)}`;
  });
}

export const sha256hex = (s) => crypto.createHash('sha256').update(String(s)).digest('hex');
