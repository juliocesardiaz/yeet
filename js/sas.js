// Short Authentication String (SAS) — sole authentication mechanism for the
// post-DTLS handshake. Pure functions, no DOM or RTC dependencies.

const SAS_INFO_PREFIX = new TextEncoder().encode('YEET-SAS-v1');

// "AB:CD:EF:..." -> Uint8Array(32). Hyphens, spaces, lowercase all accepted.
export function parseHexFingerprint(fpString) {
  const cleaned = fpString.replace(/[\s:-]/g, '').toLowerCase();
  if (cleaned.length !== 64) {
    throw new Error(`fingerprint must be 32 bytes (64 hex chars), got ${cleaned.length}`);
  }
  if (!/^[0-9a-f]+$/.test(cleaned)) {
    throw new Error('fingerprint contains non-hex characters');
  }
  const bytes = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    bytes[i] = parseInt(cleaned.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

function bytesCompareUnsigned(a, b) {
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i++) {
    if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1;
  }
  return a.length - b.length;
}

function concatBytes(...arrays) {
  const total = arrays.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) { out.set(a, off); off += a.length; }
  return out;
}

// HKDF-SHA256 over (fp_lo || fp_hi) with info = "YEET-SAS-v1" || nonce.
// Output: 24 bits, low 20 bits -> 6-digit zero-padded decimal, displayed "XXX XXX".
export async function computeSAS(fpLocalString, fpRemoteString, nonceBytes) {
  if (!(nonceBytes instanceof Uint8Array) || nonceBytes.length !== 2) {
    throw new Error('nonce must be Uint8Array(2)');
  }

  const fpLocal = parseHexFingerprint(fpLocalString);
  const fpRemote = parseHexFingerprint(fpRemoteString);

  if (bytesEqual(fpLocal, fpRemote)) {
    throw new Error('identical fingerprints — bug or replay attack');
  }

  const cmp = bytesCompareUnsigned(fpLocal, fpRemote);
  const fpLo = cmp < 0 ? fpLocal : fpRemote;
  const fpHi = cmp < 0 ? fpRemote : fpLocal;

  const ikm = concatBytes(fpLo, fpHi);
  const info = concatBytes(SAS_INFO_PREFIX, nonceBytes);

  const ikmKey = await crypto.subtle.importKey(
    'raw',
    ikm,
    { name: 'HKDF' },
    false,
    ['deriveBits'],
  );

  const okmBuf = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new Uint8Array(0),
      info,
    },
    ikmKey,
    24, // bits
  );

  const okm = new Uint8Array(okmBuf);
  const sasInt = ((okm[0] << 16) | (okm[1] << 8) | okm[2]) & 0x0FFFFF;
  const sasStr = sasInt.toString(10).padStart(6, '0');
  return sasStr.slice(0, 3) + ' ' + sasStr.slice(3, 6);
}
