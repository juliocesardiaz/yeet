import { WORDLIST } from './wordlist.js';

// Build reverse lookup once
const WORD_INDEX = new Map(WORDLIST.map((w, i) => [w, i]));
const BITS_PER_WORD = 12; // 4096-word list

// Wire format version. Bump this on any change to the packed layout, the SAS
// HKDF inputs, the SAS extraction rule, or the wordlist. Parser rejects any
// other value with an "update YEET" error. See ANALYSIS.md and SECURITY.md.
export const PROTOCOL_VERSION = 0x01;

export class UnknownVersionError extends Error {
  constructor(version) {
    super(`unknown passcode version 0x${version.toString(16).padStart(2, '0')} — both people need to be on the same version of YEET`);
    this.name = 'UnknownVersionError';
    this.version = version;
  }
}

// --- Public API ---

// Initiator (the side showing the passcode) generates the nonce and embeds it
// in the offer code. Joiner parses it out and reuses it for HKDF so both sides
// feed identical info into the SAS computation.
export function generateNonce() {
  const out = new Uint8Array(2);
  crypto.getRandomValues(out);
  return out;
}

export async function compress(sdpString, nonceBytes) {
  if (!(nonceBytes instanceof Uint8Array) || nonceBytes.length !== 2) {
    throw new Error('compress: nonceBytes must be Uint8Array(2)');
  }
  const fields = extractSDP(sdpString);
  const packed = packSDP(fields, nonceBytes);
  const compressed = await deflate(packed);

  // Use whichever is shorter; high bit in header word indicates deflate
  if (compressed.length < packed.length) {
    return bytesToWords(compressed, true);
  }
  return bytesToWords(packed, false);
}

export async function decompress(wordString) {
  const { bytes, deflated } = wordsToBytes(wordString);
  const packed = deflated ? await inflate(bytes) : bytes;
  const { fields, nonce } = unpackSDP(packed);
  const sdp = await reconstructSDP(fields);
  return { sdp, nonce };
}

// Derive ICE credentials deterministically from DTLS fingerprint.
// Both peers derive the same ufrag/pwd from the fingerprint, so we
// don't need to transmit them — saving ~28 bytes per code.
export async function deriveCredentials(fingerprintBytes) {
  const prefix = new Uint8Array([0x59, 0x45, 0x45, 0x54]); // "YEET"
  const input = new Uint8Array(prefix.length + fingerprintBytes.length);
  input.set(prefix);
  input.set(fingerprintBytes, prefix.length);

  const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', input));
  const hex = Array.from(hash, b => b.toString(16).padStart(2, '0')).join('');

  return {
    ufrag: hex.slice(0, 8),  // 8 hex chars (≥4 required by ICE)
    pwd: hex.slice(8, 32),   // 24 hex chars (≥22 required by ICE)
  };
}

// Replace ICE credentials in an SDP string with derived ones.
// Call this before setLocalDescription so the browser's ICE agent
// uses the deterministic credentials.
export async function replaceCredentials(sdp) {
  const fpMatch = sdp.match(/a=fingerprint:\S+\s+([0-9A-Fa-f:]+)/);
  if (!fpMatch) return sdp;

  const fpBytes = new Uint8Array(fpMatch[1].split(':').map(h => parseInt(h, 16)));
  const { ufrag, pwd } = await deriveCredentials(fpBytes);

  return sdp
    .replace(/a=ice-ufrag:.*/g, 'a=ice-ufrag:' + ufrag)
    .replace(/a=ice-pwd:.*/g, 'a=ice-pwd:' + pwd);
}

// --- SDP Extraction ---

function extractSDP(sdp) {
  const lines = sdp.split(/\r?\n/);
  const fields = { fingerprintBytes: null, setup: 0, candidates: [] };

  for (const line of lines) {
    if (line.startsWith('a=fingerprint:')) {
      const m = /^a=fingerprint:(\S+)\s+([0-9A-Fa-f:]+)/.exec(line);
      if (!m) continue;
      if (m[1].toLowerCase() !== 'sha-256') {
        throw new Error(`unsupported fingerprint algorithm: ${m[1]}`);
      }
      fields.fingerprintBytes = new Uint8Array(m[2].split(':').map(h => parseInt(h, 16)));
      if (fields.fingerprintBytes.length !== 32) {
        throw new Error('malformed sha-256 fingerprint');
      }
    } else if (line.startsWith('a=setup:')) {
      const val = line.slice(8);
      fields.setup = val === 'actpass' ? 0 : val === 'active' ? 1 : 2;
    } else if (line.startsWith('a=candidate:')) {
      const c = parseCandidate(line);
      if (c && (c.type === 'host' || c.type === 'srflx')) fields.candidates.push(c);
    }
  }

  // Keep only first candidate
  if (fields.candidates.length > 1) fields.candidates = [fields.candidates[0]];

  return fields;
}

const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

function parseCandidate(line) {
  const parts = line.slice(12).split(/\s+/);
  if (parts.length < 8 || parts[6] !== 'typ') return null;
  const ip = parts[4];
  const m = IPV4_RE.exec(ip);
  if (!m) return null; // IPv6 or hostname — not encodable in 4 bytes
  for (let i = 1; i <= 4; i++) {
    if (Number(m[i]) > 255) return null;
  }
  const port = parseInt(parts[5], 10);
  if (!Number.isFinite(port) || port < 0 || port > 65535) return null;
  return { ip, port, type: parts[7] };
}

// --- SDP Reconstruction ---

async function reconstructSDP(fields) {
  const fpHex = Array.from(fields.fingerprintBytes, b => b.toString(16).toUpperCase().padStart(2, '0')).join(':');
  const setupStr = ['actpass', 'active', 'passive'][fields.setup] || 'actpass';
  const { ufrag, pwd } = await deriveCredentials(fields.fingerprintBytes);

  const lines = [
    'v=0',
    'o=- 0 0 IN IP4 127.0.0.1',
    's=-',
    't=0 0',
    'a=group:BUNDLE 0',
    'a=msid-semantic:WMS',
    'm=application 9 UDP/DTLS/SCTP webrtc-datachannel',
    'c=IN IP4 0.0.0.0',
  ];

  for (const c of fields.candidates) {
    lines.push(`a=candidate:1 1 UDP 2113937151 ${c.ip} ${c.port} typ host`);
  }

  lines.push('a=ice-ufrag:' + ufrag);
  lines.push('a=ice-pwd:' + pwd);
  lines.push('a=fingerprint:sha-256 ' + fpHex);
  lines.push('a=setup:' + setupStr);
  lines.push('a=mid:0');
  lines.push('a=sctp-port:5000');
  lines.push('');

  return lines.join('\r\n');
}

// --- Binary Packing ---
// Format (ICE credentials derived from fingerprint, not transmitted):
//   [0]       version byte (PROTOCOL_VERSION)
//   [1..2]    nonce (2 bytes, big-endian) — feeds HKDF info for SAS
//   [3]       flags: setup(2 bits) + candidateCount(2 bits) + reserved(4 bits)
//   [4..35]   fingerprint raw bytes (SHA-256)
//   per candidate: [4 bytes IPv4] [2 bytes port BE]

function packSDP(fields, nonceBytes) {
  const fp = fields.fingerprintBytes || new Uint8Array(32);
  const candidateCount = Math.min(fields.candidates.length, 3);

  const flags = ((fields.setup & 0x3) << 6) | ((candidateCount & 0x3) << 4);

  const totalSize = 1 + 2 + 1 + 32 + (candidateCount * 6);
  const buf = new Uint8Array(totalSize);
  let i = 0;

  buf[i++] = PROTOCOL_VERSION;
  buf[i++] = nonceBytes[0];
  buf[i++] = nonceBytes[1];
  buf[i++] = flags;
  buf.set(fp, i); i += 32;

  for (let c = 0; c < candidateCount; c++) {
    const cand = fields.candidates[c];
    const ipParts = cand.ip.split('.').map(Number);
    buf[i++] = ipParts[0]; buf[i++] = ipParts[1]; buf[i++] = ipParts[2]; buf[i++] = ipParts[3];
    buf[i++] = (cand.port >> 8) & 0xFF;
    buf[i++] = cand.port & 0xFF;
  }

  return buf;
}

function unpackSDP(bytes) {
  let i = 0;
  const version = bytes[i++];
  if (version !== PROTOCOL_VERSION) {
    throw new UnknownVersionError(version);
  }

  const nonce = new Uint8Array([bytes[i++], bytes[i++]]);

  const flags = bytes[i++];
  const setup = (flags >> 6) & 0x3;
  const candidateCount = (flags >> 4) & 0x3;

  const fingerprintBytes = bytes.slice(i, i + 32); i += 32;

  const candidates = [];
  for (let c = 0; c < candidateCount; c++) {
    const ip = `${bytes[i++]}.${bytes[i++]}.${bytes[i++]}.${bytes[i++]}`;
    const port = (bytes[i++] << 8) | bytes[i++];
    candidates.push({ ip, port, type: 'host' });
  }

  return { fields: { fingerprintBytes, setup, candidates }, nonce };
}

// --- Deflate / Inflate (native CompressionStream) ---

async function deflate(data) {
  const cs = new CompressionStream('deflate-raw');
  const writer = cs.writable.getWriter();
  writer.write(data);
  writer.close();
  return readAllBytes(cs.readable);
}

async function inflate(data) {
  const ds = new DecompressionStream('deflate-raw');
  const writer = ds.writable.getWriter();
  writer.write(data);
  writer.close();
  return readAllBytes(ds.readable);
}

async function readAllBytes(readable) {
  const reader = readable.getReader();
  const chunks = [];
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
  }
  const totalLen = chunks.reduce((sum, c) => sum + c.length, 0);
  const result = new Uint8Array(totalLen);
  let offset = 0;
  for (const chunk of chunks) { result.set(chunk, offset); offset += chunk.length; }
  return result;
}

// --- Word Encoding (12 bits per word) ---

// First word header: bit 11 = deflate flag, bits 0-10 = byte count (max 2047)
function bytesToWords(bytes, deflated) {
  let bits = '';
  for (const b of bytes) bits += b.toString(2).padStart(8, '0');

  const header = (deflated ? 0x800 : 0) | (bytes.length & 0x7FF);
  const words = [WORDLIST[header]];

  for (let i = 0; i < bits.length; i += BITS_PER_WORD) {
    const chunk = bits.slice(i, i + BITS_PER_WORD).padEnd(BITS_PER_WORD, '0');
    words.push(WORDLIST[parseInt(chunk, 2)]);
  }

  return words.join(' ');
}

function wordsToBytes(wordString) {
  const words = wordString.trim().toLowerCase().split(/\s+/);
  if (words.length < 2) throw new Error('Invalid code: too few words');

  const headerIdx = WORD_INDEX.get(words[0]);
  if (headerIdx === undefined) throw new Error(`Unknown word: "${words[0]}"`);

  const deflated = !!(headerIdx & 0x800);
  const totalBytes = headerIdx & 0x7FF;

  let bits = '';
  for (let i = 1; i < words.length; i++) {
    const idx = WORD_INDEX.get(words[i]);
    if (idx === undefined) throw new Error(`Unknown word: "${words[i]}"`);
    bits += idx.toString(2).padStart(BITS_PER_WORD, '0');
  }

  const result = new Uint8Array(totalBytes);
  for (let i = 0; i < totalBytes; i++) {
    result[i] = parseInt(bits.slice(i * 8, i * 8 + 8), 2);
  }

  return { bytes: result, deflated };
}
