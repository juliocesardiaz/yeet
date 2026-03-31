import { WORDLIST } from './wordlist.js';

// Build reverse lookup once
const WORD_INDEX = new Map(WORDLIST.map((w, i) => [w, i]));
const BITS_PER_WORD = 12; // 4096-word list

// --- Public API ---

export async function compress(sdpString) {
  const fields = extractSDP(sdpString);
  const packed = packSDP(fields);
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
  const fields = unpackSDP(packed);
  return reconstructSDP(fields);
}

// --- SDP Extraction ---

function extractSDP(sdp) {
  const lines = sdp.split(/\r?\n/);
  const fields = { ufrag: '', pwd: '', fingerprintBytes: null, setup: 0, candidates: [] };

  for (const line of lines) {
    if (line.startsWith('a=ice-ufrag:')) {
      fields.ufrag = line.slice(12);
    } else if (line.startsWith('a=ice-pwd:')) {
      fields.pwd = line.slice(10);
    } else if (line.startsWith('a=fingerprint:sha-256 ')) {
      const hex = line.slice(21);
      fields.fingerprintBytes = new Uint8Array(hex.split(':').map(h => parseInt(h, 16)));
    } else if (line.startsWith('a=setup:')) {
      const val = line.slice(8);
      fields.setup = val === 'actpass' ? 0 : val === 'active' ? 1 : 2;
    } else if (line.startsWith('a=candidate:')) {
      const c = parseCandidate(line);
      if (c && (c.type === 'host' || c.type === 'srflx')) fields.candidates.push(c);
    }
  }

  // Keep only first host candidate
  if (fields.candidates.length > 1) fields.candidates = [fields.candidates[0]];

  return fields;
}

function parseCandidate(line) {
  const parts = line.slice(12).split(/\s+/);
  if (parts.length < 8) return null;
  return {
    ip: parts[4],
    port: parseInt(parts[5], 10),
    type: parts[7],
  };
}

// --- SDP Reconstruction ---

function reconstructSDP(fields) {
  const fpHex = Array.from(fields.fingerprintBytes, b => b.toString(16).toUpperCase().padStart(2, '0')).join(':');
  const setupStr = ['actpass', 'active', 'passive'][fields.setup] || 'actpass';

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

  lines.push('a=ice-ufrag:' + fields.ufrag);
  lines.push('a=ice-pwd:' + fields.pwd);
  lines.push('a=fingerprint:sha-256 ' + fpHex);
  lines.push('a=setup:' + setupStr);
  lines.push('a=mid:0');
  lines.push('a=sctp-port:5000');
  lines.push('');

  return lines.join('\r\n');
}

// --- Binary Packing ---
// Format:
//   [0]       flags: setup(2 bits) + candidateCount(2 bits) + reserved(4 bits)
//   [1]       ufrag length (N)
//   [2..1+N]  ufrag bytes
//   [2+N]     pwd length (M)
//   [3+N..2+N+M]  pwd bytes
//   [next 32] fingerprint raw bytes (SHA-256)
//   per candidate: [4 bytes IPv4] [2 bytes port BE]

function packSDP(fields) {
  const ufragBytes = new TextEncoder().encode(fields.ufrag);
  const pwdBytes = new TextEncoder().encode(fields.pwd);
  const fp = fields.fingerprintBytes || new Uint8Array(32);
  const candidateCount = Math.min(fields.candidates.length, 3);

  const flags = ((fields.setup & 0x3) << 6) | ((candidateCount & 0x3) << 4);

  const totalSize = 1 + 1 + ufragBytes.length + 1 + pwdBytes.length + 32 + (candidateCount * 6);
  const buf = new Uint8Array(totalSize);
  let i = 0;

  buf[i++] = flags;
  buf[i++] = ufragBytes.length;
  buf.set(ufragBytes, i); i += ufragBytes.length;
  buf[i++] = pwdBytes.length;
  buf.set(pwdBytes, i); i += pwdBytes.length;
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
  const flags = bytes[i++];
  const setup = (flags >> 6) & 0x3;
  const candidateCount = (flags >> 4) & 0x3;

  const ufragLen = bytes[i++];
  const ufrag = new TextDecoder().decode(bytes.slice(i, i + ufragLen)); i += ufragLen;

  const pwdLen = bytes[i++];
  const pwd = new TextDecoder().decode(bytes.slice(i, i + pwdLen)); i += pwdLen;

  const fingerprintBytes = bytes.slice(i, i + 32); i += 32;

  const candidates = [];
  for (let c = 0; c < candidateCount; c++) {
    const ip = `${bytes[i++]}.${bytes[i++]}.${bytes[i++]}.${bytes[i++]}`;
    const port = (bytes[i++] << 8) | bytes[i++];
    candidates.push({ ip, port, type: 'host' });
  }

  return { ufrag, pwd, fingerprintBytes, setup, candidates };
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
